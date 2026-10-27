#!/usr/bin/env python3
"""
muse_client.py - standalone client for the muse.ai "hatch" gateway.

Reverse-engineered from the muse.ai web app (Abra/Next.js bundle):
  * auth   : the muse.ai session cookie (same one the website uses)
  * token  : POST https://muse.ai/api/hatch/token   -> {token, notary_token}
  * tunnel : wss://<vm>.metaaivm.com/v1/noise  (Noise_XX_25519_AESGCM_SHA256)
  * rpc    : protobuf envelope (h a t c h . n o i s e), HTTP-like verbs/paths
  * chat   : POST /chat/stream (noise) + POST /chat/subscribe (noise, NDJSON stream)

Secrets are only ever read from disk / env by this process; they are never printed.

Usage
  python muse_client.py probe
  python muse_client.py chat "hello" [--session <session_id>] [--watch 60]
  python muse_client.py gen "prompt" [--watch 300] [--out images]
  python muse_client.py rest GET /api/artifacts
  python muse_client.py history [--limit 20]

Cookie (first hit wins)
  --cookie-file PATH   (default: ~/.muse/cookie.txt)
  MUSE_COOKIE env var
The file may contain either a raw `Cookie:` header line or `name=value; name2=value2`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import random
import re
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import quote, urlparse

import requests

try:
    import zstandard  # optional, only needed if the server zstd-compresses bodies
except Exception:  # pragma: no cover
    zstandard = None

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# constants (from the app bundle)
# --------------------------------------------------------------------------- #

MUSE_ORIGIN = "https://muse.ai"
GATEWAY_HOST = "hatch.metaaivm.com"          # shared LB fallback
NOISE_WS_PATH = "/v1/noise"
APP_ID = os.environ.get("MUSE_APP_ID", "hatch-web")
# Vendored into Agent Sprite Forge (skills/generate2dmedia/scripts/): the route's version, read by
# `python muse_client.py --version` (cli_media.py probes it like a CLI).
MUSE_CLIENT_VERSION = "1.0.0"
MAX_FRAME_PAYLOAD = 65489                    # bytes per NoiseTransportFrame chunk
MAX_CHUNKS = 256
CHAT_CAPABILITIES = [
    "chat_cancel",
    "delta_stream",
    "custom_reactions",
    "custom_reactions_facebook_thumbs_up_v1",
]

SERVICE_DAEMON = 0
SERVICE_SENTINEL = 1
SERVICE_VAULT = 2
SERVICE_AUTHD = 3

STATE_DIR = Path(os.environ.get("MUSE_STATE_DIR", Path.home() / ".muse"))

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# tiny protobuf codec (only what the noise envelope needs)
# --------------------------------------------------------------------------- #


def _varint(n: int) -> bytes:
    if n < 0:
        n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def pb_varint_field(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def pb_bytes_field(field: int, value: bytes) -> bytes:
    return _varint(field << 3 | 2) + _varint(len(value)) + value


def pb_str_field(field: int, value: str) -> bytes:
    return pb_bytes_field(field, value.encode())


def pb_parse(buf: bytes):
    """Yield (field, wiretype, value) - value is int for varint, bytes for LEN."""
    pos = 0
    end = len(buf)
    while pos < end:
        key, pos = _read_varint(buf, pos)
        field, wt = key >> 3, key & 7
        if wt == 0:
            val, pos = _read_varint(buf, pos)
            yield field, wt, val
        elif wt == 2:
            ln, pos = _read_varint(buf, pos)
            yield field, wt, buf[pos : pos + ln]
            pos += ln
        elif wt == 5:
            yield field, wt, buf[pos : pos + 4]
            pos += 4
        elif wt == 1:
            yield field, wt, buf[pos : pos + 8]
            pos += 8
        else:
            raise ValueError(f"unsupported wire type {wt}")


def _read_varint(buf: bytes, pos: int):
    shift = 0
    val = 0
    while True:
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, pos
        shift += 7


def pb_fields(buf: bytes) -> dict:
    out: dict = {}
    for field, wt, val in pb_parse(buf):
        out.setdefault(field, []).append(val)
    return out


# ---- envelope builders ----------------------------------------------------- #


def build_application_request(verb: str, path: str, headers=None, body: bytes = b"", end_body=True) -> bytes:
    out = pb_str_field(1, verb) + pb_str_field(2, path)
    for k, v in headers or []:
        out += pb_bytes_field(3, pb_str_field(1, k) + pb_str_field(2, v))
    if body:
        out += pb_bytes_field(4, body)
    if end_body:
        out += pb_varint_field(5, 1)
    return out


def build_service_frame_request(stream_id: int, app_req: bytes) -> bytes:
    return pb_varint_field(1, stream_id) + pb_bytes_field(2, app_req)


def build_service_request(service: int, payload: bytes) -> bytes:
    return pb_varint_field(1, service) + pb_bytes_field(2, payload)


def build_body_chunk(stream_id: int, data: bytes, end_body: bool) -> bytes:
    chunk = pb_bytes_field(1, data) + (pb_varint_field(2, 1) if end_body else b"")
    return pb_varint_field(1, stream_id) + pb_bytes_field(4, chunk)


def build_noise_transport_frame(chunk_id: int, index: int, total: int, payload: bytes) -> bytes:
    return (
        pb_varint_field(1, chunk_id)
        + pb_varint_field(2, index)
        + pb_varint_field(3, total)
        + pb_bytes_field(4, payload)
    )


def parse_service_response(buf: bytes) -> bytes:
    """ServiceResponse { payload = 1 }"""
    f = pb_fields(buf)
    payload = f.get(1, [b""])[0]
    if not payload:
        raise ValueError("empty ServiceResponse payload")
    return payload


def parse_service_frame(buf: bytes):
    """-> dict(kind=..., stream_id=..., ...)"""
    f = pb_fields(buf)
    stream_id = f.get(1, [0])[0]
    if 2 in f:  # request (client->server only)
        return {"kind": "request", "stream_id": stream_id, "raw": f[2][0]}
    if 3 in f:
        resp = pb_fields(f[3][0])
        headers = []
        for h in resp.get(2, []):
            hf = pb_fields(h)
            headers.append(
                (
                    hf.get(1, [b""])[0].decode("utf-8", "replace"),
                    hf.get(2, [b""])[0].decode("utf-8", "replace"),
                )
            )
        return {
            "kind": "response",
            "stream_id": stream_id,
            "status": resp.get(1, [0])[0],
            "headers": headers,
            "body": resp.get(3, [b""])[0],
            "end_body": bool(resp.get(4, [0])[0]),
        }
    if 4 in f:
        bc = pb_fields(f[4][0])
        return {
            "kind": "body_chunk",
            "stream_id": stream_id,
            "data": bc.get(1, [b""])[0],
            "end_body": bool(bc.get(2, [0])[0]),
        }
    if 5 in f:
        rs = pb_fields(f[5][0])
        return {
            "kind": "reset",
            "stream_id": stream_id,
            "code": rs.get(1, [0])[0],
            "reason": rs.get(2, [b""])[0].decode("utf-8", "replace"),
        }
    return {"kind": "unknown", "stream_id": stream_id}


# --------------------------------------------------------------------------- #
# Noise_XX_25519_AESGCM_SHA256 (initiator)
# --------------------------------------------------------------------------- #

PROTOCOL_NAME = b"Noise_XX_25519_AESGCM_SHA256"
_EMPTY = b""


def _hkdf(ck: bytes, ikm: bytes, n: int):
    tmp = hmac.new(ck, ikm, hashlib.sha256).digest()
    out = []
    prev = b""
    for i in range(1, n + 1):
        prev = hmac.new(tmp, prev + bytes([i]), hashlib.sha256).digest()
        out.append(prev)
    return out


class CipherState:
    def __init__(self):
        self.key: bytes | None = None
        self.n = 0

    def initialize_key(self, key: bytes):
        self.key = key
        self.n = 0

    def _nonce(self) -> bytes:
        # Noise AESGCM nonce = 4 zero bytes || 64-bit counter, and the gateway's
        # CipherState writes that counter BIG-endian (DataView.setUint32(4,hi,false),
        # setUint32(8,lo,false)) - NOT the little-endian form from the Noise spec.
        return b"\x00\x00\x00\x00" + self.n.to_bytes(8, "big")

    def encrypt(self, ad: bytes, pt: bytes) -> bytes:
        # Noise: while k is empty, EncryptAndHash is the identity function.
        if self.key is None:
            return pt
        ct = AESGCM(self.key).encrypt(self._nonce(), pt, ad)
        self.n += 1
        return ct

    def decrypt(self, ad: bytes, ct: bytes) -> bytes:
        if self.key is None:
            return ct
        pt = AESGCM(self.key).decrypt(self._nonce(), ct, ad)
        self.n += 1
        return pt


class SymmetricState:
    def __init__(self):
        name = PROTOCOL_NAME
        if len(name) <= 32:
            name = name + b"\x00" * (32 - len(name))
        self.h = name
        self.ck = name
        self.cipher = CipherState()
        self.mix_hash(_EMPTY)

    def mix_hash(self, data: bytes):
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm: bytes):
        self.ck, k = _hkdf(self.ck, ikm, 2)
        self.cipher.initialize_key(k)

    def encrypt_and_hash(self, pt: bytes) -> bytes:
        ct = self.cipher.encrypt(self.h, pt)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct: bytes) -> bytes:
        pt = self.cipher.decrypt(self.h, ct)
        self.mix_hash(ct)
        return pt

    def split(self):
        k1, k2 = _hkdf(self.ck, _EMPTY, 2)
        c1, c2 = CipherState(), CipherState()
        c1.initialize_key(k1)
        c2.initialize_key(k2)
        return c1, c2


def _dh(priv: X25519PrivateKey, pub: bytes) -> bytes:
    return priv.exchange(X25519PublicKey.from_public_bytes(pub))


class NoiseXXInitiator:
    """Noise XX initiator, message 1/2/3 (no RV challenge support)."""

    def __init__(self):
        self.ss = SymmetricState()
        self.s = X25519PrivateKey.generate()
        self.e = X25519PrivateKey.generate()
        self.observed_type = "unknown"
        self.remote_static: bytes | None = None
        self.handshake_hash: bytes | None = None

    def write_message1(self, payload: bytes = b"") -> bytes:
        e_pub = self.e.public_key().public_bytes_raw()
        self.ss.mix_hash(e_pub)
        return e_pub + self.ss.encrypt_and_hash(payload)

    def read_message2(self, msg: bytes) -> bytes:
        if len(msg) < 32 + 48:
            raise ValueError(f"noise message2 too short ({len(msg)})")
        re_pub = msg[:32]
        self._remote_ephemeral = re_pub
        self.ss.mix_hash(re_pub)
        self.ss.mix_key(_dh(self.e, re_pub))
        self.remote_static = self.ss.decrypt_and_hash(msg[32:80])
        self.ss.mix_key(_dh(self.e, self.remote_static))
        payload = self.ss.decrypt_and_hash(msg[80:])
        self.observed_type = "confidential" if parse_rv_challenge(payload) else "standard"
        return payload

    def write_message3(self, payload: bytes = b"") -> bytes:
        if len(payload) > 65535:
            raise ValueError("noise message3 payload too large")
        s_pub = self.s.public_key().public_bytes_raw()
        out = self.ss.encrypt_and_hash(s_pub)
        # no need for the remote ephemeral again: it was already consumed in read_message2
        self.ss.mix_key(_dh(self.s, self._remote_ephemeral))
        out += self.ss.encrypt_and_hash(payload)
        self.handshake_hash = self.ss.h
        return out

    def read_message2_wrapper(self, msg: bytes) -> bytes:
        # keep the remote ephemeral around for message3
        re_pub = msg[:32]
        self._remote_ephemeral = re_pub
        return self.read_message2(msg)

    def split(self):
        return self.ss.split()


def parse_rv_challenge(payload: bytes):
    """Return dict if `payload` is an owner-RV challenge, else None."""
    try:
        f = pb_fields(payload)
    except Exception:
        return None
    attestation = f.get(1, [None])[0]
    state = f.get(2, [None])[0]
    vm_nonce = f.get(3, [None])[0]
    vm_proof = f.get(4, [None])[0]
    if attestation is None or state not in (1, 2):
        return None
    if vm_nonce is None or len(vm_nonce) != 32:
        return None
    return {
        "state": "unprovisioned" if state == 1 else "provisioned",
        "attestation": attestation,
        "vm_nonce": vm_nonce,
        "vm_proof": vm_proof,
    }


# --------------------------------------------------------------------------- #
# muse.ai REST (cookie auth)
# --------------------------------------------------------------------------- #


class MuseRest:
    def __init__(self, cookie: str, origin: str = MUSE_ORIGIN):
        self.origin = origin.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "cookie": cookie,
                "user-agent": UA,
                "accept": "*/*",
                "origin": self.origin,
                "referer": self.origin + "/",
                "x-app-id": APP_ID,
                # muse.ai rejects api calls without these (bot/CSRF guard)
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                "accept-language": "en-US,en;q=0.9",
            }
        )

    def request(self, method: str, path: str, **kw):
        url = path if path.startswith("http") else self.origin + path
        kw.setdefault("timeout", 60)
        if "json" in kw:
            kw.setdefault("headers", {})["content-type"] = "application/json"
        r = self.session.request(method, url, **kw)
        return r

    def json(self, method: str, path: str, **kw):
        r = self.request(method, path, **kw)
        try:
            data = r.json()
        except Exception:
            data = None
        return r.status_code, data

    # --- hatch lifecycle ---
    def session_info(self):
        code, data = self.json("GET", "/api/session?vm_state=live")
        return code, (data or {})

    def wake(self, vm_id: str):
        return self.json(
            "POST",
            "/api/hatch/vm/wake",
            json={"vm_id": vm_id, "retry_count": 0, "connect_attempt_id": str(uuid.uuid4())},
        )

    def token(self, gateway_url: str, vm_name: str | None = None):
        body = {"vmAddress": gateway_url}
        if vm_name:
            body["vmName"] = vm_name
        return self.json("POST", "/api/hatch/token", json=body)


# --------------------------------------------------------------------------- #
# gateway connection
# --------------------------------------------------------------------------- #


class GatewayError(RuntimeError):
    pass


class Gateway:
    def __init__(self, ws, send_cipher: CipherState, recv_cipher: CipherState, handshake: NoiseXXInitiator):
        self.ws = ws
        self.send = send_cipher
        self.recv = recv_cipher
        self.handshake = handshake
        self._next_stream = 1
        self._assemblies: dict[int, dict] = {}
        self.pending: dict[int, list] = {}

    # -- framing --
    def _encrypt_chunks(self, plaintext: bytes):
        chunk_id = random.getrandbits(63)
        total = max(1, -(-len(plaintext) // MAX_FRAME_PAYLOAD))
        if total > MAX_CHUNKS:
            raise GatewayError("payload too large for noise framing")
        if not plaintext:
            parts = [(0, 1, b"")]
        else:
            parts = [
                (i, total, plaintext[i * MAX_FRAME_PAYLOAD : (i + 1) * MAX_FRAME_PAYLOAD])
                for i in range(total)
            ]
        frames = []
        for idx, tot, part in parts:
            frame = build_noise_transport_frame(chunk_id, idx, tot, part)
            frames.append(self.send.encrypt(b"", frame))
        return frames

    def send_request(self, app_req: bytes, service: int = SERVICE_DAEMON) -> int:
        stream_id = self._next_stream
        self._next_stream += 1
        frame = build_service_frame_request(stream_id, app_req)
        req = build_service_request(service, frame)
        for f in self._encrypt_chunks(req):
            self.ws.send(f)
        return stream_id

    def http(self, method: str, path: str, body: bytes = b"", headers=None, service: int = SERVICE_DAEMON) -> int:
        hdrs = [("x-app-id", APP_ID), ("accept-encoding", "identity")]
        if body:
            hdrs.append(("content-type", "application/json"))
        hdrs.extend(headers or [])
        app_req = build_application_request(method, path, hdrs, body, True)
        return self.send_request(app_req, service)

    def send_body_chunk(self, stream_id: int, data: bytes, end_body: bool = False):
        chunk = build_body_chunk(stream_id, data, end_body)
        req = build_service_request(SERVICE_DAEMON, chunk)
        for f in self._encrypt_chunks(req):
            self.ws.send(f)

    # -- receive --
    def _decrypt_message(self, raw: bytes):
        pt = self.recv.decrypt(b"", raw)
        f = pb_fields(pt)
        chunk_id = f.get(1, [0])[0]
        index = f.get(2, [0])[0]
        total = f.get(3, [1])[0]
        payload = f.get(4, [b""])[0]
        if total == 1:
            return payload
        asm = self._assemblies.setdefault(chunk_id, {"parts": {}, "total": total})
        if asm["total"] != total:
            self._assemblies.pop(chunk_id, None)
            raise GatewayError("inconsistent totalChunks")
        asm["parts"][index] = payload
        if len(asm["parts"]) < total:
            return None
        self._assemblies.pop(chunk_id, None)
        return b"".join(asm["parts"][i] for i in range(total))

    def recv_frame(self, timeout: float = 60.0):
        """Block until one ServiceFrame arrives. Returns dict or None on timeout."""
        deadline = time.time() + timeout
        while True:
            remain = deadline - time.time()
            if remain <= 0:
                return None
            try:
                raw = self.ws.recv(timeout=remain)
            except TimeoutError:
                return None
            if isinstance(raw, str):
                raw = raw.encode()
            pt = self._decrypt_message(raw)
            if pt is None:
                continue
            return parse_service_frame(parse_service_response(pt))


# --------------------------------------------------------------------------- #
# noise handshake over websocket
# --------------------------------------------------------------------------- #


def open_gateway(rest: MuseRest, vm_id: str | None = None, gateway_url: str | None = None, vm_name: str | None = None):
    """Returns (Gateway, ws)."""
    from websockets.sync.client import connect

    vm_name = vm_name or vm_id
    if not gateway_url:
        code, info = rest.session_info()
        if code != 200:
            raise GatewayError(f"/api/session failed: HTTP {code}")
        vm_id = vm_id or info.get("vm_id") or info.get("vmId")
        gateway_url = info.get("endpoint_url") or info.get("endpointUrl")
        if not gateway_url:
            raise GatewayError(
                "no endpoint_url from /api/session (VM suspended?): " + json.dumps(info)[:400]
            )
    host = urlparse(gateway_url).hostname or ""
    if host.endswith(".metaaivm.com"):
        derived = host.split(".")[0]
        vm_id = vm_id or derived
    vm_id = vm_id or vm_name
    if not vm_id:
        raise GatewayError("cannot determine vm_id")
    code, tok = rest.token(gateway_url, vm_name)
    if code != 200 or not isinstance(tok, dict) or not tok.get("token"):
        raise GatewayError(f"/api/hatch/token failed: HTTP {code} {json.dumps(tok)[:300] if tok else ''}")
    auth_token = tok["token"]
    notary = tok.get("notary_token") or ""
    # the app also mints a dedicated notary token for the /v1/noise ingress
    try:
        code, nt = rest.json("POST", "/api/hatch/noise-notary-token", json={"vmName": vm_name})
        if code == 200 and isinstance(nt, dict) and nt.get("notaryToken"):
            notary = nt["notaryToken"].strip()
    except Exception as e:
        log(f"[warn] noise-notary-token failed: {e}")

    request_id = str(uuid.uuid4())
    params = [
        f"vm_id={quote(vm_id)}",
        f"auth_token={quote(auth_token)}",
    ]
    if notary:
        params.append(f"notary_token={quote(notary)}")
    params.append(f"app_id={quote(APP_ID)}")
    params.append(f"request_id={quote(request_id)}")
    # NOTE: per-VM hostnames (<vm>.metaaivm.com) are NOT in public DNS; the app
    # always dials the shared ingress hatch.metaaivm.com and passes vm_id as a param.
    base = f"wss://{GATEWAY_HOST}"
    ws_url = base.rstrip("/") + NOISE_WS_PATH + "?" + "&".join(params)

    ws = connect(
        ws_url,
        additional_headers={"user-agent": UA, "origin": MUSE_ORIGIN},
        max_size=None,
        open_timeout=30,
        close_timeout=5,
        legacy=True,
    )

    hs = NoiseXXInitiator()
    nonce = os.urandom(32)
    msg1_payload = pb_bytes_field(1, nonce)  # NoiseClientNonceMessage1 { nonce = 1 }
    ws.send(hs.write_message1(msg1_payload))
    msg2 = ws.recv(timeout=30)
    if isinstance(msg2, str):
        msg2 = msg2.encode()
    payload = hs.read_message2_wrapper(msg2)
    challenge = parse_rv_challenge(payload)
    if challenge:
        ws.close()
        raise GatewayError(
            "server requires a confidential-VM (RV) challenge; this VM needs the CVM recovery key "
            f"(state={challenge['state']}). Not supported by this client."
        )
    ws.send(hs.write_message3(b""))
    send_c, recv_c = hs.split()
    return Gateway(ws, send_c, recv_c, hs), ws


# --------------------------------------------------------------------------- #
# high level chat helpers
# --------------------------------------------------------------------------- #


def node_id() -> str:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    p = STATE_DIR / "node_id"
    if p.exists():
        v = p.read_text().strip()
        if v:
            return v
    v = str(uuid.uuid4())
    p.write_text(v)
    return v


def load_cookie(args) -> str:
    if args.cookie:
        return args.cookie
    env = os.environ.get("MUSE_COOKIE")
    if env:
        return env.strip()
    path = Path(args.cookie_file) if args.cookie_file else STATE_DIR / "cookie.txt"
    if not path.exists():
        raise SystemExit(
            f"cookie file not found: {path}\n"
            "Create it with the `Cookie:` header value from muse.ai (or set MUSE_COOKIE)."
        )
    raw = path.read_text().strip()
    if raw.lower().startswith("cookie:"):
        raw = raw.split(":", 1)[1].strip()
    raw = raw.replace("\n", "").strip()
    if not raw:
        raise SystemExit(f"cookie file is empty: {path}")
    return raw


def decode_body(data: bytes, headers) -> bytes:
    enc = ""
    for k, v in headers or []:
        if k.lower() == "content-encoding":
            enc = v.lower()
    if "zstd" in enc:
        if zstandard is None:
            raise GatewayError("body is zstd-compressed but the `zstandard` package is missing")
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    if "gzip" in enc:
        import gzip

        return gzip.decompress(data)
    return data


class ChatSession:
    """One noise connection + helpers to send chat messages and read the event stream."""

    def __init__(self, rest: MuseRest, gateway: Gateway, ws):
        self.rest = rest
        self.gw = gateway
        self.ws = ws
        self.session_id: str | None = None
        self.stream_id: int | None = None
        self.sub_id: int | None = None
        self._buf: dict[int, bytearray] = {}
        self._zstd: dict[int, bool] = {}
        self._buffered: list = []

    # ---- subscribe ----
    def subscribe(self, session_id: str | None = None, after_stream_seq: int = 0, after_chat_event_seq: int = 0):
        params = {
            "after_stream_seq": after_stream_seq,
            "after_chat_event_seq": after_chat_event_seq,
            "capabilities": CHAT_CAPABILITIES,
        }
        if session_id:
            params["session_id"] = session_id
        body = json.dumps(params).encode()
        self.sub_id = self.gw.http("POST", "/chat/subscribe", body)
        return self.sub_id

    # ---- send ----
    def send(self, text: str, session_id: str | None = None, extra: dict | None = None, images=None):
        items = list(build_attachment_items(images or []))
        if text:
            items.append({"type": "text", "text": text})
        params = {
            "items": items,
            "node_id": node_id(),
            "capabilities": CHAT_CAPABILITIES,
        }
        if session_id or self.session_id:
            params["session_id"] = session_id or self.session_id
        if extra:
            params.update(extra)
        body = json.dumps(params).encode()
        self.stream_id = self.gw.http("POST", "/chat/stream", body)
        return self.stream_id

    def cancel(self):
        if self.stream_id:
            self.gw.http("POST", "/chat/cancel", json.dumps({"stream_id": self.stream_id}).encode())

    # ---- events ----
    def _records(self, frame) -> list:
        sid = frame["stream_id"]
        out = []
        if frame["kind"] == "response":
            buf = self._buf.setdefault(sid, bytearray())
            buf += frame["body"]
            enc = " ".join(v.lower() for k, v in frame["headers"] if k.lower() == "content-encoding")
            if "zstd" in enc:
                self._zstd[sid] = True
        elif frame["kind"] == "body_chunk":
            buf = self._buf.setdefault(sid, bytearray())
            buf += frame["data"]
        else:
            return out
        buf = self._buf[sid]
        while True:
            idx = buf.find(b"\n")
            if idx < 0:
                break
            line = bytes(buf[:idx])
            del buf[: idx + 1]
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                out.append({"raw": line.decode("utf-8", "replace")})
        return out

    def fetch(self, path: str, timeout: float = 180.0, max_bytes: int = 200 * 1024 * 1024):
        """GET a path over the tunnel and collect the whole body (media/fs downloads).

        Returns (status, headers, body).
        """
        sid = self.gw.http("GET", path)
        body = bytearray()
        headers: list = []
        status = 0
        end = time.time() + timeout
        while time.time() < end:
            frame = self.gw.recv_frame(timeout=min(15, max(0.5, end - time.time())))
            if frame is None:
                continue
            if frame["stream_id"] != sid:
                self._records(frame)
                continue
            if frame["kind"] == "reset":
                raise GatewayError(f"stream reset: code={frame['code']} {frame['reason']}")
            if frame["kind"] == "response":
                status = frame["status"]
                headers = frame["headers"]
                body += decode_body(frame["body"], frame["headers"])
                if frame["end_body"]:
                    break
            elif frame["kind"] == "body_chunk":
                body += frame["data"]
                if frame["end_body"]:
                    break
            if len(body) > max_bytes:
                raise GatewayError("response too large")
        return status, headers, bytes(body)

    def download(self, path: str, dest: Path, retries: int = 6, delay: float = 2.0):
        """Fetch a workspace file into `dest`, retrying while it is not ready yet."""
        p = workspace_path(path)
        last = ""
        for attempt in range(retries):
            status, headers, data = self.fetch("/fs/raw" + p)
            ctype = dict((k.lower(), v) for k, v in headers).get("content-type", "")
            if status == 200 and data and not ctype.startswith("application/json"):
                dest.write_bytes(data)
                return status, ctype, len(data)
            last = f"HTTP {status} {ctype} {data[:120]!r}"
            time.sleep(delay)
        raise GatewayError(f"could not download {p}: {last}")

    def watch(self, seconds: float, on_event=None, quiet=False, stop=None):
        """Read frames for `seconds`; returns list of events.

        `stop(event)` may return True to end early.
        """
        events = []
        end = time.time() + seconds
        while True:
            remain = end - time.time()
            if remain <= 0:
                break
            try:
                frame = self.gw.recv_frame(timeout=min(remain, 15))
            except Exception as e:  # connection closed etc.
                log(f"[watch] {type(e).__name__}: {e}")
                break
            if frame is None:
                continue
            if frame["kind"] == "reset":
                log(f"[reset] code={frame['code']} {frame['reason']}")
                continue
            for rec in self._records(frame):
                events.append(rec)
                if on_event:
                    on_event(rec)
                elif not quiet:
                    print(json.dumps(rec, ensure_ascii=False))
                if stop and stop(rec):
                    return events
        return events

    def drain_baseline(self, seconds: float = 3.0):
        """Read the replayed history until the subscribe response + replay burst finish.
        Returns (session_id, max_seq)."""
        session, maxseq = None, 0
        hard_end = time.time() + max(seconds, 20.0)
        while time.time() < hard_end:
            # Wait longer until the subscribe 'res' + initial history arrive; once we have
            # seen the session and the stream goes quiet for 0.8s, the replay is done.
            wait = 5.0 if session is None else 0.8
            frame = self.gw.recv_frame(timeout=wait)
            if frame is None:
                if session is not None:
                    break
                continue
            for rec in self._records(frame):
                payload = rec.get("payload")
                if rec.get("type") == "res" and isinstance(payload, dict):
                    session = payload.get("session_id") or session
                seq = rec.get("seq")
                if isinstance(seq, int) and seq > maxseq:
                    maxseq = seq
        return session, maxseq

    def wait_ack(self, stream_id: int, timeout: float = 30.0):
        """Wait for the ApplicationResponse of a specific stream (chat.stream ack)."""
        end = time.time() + timeout
        while time.time() < end:
            frame = self.gw.recv_frame(timeout=min(15, end - time.time()))
            if frame is None:
                continue
            if frame["stream_id"] == stream_id and frame["kind"] == "response":
                body = decode_body(frame["body"], frame["headers"])
                try:
                    data = json.loads(body) if body else {}
                except Exception:
                    data = {"raw": body.decode("utf-8", "replace")}
                return frame["status"], data
            # keep other frames buffered for the event loop
            self._buffered.extend(self._records(frame))
        return None, None

    def wait_turn(self, baseline_seq: int = 0, max_seconds: float = 900.0, grace: float = 2.0, on_event=None,
                  expected_media: int = 1):
        """Read the event stream until the agent turn finishes.

        End of turn = `task.status: completed` (or `expected_media` presentation events)
        with seq > baseline, then `grace` seconds to pick up trailing events. Image-only turns
        never emit `delta.message_done`, so watching for that alone hangs until the timeout.
        """
        events = list(self._buffered)
        self._buffered.clear()
        done_at = None
        saw_user = False
        seen_paths: set[str] = set()

        def inspect(rec):
            nonlocal done_at, saw_user
            if on_event:
                on_event(rec)
            seq = rec.get("seq")
            payload = rec.get("payload") or {}
            chat_seq = payload.get("chat_event_seq") if isinstance(payload, dict) else None
            if rec.get("event") == "message.user":
                saw_user = True
            fresh = (isinstance(seq, int) and seq != chat_seq and seq > baseline_seq) or saw_user
            if not fresh:
                return
            if rec.get("event") == "delta.presentation" and isinstance(payload.get("data"), dict):
                data = payload["data"]
                for key in MEDIA_KEYS:
                    for m in data.get(key) or []:
                        if isinstance(m, dict) and m.get("path"):
                            seen_paths.add(workspace_path(m["path"]))
                if len(seen_paths) >= max(1, expected_media) and done_at is None:
                    done_at = time.time() + 1.5
            if done_at is None:
                if rec.get("event") == "task.status" and payload.get("status") == "completed":
                    done_at = time.time()
                elif rec.get("event") == "delta.message_done" and expected_media <= 1 and len(seen_paths) >= 1:
                    done_at = time.time()

        for rec in events:
            inspect(rec)
        deadline = time.time() + max_seconds
        while True:
            now = time.time()
            if done_at is not None and now - done_at > grace:
                break
            if now > deadline:
                break
            limit = max(now + 0.5, (done_at + grace) if done_at is not None else deadline)
            frame = self.gw.recv_frame(timeout=min(15.0, max(0.5, limit - now)))
            if frame is None:
                continue
            if frame["kind"] == "reset":
                log(f"[reset] code={frame['code']} {frame['reason']}")
                continue
            for rec in self._records(frame):
                events.append(rec)
                inspect(rec)
        return events


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #


def cmd_probe(args, rest):
    gw, ws = open_gateway(rest, vm_id=args.vm, vm_name=args.vm_name)
    print(
        json.dumps(
            {
                "ok": True,
                "observed_type": gw.handshake.observed_type,
                "handshake_hash": gw.handshake.handshake_hash.hex(),
                "server_static_pub": gw.handshake.remote_static.hex(),
            },
            indent=2,
        )
    )
    ws.close()
    return 0


def cmd_chat(args, rest):
    gw, ws = open_gateway(rest, vm_id=args.vm, vm_name=args.vm_name)
    cs = ChatSession(rest, gw, ws)
    cs.subscribe(args.session)
    session, baseline = cs.drain_baseline(2.0)
    sid = cs.send(args.text, session_id=args.session or session, images=args.image)
    status, data = cs.wait_ack(sid)
    print(json.dumps({"status": status, "ack": data}, ensure_ascii=False))
    if isinstance(data, dict) and data.get("session_id"):
        cs.session_id = data["session_id"]

    def on_event(rec):
        seq = rec.get("seq")
        if isinstance(seq, int) and seq <= baseline:
            return
        ev = rec.get("event") or rec.get("type")
        payload = rec.get("payload") or {}
        if ev == "delta.text_append":
            print(payload.get("text", ""), end="", flush=True)
        elif ev == "delta.message_done":
            print()
        elif ev == "agent.status" and payload.get("activity_text"):
            print(f"[status] {payload['activity_text']}", flush=True)
        elif ev == "delta.presentation":
            print(f"[media] {payload.get('display_text')}", flush=True)
        elif args.raw:
            print(json.dumps(rec, ensure_ascii=False), flush=True)

    events = cs.wait_turn(baseline_seq=baseline, max_seconds=args.watch, on_event=on_event)
    media = collect_media(events, baseline)
    print(json.dumps({"events": len(events), "media": sorted(media)}, ensure_ascii=False))
    ws.close()
    return 0


def build_attachment_items(paths) -> list:
    """Attachment items exactly as the web composer builds them (bundle fn `buildAttachmentItems`).

    Images always travel inline as base64 (`data_base64` carries raw base64, no data: prefix).
    Only non-image files >= 10 MB (video: >= 60 MB) go through rupload + `file_ref`.
    """
    items = []
    for raw in paths:
        p = Path(raw)
        data = p.read_bytes()
        mime = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
        items.append(
            {
                "type": "image" if mime.startswith("image/") else "file",
                "mime_type": mime,
                "data_base64": base64.b64encode(data).decode(),
                "filename": p.name,
            }
        )
    return items


def workspace_path(p: str) -> str:
    """Normalize sandbox:// paths, /media/raw URLs and workspace paths to "/workspace/..."."""
    p = (p or "").strip()
    if p.startswith("sandbox://"):
        p = p[len("sandbox://") :]
    m = re.search(r"/(?:media|fs)/raw/(.+)$", p)
    if m:
        p = m.group(1)
    if not p.startswith("/"):
        p = "/" + p
    return p


MEDIA_KEYS = ("images", "videos", "files", "audio")


def collect_media(events, baseline_seq: int = 0) -> dict:
    """Pull media items (path/mime/byte_len/variants) out of chat events."""
    items: dict = {}

    def add(data):
        if not isinstance(data, dict):
            return
        for key in MEDIA_KEYS:
            for m in data.get(key) or []:
                if isinstance(m, dict) and m.get("path"):
                    items.setdefault(workspace_path(m["path"]), m)

    saw_user = False
    for rec in events:
        if rec.get("event") == "message.user":
            saw_user = True
        if baseline_seq > 0 and not saw_user:
            seq = rec.get("seq")
            payload = rec.get("payload") or {}
            chat_seq = payload.get("chat_event_seq") if isinstance(payload, dict) else None
            if isinstance(seq, int) and (seq == chat_seq or seq <= baseline_seq):
                continue
        ev = rec.get("event")
        payload = rec.get("payload") or {}
        if ev == "delta.presentation":
            add(payload.get("data"))
        elif ev == "delta.message_done":
            for msg in (payload.get("transcript") or {}).get("messages", []):
                for c in msg.get("content", []):
                    add(c.get("data") if isinstance(c.get("data"), dict) else c)
    return items


def cmd_gen(args, rest):
    """Send a chat message, wait for the answer, then download every generated file."""
    gw, ws = open_gateway(rest, vm_id=args.vm, vm_name=args.vm_name)
    cs = ChatSession(rest, gw, ws)
    cs.subscribe(args.session)
    session, baseline = cs.drain_baseline(args.drain)
    if args.session:
        session = args.session
    log(f"[gen] session={session} baseline_seq={baseline}")

    prompt = args.text
    if args.count and "image" not in prompt.lower() and "ảnh" not in prompt.lower():
        prompt = f"Generate exactly {args.count} images. {prompt}"
    sid = cs.send(prompt, session_id=session, images=args.image)
    status, ack = cs.wait_ack(sid)
    print(json.dumps({"status": status, "ack": ack}, ensure_ascii=False), flush=True)

    def on_event(rec):
        if rec.get("seq") is None or rec["seq"] > baseline:
            ev = rec.get("event") or rec.get("type")
            payload = rec.get("payload") or {}
            if ev == "delta.text_append":
                print(payload.get("text", ""), end="", flush=True)
            elif ev == "agent.status" and payload.get("activity_text"):
                print(f"\n[status] {payload.get('activity_text')}", flush=True)
            elif ev == "delta.presentation":
                print(f"\n[media] {payload.get('display_text')}", flush=True)
            elif ev == "delta.message_done":
                print("\n[done]", flush=True)

    events = cs.wait_turn(baseline_seq=baseline, max_seconds=args.watch, on_event=on_event,
                          expected_media=max(1, args.count or 1))
    media = collect_media(events, baseline)
    print(f"\n[gen] {len(media)} media item(s) in this turn", flush=True)

    outdir = Path(args.out or "media")
    saved = []
    manifest = []
    if not args.no_download:
        outdir.mkdir(parents=True, exist_ok=True)
        for idx, (path, m) in enumerate(media.items()):
            dest = outdir / (Path(path).name or f"file_{idx}.bin")
            try:
                _, ctype, nbytes = cs.download(path, dest)
            except Exception as e:
                log(f"[download] {path}: {e}")
                continue
            saved.append(str(dest))
            manifest.append({"index": idx, "path": path, "saved": str(dest), "bytes": nbytes, "mime": ctype,
                             "label": m.get("label") or ""})
            print(json.dumps({"saved": str(dest), "bytes": nbytes, "mime": ctype, "label": m.get("label") or ""}))
        if manifest:
            (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    ws.close()
    print(json.dumps({"session_id": session, "media": list(media.keys()), "saved": saved, "manifest": manifest}, ensure_ascii=False))
    return 0


def cmd_rpc(args, rest):
    gw, ws = open_gateway(rest, vm_id=args.vm, vm_name=args.vm_name)
    body = args.data.encode() if args.data else b""
    sid = gw.http(args.method.upper(), args.path, body)
    log(f"[rpc] stream_id={sid} {args.method.upper()} {args.path}")
    cs = ChatSession(rest, gw, ws)
    end = time.time() + args.watch
    got_response = False
    while time.time() < end:
        frame = gw.recv_frame(timeout=min(15, max(0.5, end - time.time())))
        if frame is None:
            continue
        if frame["kind"] == "response" and not got_response:
            got_response = True
            print(
                json.dumps(
                    {
                        "kind": "response",
                        "stream_id": frame["stream_id"],
                        "status": frame["status"],
                        "headers": frame["headers"],
                        "body": decode_body(frame["body"], frame["headers"]).decode("utf-8", "replace")[:2000],
                        "end_body": frame["end_body"],
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
        for rec in cs._records(frame):
            print(json.dumps(rec, ensure_ascii=False), flush=True)
    ws.close()
    return 0


def cmd_media(args, rest):
    """Download a workspace file (sandbox:// path or a VM /media/raw URL) over the tunnel."""
    gw, ws = open_gateway(rest, vm_id=args.vm, vm_name=args.vm_name)
    cs = ChatSession(rest, gw, ws)
    paths = [workspace_path(raw) for raw in args.paths]
    outdir = Path(args.out or "media")
    outdir.mkdir(parents=True, exist_ok=True)
    saved = []
    for p in paths:
        dest = outdir / (Path(p).name or "download.bin")
        try:
            status, ctype, nbytes = cs.download(p, dest, retries=args.retries)
        except Exception as e:
            log(f"[media] {p}: {e}")
            continue
        saved.append(str(dest))
        print(json.dumps({"path": p, "bytes": nbytes, "content_type": ctype, "saved": str(dest)}))
    ws.close()
    if args.json:
        print(json.dumps({"saved": saved}))
    return 0


def cmd_list(args, rest):
    """Replay the chat history and list (optionally download) every media file ever produced."""
    gw, ws = open_gateway(rest, vm_id=args.vm, vm_name=args.vm_name)
    cs = ChatSession(rest, gw, ws)
    cs.subscribe(args.session)
    events = cs.watch(args.drain, quiet=True)
    media = collect_media(events, 0)
    if args.kind:
        media = {p: m for p, m in media.items() if (m.get("mime") or "").startswith(args.kind)}
    outdir = Path(args.out) if args.out else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
    for path, m in sorted(media.items()):
        rec = {"path": path, "mime": m.get("mime"), "bytes": m.get("byte_len"), "label": m.get("label")}
        if outdir:
            dest = outdir / (Path(path).name or "file.bin")
            try:
                _, ctype, nbytes = cs.download(path, dest)
                rec["saved"] = str(dest)
                rec["bytes"] = nbytes
            except Exception as e:
                rec["error"] = str(e)
        print(json.dumps(rec, ensure_ascii=False))
    print(json.dumps({"count": len(media)}))
    ws.close()
    return 0


def cmd_rest(args, rest):
    method = args.method.upper()
    body = None
    if args.data:
        body = args.data.encode()
    r = rest.request(method, args.path, data=body)
    print(f"HTTP {r.status_code} {r.headers.get('content-type','')}")
    txt = r.text
    if args.out:
        Path(args.out).write_bytes(r.content)
        print(f"-> {args.out} ({len(r.content)} bytes)")
    if len(txt) > 20000:
        txt = txt[:20000] + "\n... [truncated]"
    print(txt)
    return 0


def cmd_history(args, rest):
    q = f"/chat/history?limit={args.limit}"
    if args.session:
        q += f"&session_id={quote(args.session)}"
    code, data = rest.json("GET", q)
    print(json.dumps({"status": code, "data": data}, ensure_ascii=False, indent=2)[:20000])
    return 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(prog="muse_client", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="store_true", help="print the client version and exit")
    ap.add_argument("--cookie", help="raw cookie header value (prefer --cookie-file / MUSE_COOKIE)")
    ap.add_argument("--cookie-file", help="path to a file holding the muse.ai cookie (default ~/.muse/cookie.txt)")
    ap.add_argument("--vm", help="vm id override")
    ap.add_argument("--vm-name", help="vm name (passed to /api/hatch/token)")
    ap.add_argument("--json", action="store_true", help="(reserved) machine readable output")
    sub = ap.add_subparsers(dest="cmd", required=False)

    p = sub.add_parser("probe", help="open the noise tunnel and print handshake info")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("chat", help="send a chat message")
    p.add_argument("text")
    p.add_argument("--image", action="append", default=[], help="attach a local image/file (repeatable)")
    p.add_argument("--session", help="session/thread id")
    p.add_argument("--watch", type=float, default=900, help="max seconds to wait for the turn to finish")
    p.add_argument("--raw", action="store_true", help="print every event as JSON")
    p.set_defaults(func=cmd_chat)

    p = sub.add_parser("gen", help="send a prompt and collect generated image urls")
    p.add_argument("text")
    p.add_argument("--image", action="append", default=[], help="attach a local reference image (repeatable)")
    p.add_argument("--session")
    p.add_argument("--count", type=int, default=0)
    p.add_argument("--watch", type=float, default=900, help="max seconds to wait for the turn")
    p.add_argument("--drain", type=float, default=3.0, help="seconds of history replay to skip")
    p.add_argument("--no-download", action="store_true")
    p.add_argument("--out", help="directory to download found images into")
    p.set_defaults(func=cmd_gen)

    p = sub.add_parser("list", help="replay history and list every media file produced")
    p.add_argument("--session")
    p.add_argument("--drain", type=float, default=12.0, help="seconds of history replay to read")
    p.add_argument("--kind", help="filter by mime prefix, e.g. image/ or video/")
    p.add_argument("--out", help="download everything into this directory")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("rest", help="call the muse.ai REST api directly")
    p.add_argument("method")
    p.add_argument("path")
    p.add_argument("--data")
    p.add_argument("--out")
    p.set_defaults(func=cmd_rest)

    p = sub.add_parser("rpc", help="send a raw gateway rpc over the noise tunnel")
    p.add_argument("method")
    p.add_argument("path")
    p.add_argument("--data")
    p.add_argument("--watch", type=float, default=15)
    p.set_defaults(func=cmd_rpc)

    p = sub.add_parser("media", help="download workspace files over the tunnel")
    p.add_argument("paths", nargs="+", help="sandbox:// paths, /media/raw URLs, or workspace paths")
    p.add_argument("--out", help="output directory (default ./media)")
    p.add_argument("--retries", type=int, default=6)
    p.set_defaults(func=cmd_media)

    p = sub.add_parser("history", help="fetch chat history")
    p.add_argument("--session")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_history)

    args = ap.parse_args(argv)
    if args.version:
        print(f"muse_client {MUSE_CLIENT_VERSION}")
        return 0
    if not getattr(args, "func", None):
        ap.error("the following arguments are required: cmd")
    try:
        rest = MuseRest(load_cookie(args))
    except SystemExit as exc:
        # load_cookie raises SystemExit with the message in .code; report it on stderr so the
        # driving tool (cli_media.py) can classify it as an auth problem.
        if exc.code not in (None, 0):
            print(f"error: {exc.code}", file=sys.stderr)
        return 2
    try:
        return args.func(args, rest)
    except GatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
