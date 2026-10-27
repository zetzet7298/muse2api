"""Direct-protocol driver: talks to muse.ai's hatch gateway without a browser.

The gateway speaks Noise_XX over a websocket; ``muse_client`` (vendored from the
standalone muse-api client) implements the handshake and the chat RPCs. Every call is
blocking, so each request runs in a worker thread and is bridged back to asyncio.
Completion is event-driven: a turn ends as soon as the agent emits its media (or
``task.status: completed``), no fixed sleeps.
"""

from __future__ import annotations

import asyncio
import mimetypes
import tempfile
import threading
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from ...accounts.model import Account
from ...config import Settings
from ...errors import UpstreamAuthError, UpstreamError
from ...upstream import muse
from ..base import (
    ChatRequest,
    DriverCapabilities,
    ImageRequest,
    InputImage,
    MediaResult,
    MuseDriver,
    SessionInfo,
    VideoRequest,
)
from . import muse_client as mc

_DONE = object()


def _cookie_header(account: Account) -> str:
    return "; ".join(f"{k}={v}" for k, v in account.cookies.items())


def _aspect_hint(size: str | None) -> str:
    if not size:
        return ""
    if ":" in size:
        return f" Aspect ratio {size}."
    if "x" in size:
        try:
            w, h = (int(v) for v in size.lower().split("x"))
        except ValueError:
            return ""
        r = w / h
        ar = "16:9" if r > 1.5 else "9:16" if r < 0.67 else "4:3" if r > 1.15 else "3:4" if r < 0.87 else "1:1"
        return f" Aspect ratio {ar}."
    return ""


def _stage_images(images: list[InputImage], workdir: str) -> list[str]:
    paths = []
    for i, img in enumerate(images):
        ext = mimetypes.guess_extension(img.mime) or ".png"
        p = Path(workdir) / f"ref{i}{ext}"
        p.write_bytes(img.data)
        paths.append(str(p))
    return paths


def _wrap(exc: Exception) -> UpstreamError:
    if isinstance(exc, UpstreamError):
        return exc
    text = str(exc)
    if "HTTP 401" in text or "HTTP 403" in text:
        return UpstreamAuthError(f"muse session rejected: {text}")
    return UpstreamError(f"muse request failed: {text}")


class HttpDriver(MuseDriver):
    name = "http"
    capabilities = DriverCapabilities(
        chat=True, chat_images=True, image=True, image_edit=True, video=True, renew_session=True
    )

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    # -- gateway plumbing ------------------------------------------------- #
    @staticmethod
    def _wake(rest: Any, timeout: float = 90.0) -> None:
        _, info = rest.session_info()
        vm_id = (info or {}).get("vm_id")
        if not vm_id:
            return
        rest.json("POST", "/api/hatch/vm/wake",
                  json={"vm_id": vm_id, "retry_count": 0, "connect_attempt_id": str(uuid.uuid4())})
        end = time.time() + timeout
        while time.time() < end:
            _, info = rest.session_info()
            if (info or {}).get("vm_state") in ("RUNNING", "LIVE"):
                return
            time.sleep(1.5)

    def _open(self, rest: Any):
        try:
            return mc.open_gateway(rest)
        except Exception as exc:  # suspended VM -> 502 on the websocket
            if "502" not in str(exc) and "suspended" not in str(exc).lower():
                raise
            self._wake(rest)
            last: Exception = exc
            for _ in range(10):
                try:
                    return mc.open_gateway(rest)
                except Exception as e2:
                    last = e2
                    time.sleep(3)
            raise last

    def _turn(self, account: Account, prompt: str, images: list[str], *, expected: int, timeout: float,
              on_text=None, cancel: threading.Event | None = None):
        """Blocking: one prompt -> (chat session, events, media). The caller closes ``cs.gw.ws``."""
        rest = mc.MuseRest(_cookie_header(account))
        try:
            gw, ws = self._open(rest)
        except Exception as exc:
            raise _wrap(exc) from exc
        try:
            cs = mc.ChatSession(rest, gw, ws)
            cs.subscribe(None)
            session, baseline = cs.drain_baseline(2.0)
            sid = cs.send(prompt, session_id=session, images=images)
            status, ack = cs.wait_ack(sid)
            if status != 200:
                raise UpstreamError(f"muse rejected the prompt: HTTP {status} {ack}")

            def on_event(rec):
                if cancel is not None and cancel.is_set():
                    raise InterruptedError("cancelled")
                if on_text and rec.get("event") == "delta.text_append":
                    text = (rec.get("payload") or {}).get("text")
                    if text:
                        on_text(text)

            events = cs.wait_turn(baseline_seq=baseline, max_seconds=timeout, grace=0.5,
                                  on_event=on_event, expected_media=max(1, expected))
            return cs, events, mc.collect_media(events, baseline)
        except Exception as exc:
            ws.close()
            if isinstance(exc, InterruptedError):
                raise
            raise _wrap(exc) from exc

    def _download_media(self, cs, media: dict, kind: str) -> list[MediaResult]:
        out: list[MediaResult] = []
        with tempfile.TemporaryDirectory() as d:
            for path in media:
                dest = Path(d) / (Path(path).name or "file.bin")
                _, ctype, _ = cs.download(path, dest)
                mime = ctype.split(";")[0] or mimetypes.guess_type(dest.name)[0] or "application/octet-stream"
                if mime.startswith(kind + "/"):
                    out.append(MediaResult(data=dest.read_bytes(), mime=mime, kind=kind))  # type: ignore[arg-type]
        return out

    async def _run_media(self, account, prompt, images, kind, expected, timeout, cancel) -> list[MediaResult]:
        stop = threading.Event()

        def work() -> list[MediaResult]:
            with tempfile.TemporaryDirectory() as d:
                cs, events, media = self._turn(account, prompt, _stage_images(images, d),
                                               expected=expected, timeout=timeout, cancel=stop)
                try:
                    if not media:
                        text = "".join((e.get("payload") or {}).get("text", "")
                                       for e in events if e.get("event") == "delta.text_append")
                        raise UpstreamError("muse returned no media: " + (text[:300] or "empty reply"))
                    results = self._download_media(cs, media, kind)
                    if not results:
                        raise UpstreamError(f"muse returned no {kind} in this turn")
                    return results
                finally:
                    try:
                        cs.gw.ws.close()
                    except Exception:
                        pass

        def work_retry() -> list[MediaResult]:
            # An occasional turn ends without media (agent replied with nothing); one retry fixes it.
            try:
                return work()
            except UpstreamError as exc:
                if "returned no" not in str(exc):
                    raise
                return work()

        task = asyncio.ensure_future(asyncio.to_thread(work_retry))
        try:
            while not task.done():
                if cancel is not None and cancel.is_set():
                    stop.set()
                    raise asyncio.CancelledError()
                await asyncio.wait({task}, timeout=0.5)
            return task.result()
        except asyncio.CancelledError:
            stop.set()
            raise

    # -- MuseDriver ------------------------------------------------------- #
    async def chat_stream(self, account: Account, req: ChatRequest) -> AsyncIterator[str]:
        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        stop = threading.Event()

        def push(item):
            loop.call_soon_threadsafe(queue.put_nowait, item)

        def work():
            try:
                with tempfile.TemporaryDirectory() as d:
                    cs, _events, _media = self._turn(account, req.prompt, _stage_images(req.images, d),
                                                     expected=1, timeout=req.timeout, on_text=push, cancel=stop)
                    cs.gw.ws.close()
                push(_DONE)
            except BaseException as exc:  # noqa: BLE001
                push(exc)

        loop.run_in_executor(None, work)
        first = True
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), req.first_token_timeout if first else req.timeout)
            except asyncio.TimeoutError as exc:
                stop.set()
                raise UpstreamError("muse chat timed out") from exc
            if req.cancel is not None and req.cancel.is_set():
                stop.set()
                return
            if item is _DONE:
                return
            if isinstance(item, BaseException):
                raise item
            first = False
            yield item

    async def generate_image(self, account: Account, req: ImageRequest) -> list[MediaResult]:
        n = max(1, req.n)
        prompt = f"Generate exactly {n} image{'s' if n > 1 else ''}. {req.prompt}{_aspect_hint(req.size)}"
        if req.reference_images:
            prompt += " Use the attached image(s) as reference."
        results = await self._run_media(account, prompt, req.reference_images, "image", n, req.timeout, req.cancel)
        if req.on_progress:
            req.on_progress(100)
        for r in results:
            r.revised_prompt = req.prompt
        return results[:n]

    async def generate_video(self, account: Account, req: VideoRequest) -> MediaResult:
        prompt = (f"Generate a {req.duration} second video. " if req.duration else "Generate a video. ") + req.prompt
        prompt += _aspect_hint(req.size)
        imgs = [req.first_frame] if req.first_frame else []
        if imgs:
            prompt += " Use the attached image as the first frame."
        results = await self._run_media(account, prompt, imgs, "video", 1, req.timeout, req.cancel)
        if req.on_progress:
            req.on_progress(100)
        return results[0]

    async def renew_session(self, account: Account) -> SessionInfo:
        return await muse.renew_session(account.cookies)
