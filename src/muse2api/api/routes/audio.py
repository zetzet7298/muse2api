"""OpenAI-style TTS shim backed by ElevenLabs (``POST /v1/audio/speech``).

Lets OpenAI-compatible clients (ArcReel's ``openai-tts`` endpoint) use ElevenLabs voices.
The ``voice`` field is an ElevenLabs voice id. The key comes from
``MUSE2API_ELEVENLABS_API_KEY`` or ``~/.muse/elevenlabs.key``.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel

from ...errors import InvalidRequest, UpstreamError
from ..deps import require_api_key

router = APIRouter(tags=["audio"], dependencies=[Depends(require_api_key)])

_FORMATS = {"mp3": ("mp3_44100_128", "audio/mpeg"), "wav": ("pcm_44100", "audio/wav"),
            "pcm": ("pcm_24000", "audio/L16"), "opus": ("opus_48000_128", "audio/ogg")}
_OPENAI_MODELS = {"tts-1", "tts-1-hd", "gpt-4o-mini-tts"}
_DEFAULT_VOICE = os.environ.get("MUSE2API_ELEVENLABS_VOICE_ID", "YeV2u3R2gzLArVTYTis8")  # Tuan Anh - Story


class SpeechRequest(BaseModel):
    model: str | None = None
    input: str
    voice: str | None = None
    response_format: str = "mp3"
    speed: float | None = None


def _key() -> str:
    key = os.environ.get("MUSE2API_ELEVENLABS_API_KEY", "").strip()
    if not key:
        f = Path.home() / ".muse" / "elevenlabs.key"
        key = f.read_text(encoding="utf-8").strip() if f.exists() else ""
    if not key:
        raise InvalidRequest("ElevenLabs key missing (MUSE2API_ELEVENLABS_API_KEY or ~/.muse/elevenlabs.key)")
    return key


@router.post("/v1/audio/speech")
async def speech(body: SpeechRequest) -> Response:
    fmt, mime = _FORMATS.get(body.response_format, _FORMATS["mp3"])
    model = body.model if body.model and body.model not in _OPENAI_MODELS else "eleven_multilingual_v2"
    payload: dict = {"text": body.input, "model_id": model}
    if body.speed:
        payload["voice_settings"] = {"speed": body.speed}
    voice = body.voice if body.voice and len(body.voice) > 12 else _DEFAULT_VOICE
    async with httpx.AsyncClient(timeout=180) as client:
        r = await client.post(f"https://api.elevenlabs.io/v1/text-to-speech/{voice}",
                              params={"output_format": fmt}, json=payload, headers={"xi-api-key": _key()})
    if r.status_code != 200:
        raise UpstreamError(f"elevenlabs HTTP {r.status_code}: {r.text[:300]}")
    return Response(content=r.content, media_type=mime)
