"""
JARVIS Voice Output — TTS provider chain.

Auto-failover (silent to user):
    1. ElevenLabs  — real JARVIS voice, 10k chars/month free
    2. gTTS        — Google TTS, free, needs internet
    3. pyttsx3     — fully offline, espeak-ng backend, always works

ElevenLabs usage tracked locally; auto-falls back when quota would be exceeded.
Spoken text capped at 350 chars — full response shown in dashboard.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import time
from pathlib import Path
from typing import Optional

# --- Config ------------------------------------------------------------------
ELEVENLABS_API_KEY = os.environ.get("ELEVENLABS_API_KEY", "").strip()
ELEVENLABS_VOICE_ID = os.environ.get("ELEVENLABS_VOICE_ID", "pNInz6obpgDQGcFmaJgB").strip()  # default "Adam" - British male
ELEVENLABS_MONTHLY_LIMIT = 10_000  # free tier chars/month
ELEVENLABS_USAGE_FILE = Path("/tmp/opencode/jarvis_elevenlabs_usage.txt")

MAX_SPEAK_CHARS = 350

# --- Usage tracking ----------------------------------------------------------
def _load_usage() -> dict:
    try:
        if ELEVENLABS_USAGE_FILE.exists():
            data = ELEVENLABS_USAGE_FILE.read_text().strip()
            month, chars = data.split(",")
            if month == time.strftime("%Y-%m"):
                return {"month": month, "chars": int(chars)}
    except Exception:
        pass
    return {"month": time.strftime("%Y-%m"), "chars": 0}


def _save_usage(usage: dict) -> None:
    ELEVENLABS_USAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    ELEVENLABS_USAGE_FILE.write_text(f"{usage['month']},{usage['chars']}")


def _can_use_elevenlabs(chars: int) -> bool:
    usage = _load_usage()
    return ELEVENLABS_API_KEY and (usage["chars"] + chars) <= ELEVENLABS_MONTHLY_LIMIT


def _record_elevenlabs_usage(chars: int) -> None:
    usage = _load_usage()
    usage["chars"] += chars
    _save_usage(usage)


# --- Provider implementations ------------------------------------------------
async def _speak_elevenlabs(text: str) -> bool:
    """Returns True on success, False on failure/quota."""
    if not _can_use_elevenlabs(len(text)):
        return False
    try:
        from elevenlabs.client import ElevenLabs
        from elevenlabs import play
    except ImportError:
        return False
    try:
        client = ElevenLabs(api_key=ELEVENLABS_API_KEY)
        audio = client.text_to_speech.convert(
            voice_id=ELEVENLABS_VOICE_ID,
            text=text,
            model_id="eleven_multilingual_v2",
            output_format="mp3_44100_128",
        )
        # elevenlabs returns a generator; collect bytes
        audio_bytes = b"".join(audio) if hasattr(audio, "__iter__") else audio
        # play via ffplay (fast, no pygame dependency)
        proc = await asyncio.create_subprocess_exec(
            "ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", "-i", "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate(audio_bytes)
        _record_elevenlabs_usage(len(text))
        return True
    except Exception:
        return False


async def _speak_gtts(text: str) -> bool:
    """Google TTS via gTTS. Needs internet. Returns True on success."""
    try:
        from gtts import gTTS
    except ImportError:
        return False
    try:
        tts = gTTS(text=text, lang="en", tld="co.uk")  # British
        # Save to temp file and play
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as f:
            tmp = f.name
        tts.save(tmp)
        proc = await asyncio.create_subprocess_exec(
            "ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", tmp,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _speak_pyttsx3(text: str) -> bool:
    """Offline TTS via pyttsx3 (espeak-ng). Always available."""
    try:
        import pyttsx3
    except ImportError:
        return False
    try:
        # pyttsx3 is synchronous and not thread-safe; run in executor
        def _run() -> None:
            engine = pyttsx3.init()
            # Prefer a British voice if available
            for v in engine.getProperty("voices"):
                if "english" in v.name.lower() and ("uk" in v.id.lower() or "british" in v.name.lower()):
                    engine.setProperty("voice", v.id)
                    break
            engine.setProperty("rate", 185)
            engine.setProperty("volume", 0.95)
            engine.say(text)
            engine.runAndWait()
        await asyncio.get_event_loop().run_in_executor(None, _run)
        return True
    except Exception:
        return False


# --- Public API --------------------------------------------------------------
async def speak(text: str) -> None:
    """
    Speak the given text using the first available provider.
    Text is truncated to MAX_SPEAK_CHARS.
    """
    if not text or not text.strip():
        return
    # Cap spoken length per spec
    if len(text) > MAX_SPEAK_CHARS:
        text = text[:MAX_SPEAK_CHARS].rsplit(" ", 1)[0] + "…"

    # Provider chain
    for provider in (_speak_elevenlabs, _speak_gtts, _speak_pyttsx3):
        if await provider(text):
            return
    # If all fail, silently give up — the text is already in the dashboard


def get_provider_status() -> dict:
    """For /api/voice endpoint — what's available."""
    status = {
        "elevenlabs": {
            "available": bool(ELEVENLABS_API_KEY),
            "quota_remaining": max(0, ELEVENLABS_MONTHLY_LIMIT - _load_usage()["chars"]),
            "voice_id": ELEVENLABS_VOICE_ID,
        },
        "gtts": {"available": shutil.which("ffplay") is not None},  # needs ffplay
        "pyttsx3": {"available": True},  # always, if deps installed
    }
    return status