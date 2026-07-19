"""
JARVIS Voice Input — Wake word + STT pipeline (openWakeWord + faster-whisper).

Architecture:
- sounddevice captures 16kHz mono audio from default mic
- openWakeWord detects "hey_jarvis" (pre-trained, no key needed)
- faster-whisper (CT2) transcribes subsequent speech until silence
- Transcribed text goes through SAME pipeline as typed input (one code path)

Hardware: RTX 4060 8GB → use CUDA for whisper. CPU fallback if CUDA unavailable.
Models: faster-whisper base/small (fits VRAM, good accuracy/speed tradeoff)
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
from pathlib import Path
from typing import Callable, Optional

# Optional imports (loaded lazily)
_sounddevice = None
_oww_model = None
_whisper_model = None

# State
_listening = False
_wake_word_detected = None  # will be threading.Event
_stop_event = threading.Event()
_audio_queue: asyncio.Queue = asyncio.Queue()
_stt_thread: Optional[threading.Thread] = None
_callback: Optional[Callable[[str], None]] = None
_audio_stream = None
_listening = False
_muted = False  # Mute mic during TTS playback to prevent echo

# Config
SAMPLE_RATE = 16000
CHANNELS = 1
BLOCK_SIZE = 1280  # 80ms at 16kHz (openWakeWord expects 1280 samples)
SILENCE_THRESHOLD = 0.015  # RMS threshold
SILENCE_DURATION = 1.5  # seconds of silence = end of utterance
MAX_UTTERANCE = 30.0  # max seconds to record


def _init_openwakeword():
    """Lazy-load openWakeWord model."""
    global _oww_model
    if _oww_model is not None:
        return True
    try:
        import openwakeword
        from openwakeword import Model
        # Find the hey_jarvis model
        paths = openwakeword.get_pretrained_model_paths()
        jarvis_path = next((p for p in paths if "hey_jarvis" in p), None)
        if not jarvis_path:
            print("[voice-in] hey_jarvis model not found", flush=True)
            return False
        _oww_model = Model(wakeword_model_paths=[jarvis_path])
        print(f"[voice-in] openWakeWord loaded (hey_jarvis)", flush=True)
        return True
    except Exception as e:
        print(f"[voice-in] openWakeWord init failed: {e}", flush=True)
        return False


def _init_whisper():
    """Lazy-load faster-whisper model on GPU if available."""
    global _whisper_model
    if _whisper_model is not None:
        return True
    try:
        from faster_whisper import WhisperModel
        # Use base model (~142MB) for speed; small (~466MB) for accuracy
        model_size = os.environ.get("WHISPER_MODEL", "base")
        device = "cuda"
        compute_type = "float16"
        try:
            _whisper_model = WhisperModel(
                model_size,
                device=device,
                compute_type=compute_type,
                download_root="/tmp/opencode/whisper_models",
            )
            print(f"[voice-in] faster-whisper loaded: {model_size} on CUDA ({compute_type})")
        except Exception:
            device = "cpu"
            compute_type = "int8"
            _whisper_model = WhisperModel(
                model_size,
                device=device,
                compute_type=compute_type,
                download_root="/tmp/opencode/whisper_models",
            )
            print(f"[voice-in] faster-whisper loaded: {model_size} on CPU ({compute_type})")
        return True
    except Exception as e:
        print(f"[voice-in] Whisper init failed: {e}")
        return False


def _audio_callback(indata, frames, time_info, status):
    """sounddevice callback — pushes audio to async queue."""
    if status:
        print(f"[voice-in] audio status: {status}")
    if _listening and not _muted:
        try:
            _audio_queue.put_nowait(indata.copy())
        except asyncio.QueueFull:
            pass  # drop frame if queue full


def _wake_word_listener():
    """Background thread: runs openWakeWord on incoming audio."""
    import numpy as np
    import threading
    if not _init_openwakeword():
        return
    global _wake_word_detected
    _wake_word_detected = threading.Event()
    print("[voice-in] wake word listener started")
    while not _stop_event.is_set():
        try:
            # Get enough frames for openWakeWord (1280 samples)
            frames_needed = BLOCK_SIZE
            audio = np.zeros(frames_needed, dtype=np.float32)
            collected = 0
            while collected < frames_needed and not _stop_event.is_set():
                try:
                    chunk = _audio_queue.get_nowait()
                    if chunk is not None:
                        chunk = chunk.flatten()
                        take = min(len(chunk), frames_needed - collected)
                        audio[collected:collected + take] = chunk[:take]
                        collected += take
                except asyncio.QueueEmpty:
                    time.sleep(0.01)
            if collected == frames_needed:
                prediction = _oww_model.predict(audio)
                # prediction is dict like {"hey_jarvis": 0.95}
                score = prediction.get("hey_jarvis", 0.0)
                if score > 0.5:  # threshold
                    print(f"[voice-in] Wake word detected (score={score:.2f})")
                    _wake_word_detected.set()
        except Exception as e:
            print(f"[voice-in] wake word error: {e}")
            time.sleep(0.1)


def _stt_listener():
    """Background thread: records audio after wake word, transcribes with whisper."""
    import numpy as np
    import threading
    if not _init_whisper():
        return
    print("[voice-in] STT listener ready")
    while not _stop_event.is_set():
        # Wait for wake word
        if _wake_word_detected is None:
            time.sleep(0.5)
            continue
        if not _wake_word_detected.wait(timeout=0.5):
            continue
        _wake_word_detected.clear()
        print("[voice-in] Recording utterance...")
        # Record until silence
        audio_chunks = []
        silence_start = None
        start_time = time.time()
        while not _stop_event.is_set():
            try:
                chunk = _audio_queue.get(timeout=0.5)
                if chunk is not None:
                    audio_chunks.append(chunk.flatten())
                    # Simple VAD: RMS energy
                    rms = float(np.sqrt(np.mean(chunk.astype(np.float32) ** 2)))
                    if rms < SILENCE_THRESHOLD:
                        if silence_start is None:
                            silence_start = time.time()
                        elif time.time() - silence_start > SILENCE_DURATION:
                            break
                    else:
                        silence_start = None
            except asyncio.QueueEmpty:
                pass
            # Max utterance length
            if time.time() - start_time > MAX_UTTERANCE:
                break
        if audio_chunks:
            audio_data = np.concatenate(audio_chunks, axis=0).astype(np.float32)
            print(f"[voice-in] Transcribing {len(audio_data)/SAMPLE_RATE:.1f}s audio...")
            try:
                segments, _ = _whisper_model.transcribe(
                    audio_data,
                    language=None,  # auto-detect
                    beam_size=5,
                    vad_filter=True,
                    vad_parameters=dict(min_silence_duration_ms=500),
                )
                text = " ".join(seg.text.strip() for seg in segments).strip()
                if text:
                    print(f"[voice-in] Transcribed: {text}")
                    if _callback:
                        # Use asyncio to run the callback in the main event loop
                        import asyncio
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                asyncio.run_coroutine_threadsafe(_callback(text), loop)
                            else:
                                asyncio.run(_callback(text))
                        except RuntimeError:
                            pass
            except Exception as e:
                print(f"[voice-in] Transcription error: {e}")


# --- Public API ---

async def start_voice_input(callback: Callable[[str], None]) -> None:
    """Start the voice input pipeline (wake word + STT)."""
    global _listening, _callback, _stt_thread, _audio_stream
    if _listening:
        return
    _callback = callback
    _listening = True
    _stop_event.clear()
    
    # Start audio stream
    import sounddevice as sd
    global _sounddevice
    _sounddevice = sd
    _audio_stream = sd.InputStream(
        samplerate=SAMPLE_RATE,
        channels=CHANNELS,
        dtype="float32",
        blocksize=BLOCK_SIZE,
        callback=_audio_callback,
    )
    _audio_stream.start()
    print("[voice-in] Audio stream started", flush=True)
    
    # Start wake word listener thread
    wake_thread = threading.Thread(target=_wake_word_listener, daemon=True)
    wake_thread.start()
    
    # Start STT thread
    _stt_thread = threading.Thread(target=_stt_listener, daemon=True)
    _stt_thread.start()
    
    print("[voice-in] Voice input active — say 'Hey Jarvis' to begin", flush=True)


async def stop_voice_input() -> None:
    """Stop the voice input pipeline."""
    global _stt_thread, _audio_stream, _stop_event
    _stop_event.set()
    if _audio_stream:
        _audio_stream.stop()
        _audio_stream.close()
        _audio_stream = None
    if _stt_thread:
        _stt_thread.join(timeout=2.0)
    _stt_thread = None
    _listening = False
    print("[voice-in] Voice input stopped")


def mute_microphone() -> None:
    """Mute microphone during TTS playback to prevent echo."""
    global _muted
    _muted = True
    print("[voice-in] Microphone muted (TTS playing)")


def unmute_microphone() -> None:
    """Unmute microphone after TTS playback."""
    global _muted
    _muted = False
    print("[voice-in] Microphone unmuted (TTS done)")


def is_listening() -> bool:
    return _stt_thread is not None and _stt_thread.is_alive()