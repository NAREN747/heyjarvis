"""
JARVIS — main entrypoint.

Run it:
    .venv/bin/python main.py
or:
    .venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000

Step 2 scope (per spec build order):
    - Step 1: server + chat (working)
    - Step 2: voice output — every JARVIS response is spoken aloud
    - pyttsx3 default (offline, no key, works on Linux immediately)
    - ElevenLabs when key is configured (the real JARVIS voice)
    - Auto-fallback: ElevenLabs → gTTS → pyttsx3
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

import httpx

from brain import think, provider_status
from voice import speak, get_provider_status
from voice_input import start_voice_input, stop_voice_input, mute_microphone, unmute_microphone
from self_modify import SelfModifier, start_health_check
from security import SecurityManager
from youtube_automation import YouTubeAutomation, VideoMetadata

# --- Tokens -----------------------------------------------------------------
# Auto-generated on first run, stored in .jarvis_token, gitignored. Per spec,
# WS first message must auth with {"token": "..."}, REST endpoints need the
# X-Jarvis-Token header. Desktop browsers reading the HUD from localhost don't
# strictly need auth, but the contract is enforced from day one.

BASE_DIR = Path(__file__).resolve().parent
TOKEN_FILE = BASE_DIR / ".jarvis_token"
FRONTEND_DIR = BASE_DIR / "frontend"


def ensure_token() -> str:
    if not TOKEN_FILE.exists():
        import secrets
        TOKEN_FILE.write_text(secrets.token_urlsafe(32))
        try:
            os.chmod(TOKEN_FILE, 0o600)
        except OSError:
            pass
    return TOKEN_FILE.read_text().strip()


AUTH_TOKEN = ensure_token()


# --- Connection registry ----------------------------------------------------
class Hub:
    """
    Tracks live dashboard clients and broadcasts events. Voice state and
    tool-use events multiply to all connected clients — a local pub/sub is over
    the top for Step 1; a set of WebSockets is honest.
    """

    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self._history: list[dict[str, Any]] = []

    def register(self, ws: WebSocket) -> None:
        self.clients.add(ws)

    def unregister(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, event: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in list(self.clients):
            try:
                await ws.send_text(json.dumps(event))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    def history(self) -> list[dict[str, Any]]:
        return list(self._history)


hub = Hub()
http_client: httpx.AsyncClient  # shared across LLM calls for Step 1
self_modifier: SelfModifier | None = None
security_manager: SecurityManager | None = None


async def _restart_server():
    """Restart callback for self-modification."""
    await hub.broadcast({"type": "system", "message": "Restarting to apply modification..."})
    os.execv(sys.executable, [sys.executable] + sys.argv)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global http_client, self_modifier, security_manager
    http_client = httpx.AsyncClient()
    print(f"[jarvis] NVIDIA_API_KEY: {'set' if os.environ.get('NVIDIA_API_KEY') else 'NOT SET — using Ollama fallback'}")
    print(f"[jarvis] server on http://127.0.0.1:8000")
    print(f"[jarvis] token: {AUTH_TOKEN}")
    # Start voice input (wake word + STT) — runs in background
    print("[jarvis] Starting voice input...")
    async def on_voice_transcript(text: str):
        await process_user_message(text)
    await start_voice_input(on_voice_transcript)
    print("[jarvis] Voice input started")
    # Initialize self-modifier
    self_modifier = SelfModifier(BASE_DIR, _restart_server, hub.broadcast)
    # Initialize security manager
    security_manager = SecurityManager(BASE_DIR, hub.broadcast)
    await security_manager.start()
    # Start health check after restart
    await start_health_check(BASE_DIR / "jarvis_snapshots", BASE_DIR, hub.broadcast)
    try:
        yield
    finally:
        await stop_voice_input()
        await security_manager.stop()
        await http_client.aclose()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


# --- Token guard -------------------------------------------------------------
def token_ok(sent: str | None) -> bool:
    if not sent:
        return False
    return sent.strip() == AUTH_TOKEN


# --- Routes ------------------------------------------------------------------
@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    """No auth — load balancer / watchdog ping."""
    return {"status": "ok"}


@app.get("/")
async def dashboard() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/token", response_model=None)
async def get_token(request: Request) -> PlainTextResponse | JSONResponse:
    """
    Same-machine trust: a request from 127.0.0.1 / ::1 may discover the token
    once, so the desktop dashboard self-configures with zero friction. Remote
    callers never see it — they must already have the token from .jarvis_token
    on the host. There is no other way to learn it.

    This keeps the auth contract honest in both directions: the desktop is
    silent and self-sufficient; remote access stays gated.
    """
    client_host = (request.client.host if request.client else "") or ""
    if client_host in ("127.0.0.1", "::1", "localhost"):
        return PlainTextResponse(AUTH_TOKEN)
    return JSONResponse(
        {"token_required": True, "hint": "read .jarvis_token on the host"},
        status_code=401,
    )


@app.get("/api/history")
async def history(x_jarvis_token: str | None = None) -> JSONResponse:
    if not token_ok(x_jarvis_token):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"messages": hub.history()})


@app.get("/api/providers")
async def providers(x_jarvis_token: str | None = None) -> JSONResponse:
    if not token_ok(x_jarvis_token):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    status = await provider_status(http_client)
    return JSONResponse({"providers": [p.__dict__ for p in status]})


# --- WebSocket chat ----------------------------------------------------------
@app.websocket("/ws")
async def ws_chat(ws: WebSocket) -> None:
    # First frame must authenticate. Per spec: connection closed immediately on
    # bad token. Desktop dashboard still has to send the token from .jarvis_token,
    # which keeps the contract honest rather than decorative.
    await ws.accept()
    try:
        first = await ws.receive_text()
        try:
            payload = json.loads(first)
        except json.JSONDecodeError:
            payload = {}
        if not token_ok(payload.get("token")):
            await ws.send_text(json.dumps({"type": "auth", "ok": False, "reason": "bad token"}))
            await ws.close(code=1008)
            return
        await ws.send_text(json.dumps({"type": "auth", "ok": True}))
    except WebSocketDisconnect:
        return

    hub.register(ws)
    # Replay in-flight history to the late joiner.
    for msg in hub.history():
        await ws.send_text(json.dumps({"type": "message", **msg}))

    try:
        async for raw in ws.iter_text():
            try:
                frame = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(json.dumps({"type": "error", "reason": "bad json"}))
                continue
            user_text = (frame.get("text") or "").strip()
            if not user_text:
                continue
            await process_user_message(user_text)
    except (WebSocketDisconnect, RuntimeError):
        # RuntimeError: "WebSocket is not connected" on closed connection
        pass
    except Exception as e:
        print(f"[ws] unexpected error: {e}")
    finally:
        hub.unregister(ws)


async def process_user_message(user_text: str) -> None:
    """Core message pipeline — used by both WS chat and voice input."""
    if not user_text.strip():
        return
    user_msg = {"role": "user", "content": user_text, "ts": _now()}
    hub._history.append(user_msg)
    await hub.broadcast({"type": "message", **user_msg})
    await hub.broadcast({"type": "state", "phase": "thinking"})

    async def self_modify_confirm(prompt: str) -> bool:
        """Callback for self-modification confirmation."""
        await hub.broadcast({
            "type": "confirm",
            "prompt": prompt,
            "action": "self_modify",
        })
        # Wait for user response via WS - for now, auto-deny
        # In production, this would wait for a specific WS message
        return False

    try:
        result = await think(hub.history()[:-1], user_text, http_client, confirm_callback=self_modify_confirm)
    except Exception as e:
        await hub.broadcast({
            "type": "message", "role": "assistant",
            "content": f"I hit a snag, Sir — {type(e).__name__}.\nPlease try again, or check the provider.",
            "provider": "error", "model": "-", "ts": _now(),
        })
        await hub.broadcast({"type": "state", "phase": "idle"})
        return

    assistant_msg = {
        "role": "assistant",
        "content": result.text,
        "provider": result.provider,
        "model": result.model,
        "ts": _now(),
    }
    hub._history.append(assistant_msg)
    await hub.broadcast({"type": "message", **assistant_msg})
    await hub.broadcast({"type": "state", "phase": "speaking"})
    
    # Mute microphone during TTS to prevent echo
    mute_microphone()
    await speak(result.text)
    unmute_microphone()
    
    await hub.broadcast({"type": "state", "phase": "idle"})


@app.get("/api/voice/providers")
async def voice_providers(request: Request) -> JSONResponse:
    """Voice provider chain status — for dashboard indicator."""
    return JSONResponse({"providers": get_provider_status()})


# --- Security Routes ---------------------------------------------------------

@app.get("/api/security/status")
async def security_status(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"status": security_manager.get_status()})


@app.get("/api/security/vault/integrity")
async def vault_integrity(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    result = await security_manager.vault.verify_integrity(full=True)
    return JSONResponse({"ok": result})


@app.post("/api/security/vault/lock")
async def vault_lock(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    security_manager.vault.lock()
    return JSONResponse({"success": True, "message": "Vault locked"})


@app.post("/api/security/vault/unlock")
async def vault_unlock(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    password = data.get("password", "")
    ok = security_manager.vault.unlock(password)
    return JSONResponse({"success": ok, "message": "Unlocked" if ok else "Invalid password"})


@app.get("/api/security/vault/secrets")
async def vault_list_secrets(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    # Require password
    data = await request.json() if request.headers.get("Content-Type") == "application/json" else {}
    password = data.get("password", "")
    if not security_manager.vault.unlock(password):
        return JSONResponse({"error": "Invalid password"}, status_code=401)
    keys = security_manager.vault.list_keys()
    return JSONResponse({"keys": keys})


@app.post("/api/security/vault/store")
async def vault_store_secret(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    password = data.get("password", "")
    key = data.get("key", "")
    value = data.get("value", "")
    if not key or not value:
        return JSONResponse({"error": "key and value required"}, status_code=400)
    if not security_manager.vault.unlock(password):
        return JSONResponse({"error": "Invalid password"}, status_code=401)
    security_manager.vault.store(key, value)
    return JSONResponse({"success": True})


@app.post("/api/security/vault/retrieve")
async def vault_retrieve_secret(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    password = data.get("password", "")
    key = data.get("key", "")
    if not key:
        return JSONResponse({"error": "key required"}, status_code=400)
    if not security_manager.vault.unlock(password):
        return JSONResponse({"error": "Invalid password"}, status_code=401)
    value = security_manager.vault.retrieve(key)
    return JSONResponse({"success": True, "value": value})


@app.post("/api/security/vault/delete")
async def vault_delete_secret(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    password = data.get("password", "")
    key = data.get("key", "")
    if not key:
        return JSONResponse({"error": "key required"}, status_code=400)
    if not security_manager.vault.unlock(password):
        return JSONResponse({"error": "Invalid password"}, status_code=401)
    ok = security_manager.vault.delete(key)
    return JSONResponse({"success": ok})


@app.get("/api/security/network/status")
async def network_status(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"status": security_manager.network.get_status()})


@app.get("/api/security/network/connections")
async def network_connections(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"connections": security_manager.network.get_recent_connections()})


@app.post("/api/security/network/block")
async def network_block_ip(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    ip = data.get("ip", "")
    ok = security_manager.network.block_ip(ip)
    return JSONResponse({"success": ok})


@app.post("/api/security/network/unblock")
async def network_unblock_ip(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    ip = data.get("ip", "")
    ok = security_manager.network.unblock_ip(ip)
    return JSONResponse({"success": ok})


@app.get("/api/security/intrusion/status")
async def intrusion_status(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"status": security_manager.intrusion.get_status()})


@app.get("/api/security/intrusion/alerts")
async def intrusion_alerts(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    limit = int(request.query_params.get("limit", 20))
    return JSONResponse({"alerts": security_manager.intrusion.get_recent_alerts(limit)})


@app.post("/api/security/intrusion/acknowledge")
async def intrusion_acknowledge(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    alert_id = data.get("alert_id", "")
    ok = security_manager.intrusion.acknowledge_alert(alert_id)
    return JSONResponse({"success": ok})


@app.get("/api/security/defense/status")
async def defense_status(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"status": security_manager.selfdefense.get_status()})


@app.post("/api/security/defense/lockdown")
async def defense_lockdown(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    reason = data.get("reason", "Manual lockdown")
    result = await security_manager.selfdefense.lockdown(reason)
    return JSONResponse(result)


@app.post("/api/security/defense/unlock")
async def defense_unlock(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    password = data.get("password", "")
    result = await security_manager.selfdefense.unlock(password)
    return JSONResponse(result)


# --- Identity Routes ---------------------------------------------------------

@app.post("/api/identity/verify")
async def identity_verify(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    password = data.get("password", "")
    face_image = data.get("face_image")  # base64 encoded
    result = security_manager.identity.verify(password, face_image)
    return JSONResponse(result)


@app.post("/api/identity/enroll_face")
async def identity_enroll_face(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    face_image = data.get("face_image")  # base64
    result = security_manager.identity.enroll_face(face_image)
    return JSONResponse(result)


@app.post("/api/identity/change_password")
async def identity_change_password(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    old = data.get("old", "")
    new = data.get("new", "")
    result = security_manager.identity.change_password(old, new)
    return JSONResponse(result)


@app.post("/api/identity/set_initial_password")
async def identity_set_initial_password(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    password = data.get("password", "")
    result = security_manager.identity.set_initial_password(password)
    return JSONResponse(result)


@app.get("/api/identity/status")
async def identity_status(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(security_manager.identity.get_status())


# --- Security Tools for LLM ---

@app.post("/api/security/tools/execute")
async def security_tools_execute(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    tool = data.get("tool", "")
    params = data.get("params", {})
    result = await security_manager.execute_security_tool(tool, params)
    return JSONResponse(result)


@app.get("/api/identity/status")
async def identity_status(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(security_manager.identity.get_status())


# --- YouTube Automation Routes ----------------------------------------------

@app.get("/api/youtube/status")
async def youtube_status(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not security_manager.youtube.is_authenticated:
        return JSONResponse({"authenticated": False})
    channel = await security_manager.youtube.get_my_channel()
    return JSONResponse({"authenticated": True, "channel": channel})


@app.get("/api/youtube/channel")
async def youtube_channel(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    channel_id = request.query_params.get("id")
    if not channel_id:
        return JSONResponse({"error": "channel_id required"}, status_code=400)
    channel = await security_manager.youtube.get_channel_by_id(channel_id)
    return JSONResponse(channel)


@app.post("/api/youtube/upload")
async def youtube_upload(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    
    data = await request.json()
    file_path = data.get("file_path")
    if not file_path:
        return JSONResponse({"error": "file_path required"}, status_code=400)
    
    metadata = VideoMetadata(
        title=data.get("title", "Untitled"),
        description=data.get("description", ""),
        tags=data.get("tags", []),
        category_id=data.get("category_id", "22"),
        privacy_status=data.get("privacy_status", "private"),
        thumbnail_path=data.get("thumbnail_path"),
        playlist_id=data.get("playlist_id"),
        made_for_kids=data.get("made_for_kids", False),
    )
    
    if data.get("publish_at"):
        metadata.publish_at = datetime.fromisoformat(data["publish_at"])
    
    try:
        result = await security_manager.youtube.upload_video(
            file_path=file_path,
            metadata=metadata,
        )
        return JSONResponse({
            "success": True,
            "video_id": result.video_id,
            "url": result.url,
            "status": result.status,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.put("/api/youtube/video/{video_id}")
async def youtube_update_video(video_id: str, request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    metadata = VideoMetadata(
        title=data.get("title", ""),
        description=data.get("description", ""),
        tags=data.get("tags", []),
        category_id=data.get("category_id", "22"),
        privacy_status=data.get("privacy_status", "private"),
    )
    try:
        result = await security_manager.youtube.update_video(video_id, metadata)
        return JSONResponse({"success": True, "result": result})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.delete("/api/youtube/video/{video_id}")
async def youtube_delete_video(video_id: str, request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        await security_manager.youtube.delete_video(video_id)
        return JSONResponse({"success": True, "message": "Video deleted"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/youtube/thumbnail")
async def youtube_set_thumbnail(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    video_id = data.get("video_id")
    thumbnail_path = data.get("thumbnail_path")
    if not video_id or not thumbnail_path:
        return JSONResponse({"error": "video_id and thumbnail_path required"}, status_code=400)
    try:
        await security_manager.youtube.set_thumbnail(video_id, thumbnail_path)
        return JSONResponse({"success": True})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/youtube/playlist/add")
async def youtube_add_to_playlist(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    playlist_id = data.get("playlist_id")
    video_id = data.get("video_id")
    if not playlist_id or not video_id:
        return JSONResponse({"error": "playlist_id and video_id required"}, status_code=400)
    try:
        result = await security_manager.youtube.add_to_playlist(playlist_id, video_id)
        return JSONResponse({"success": True, "result": result})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/youtube/videos")
async def youtube_list_videos(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    max_results = int(request.query_params.get("max_results", 50))
    order = request.query_params.get("order", "date")
    try:
        videos = await security_manager.youtube.list_my_videos(max_results, order)
        return JSONResponse({"videos": videos})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/youtube/video/{video_id}")
async def youtube_get_video(video_id: str, request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        details = await security_manager.youtube.get_video_stats(video_id)
        return JSONResponse(details)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/youtube/playlist/create")
async def youtube_create_playlist(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    title = data.get("title")
    description = data.get("description", "")
    privacy = data.get("privacy_status", "private")
    if not title:
        return JSONResponse({"error": "title required"}, status_code=400)
    try:
        result = await security_manager.youtube.create_playlist(title, description, privacy)
        return JSONResponse({"success": True, "playlist": result})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/youtube/playlists")
async def youtube_list_playlists(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    max_results = int(request.query_params.get("max_results", 50))
    try:
        playlists = await security_manager.youtube.list_my_playlists(max_results)
        return JSONResponse({"playlists": playlists})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/youtube/playlist/add")
async def youtube_add_to_playlist(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    data = await request.json()
    playlist_id = data.get("playlist_id")
    video_id = data.get("video_id")
    if not playlist_id or not video_id:
        return JSONResponse({"error": "playlist_id and video_id required"}, status_code=400)
    try:
        result = await security_manager.youtube.add_to_playlist(playlist_id, video_id)
        return JSONResponse({"success": True, "result": result})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/youtube/playlist/{playlist_id}/videos")
async def youtube_playlist_videos(playlist_id: str, request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    max_results = int(request.query_params.get("max_results", 50))
    try:
        videos = await security_manager.youtube.get_playlist_videos(playlist_id, max_results)
        return JSONResponse({"videos": videos})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/youtube/search")
async def youtube_search(request: Request) -> JSONResponse:
    if not token_ok(request.headers.get("X-Jarvis-Token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    query = request.query_params.get("q")
    if not query:
        return JSONResponse({"error": "query parameter 'q' required"}, status_code=400)
    max_results = int(request.query_params.get("max_results", 25))
    order = request.query_params.get("order", "relevance")
    try:
        videos = await security_manager.youtube.search_videos(query, max_results, order)
        return JSONResponse({"videos": videos})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


def _now() -> float:
    import time
    return time.time()
