# JARVIS — Local AI Assistant

A fully local, privacy-first AI assistant with voice I/O, self-modification capabilities, and security monitoring.

## Features

- **💬 Chat Interface** — WebSocket-based chat dashboard at `http://localhost:8000`
- **🎤 Voice I/O** — Wake word ("Hey Jarvis") + speech-to-text (faster-whisper) + text-to-speech (pyttsx3/ElevenLabs)
- **🧠 LLM Providers** — NVIDIA Nemotron (API), Ollama (local fallback), OpenAI-compatible endpoints
- **🔐 Security Suite** — Encrypted vault (AES-256-GCM), network monitor, intrusion detection, identity verification, self-defense lockdown
- **🔧 Self-Modification** — 8-stage safety pipeline: snapshot → AST scan → sandbox compile → behavioral test → fingerprint check → user confirm → apply → health check → auto-rollback
- **📺 YouTube Automation** — Upload, manage videos, playlists, thumbnails via YouTube Data API v3
- **🖥️ Terminal Access** — Secure command execution with audit logging

## Architecture

```
main.py (FastAPI + WebSocket)
├── brain.py          — LLM provider abstraction (NVIDIA, Ollama, OpenAI-compatible)
├── voice.py          — TTS: ElevenLabs → gTTS → pyttsx3 fallback chain
├── voice_input.py    — STT: sounddevice → openWakeWord → faster-whisper
├── security.py       — SecurityManager orchestrating all subsystems
│   ├── vault.py          — AES-256-GCM encrypted SQLite vault
│   ├── network.py        — Outbound connection monitor (psutil)
│   ├── intrusion.py      — File integrity, process anomalies, port scans
│   ├── identity.py       — Password + face verification
│   └── selfdefense.py    — Emergency lockdown, port blocking
├── self_modify.py    — 8-stage self-modification engine
├── youtube_automation.py — YouTube Data API v3 wrapper
└── terminal.py       — Safe command execution
```

## Quick Start

### Prerequisites

- Python 3.11+
- Linux (tested on Ubuntu/Debian/Arch)
- Microphone for voice input
- (Optional) NVIDIA GPU for faster Whisper inference
- (Optional) ElevenLabs API key for premium TTS

### Installation

```bash
# Clone and enter
git clone <your-repo-url>
cd jarvis

# Run installer (creates venv, installs deps, downloads models)
chmod +x install.sh
./install.sh
```

The installer will:
1. Create `.venv/` virtual environment
2. Install Python dependencies from `requirements.txt`
3. Install system packages (portaudio, espeak for TTS)
4. Download faster-whisper base model (~142MB)
5. Download openWakeWord hey_jarvis model
6. Generate `.jarvis_token` for authentication

### Configuration

Create `.env` file (optional):

```bash
# LLM Providers (at least one required)
NVIDIA_API_KEY=your_nvidia_key_here          # Nemotron 3 Ultra via NVIDIA API
OPENAI_API_KEY=your_openai_key_here          # OpenAI / compatible endpoint
OPENAI_BASE_URL=https://api.openai.com/v1    # Custom endpoint (e.g. local proxy)
OLLAMA_HOST=http://localhost:11434           # Local Ollama server

# Voice
ELEVENLABS_API_KEY=your_elevenlabs_key       # Premium TTS (optional)
WHISPER_MODEL=base                           # tiny/base/small/medium/large
WHISPER_DEVICE=cuda                          # cuda or cpu

# YouTube (optional)
# Place client_secrets.json in project root for YouTube API access
```

### Running

```bash
# Activate venv
source .venv/bin/activate

# Start server (foreground)
python main.py

# Or detached (logs to /tmp/opencode/jarvis.log)
python launch.py
```

Server starts at `http://localhost:8000`

Open the dashboard in your browser, enter the token from console output (or `.jarvis_token` file), and chat!

### Voice Usage

1. Say "Hey Jarvis" — wake word detected
2. Speak your request — transcribed via faster-whisper
3. JARVIS responds — spoken aloud via TTS

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/healthz` | ❌ | Health check |
| GET | `/` | ❌ | Dashboard UI |
| GET | `/api/token` | localhost only | Get auth token |
| WS | `/ws` | token in first frame | Chat WebSocket |
| GET | `/api/history` | ✅ | Message history |
| GET | `/api/providers` | ✅ | LLM provider status |
| GET | `/api/voice/providers` | ✅ | TTS provider chain |
| * | `/api/security/*` | ✅ | Security subsystem APIs |
| * | `/api/youtube/*` | ✅ | YouTube automation APIs |

### WebSocket Protocol

```json
// Client -> Server (first frame)
{"token": "your_token_here"}

// Server -> Client (auth response)
{"type": "auth", "ok": true}

// Client -> Server (chat)
{"text": "Hello JARVIS"}

// Server -> Client (message)
{"type": "message", "role": "assistant", "content": "...", "provider": "nemotron", "model": "nemotron-3-ultra", "ts": 1234567890.0}

// Server -> Client (state)
{"type": "state", "phase": "thinking|speaking|idle"}
```

## Security Features

### Vault (`/api/security/vault/*`)
- AES-256-GCM encryption with PBKDF2-HMAC-SHA256 (480k iterations)
- Per-entry unique nonces
- Integrity verification on every read
- Lock/unlock with password

### Network Monitor (`/api/security/network/*`)
- Tracks all outbound connections
- Blocks/unblocks IPs
- Port scan detection
- Baseline deviation alerts

### Intrusion Detection (`/api/security/intrusion/*`)
- File integrity monitoring (/etc/passwd, /etc/shadow, sshd_config, etc.)
- Suspicious process detection (nc, hydra, mimikatz, etc.)
- Brute force / privilege escalation heuristics
- Alert acknowledgment

### Identity (`/api/identity/*`)
- Password verification (Argon2-style PBKDF2)
- Face enrollment/verification (base64 images)
- Initial password setup

### Self-Defense (`/api/security/defense/*`)
- Emergency lockdown (block all network, kill processes)
- Password-protected unlock

## Self-Modification

JARVIS can modify its own source code safely:

1. **Request** — "Add a feature to track CPU usage"
2. **Propose** — LLM generates modified source
3. **Snapshot** — Current file backed up to `jarvis_snapshots/`
4. **AST Scan** — Blocks `eval`, `exec`, `os.system`, sockets, pickle, etc.
5. **Sandbox Compile** — Syntax + import test in isolated process
6. **Behavioral Test** — Runs quick scenario tests
7. **Fingerprint** — SHA256 prevents duplicate changes
8. **Confirm** — Shows diff, requires explicit "apply it"
9. **Apply + Restart** — Atomic write, `os.execv` restart
10. **Health Check** — 30s monitoring, auto-rollback on failure

Protected files (never modifiable):
- `self_modify.py`, `vault.py`, `identity.py`
- `network.py`, `intrusion.py`, `selfdefense.py`

## YouTube Automation

Requires `client_secrets.json` from Google Cloud Console (YouTube Data API v3 enabled).

```bash
# Authenticate (first run only)
curl -X POST http://localhost:8000/api/youtube/status \
  -H "X-Jarvis-Token: YOUR_TOKEN"
# Follow OAuth flow in browser
```

Then use endpoints:
- `POST /api/youtube/upload` — Upload video
- `GET /api/youtube/videos` — List your videos
- `POST /api/youtube/playlist/create` — Create playlist
- `POST /api/youtube/thumbnail` — Set custom thumbnail
- `GET /api/youtube/search?q=query` — Search videos

## Development

### Project Structure

```
jarvis/
├── main.py                 # FastAPI app, WebSocket, lifespan
├── brain.py                # LLM providers
├── voice.py                # TTS providers
├── voice_input.py          # Wake word + STT
├── security.py             # SecurityManager
├── vault.py                # Encrypted storage
├── network.py              # Network monitor
├── intrusion.py            # Intrusion detection
├── identity.py             # Identity verification
├── selfdefense.py          # Lockdown mechanism
├── self_modify.py          # Self-modification engine
├── youtube_automation.py   # YouTube API wrapper
├── terminal.py             # Command execution
├── launch.py               # Detached launcher
├── install.sh              # Installer
├── requirements.txt        # Python deps
├── frontend/               # Dashboard HTML/JS
│   └── index.html
└── .gitignore
```

### Running Tests

```bash
# Basic import test
python -c "import main; print('OK')"

# Test security subsystems
python -c "
from vault import Vault
from network import NetworkMonitor
from intrusion import IntrusionDetector
from identity import IdentityVerifier
from selfdefense import SelfDefense
print('All security modules OK')
"
```

### Adding a New LLM Provider

Edit `brain.py`:
1. Add provider class implementing `think()` method
2. Register in `PROVIDER_CHAIN` list
3. Add API key to `.env` and `provider_status()`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No module named uvicorn" | Run `./install.sh` or `pip install -r requirements.txt` |
| "Port 8000 in use" | `pkill -f uvicorn` or change port in `main.py` |
| Wake word not detected | Check microphone: `arecord -l`, install `portaudio19-dev` |
| Whisper slow on CPU | Set `WHISPER_MODEL=tiny` or use GPU with `WHISPER_DEVICE=cuda` |
| TTS not speaking | Install `espeak-ng` (pyttsx3 backend) |
| YouTube auth fails | Ensure `client_secrets.json` exists and API enabled |

## License

MIT — Use freely, modify responsibly.

## Security Note

This software includes powerful system-level capabilities (network monitoring, process control, self-modification, lockdown). Review code before running. Never expose the dashboard to untrusted networks without additional authentication layers.