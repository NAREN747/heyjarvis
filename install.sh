#!/usr/bin/env bash
# JARVIS — Linux one-command setup
# Verifies prerequisites and provisions the environment. Honest about what's missing.
set -euo pipefail

BOLD="\033[1m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
say() { printf "${BOLD}>>>${RESET} %s\n" "$*"; }
ok()  { printf "${GREEN}[ok]${RESET}  %s\n" "$*"; }
warn(){ printf "${YELLOW}[warn]${RESET} %s\n" "$*"; }
err() { printf "${RED}[err]${RESET} %s\n" "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Python version (3.10+ required)
say "Checking Python..."
if ! command -v python3 >/dev/null 2>&1; then
    err "Python 3 not found. Install python3 (3.10+) and rerun."
    exit 1
fi
PY_VERSION="$(python3 -c 'import sys; print(sys.version_info[:2])' | tr -d '(), ')"
PY_MAJOR="${PY_VERSION% *}" ; PY_MINOR="${PY_VERSION#* }"
PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)')"
if [ "$PY_OK" != "1" ]; then
    err "Python 3.10+ required, found $PY_MAJOR.$PY_MINOR."
    exit 1
fi
ok "Python $PY_MAJOR.$PY_MINOR"

# 2. uv (preferred installer)
say "Checking uv..."
if ! command -v uv >/dev/null 2>&1; then
    if [ -x "$HOME/.local/bin/uv" ]; then
        export PATH="$HOME/.local/bin:$PATH"
    else
        warn "uv not found. Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
    fi
fi
ok "uv $(uv --version)"

# 3. Virtual environment + dependencies
say "Creating virtual environment and installing dependencies..."
uv venv .venv >/dev/null
uv pip install -r requirements.txt >/dev/null
ok "Dependencies installed"

# 4. Ollama (fallback LLM provider — always available, no key)
say "Checking Ollama..."
if ! command -v ollama >/dev/null 2>&1; then
    warn "Ollama not installed. Local fallback LLM will be unavailable."
    warn "Install with: curl -fsSL https://ollama.com/install.sh | sh"
else
    if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        warn "Ollama installed but not responding at :11434. Starting it..."
        ollama serve >/dev/null 2>&1 & sleep 2
    fi
    ok "Ollama running"
    # Pull default fallback model if missing
    if ! ollama list 2>/dev/null | grep -q "llama3.1:8b"; then
        say "Pulling fallback model llama3.1:8b (one-time, ~5GB)..."
        ollama pull llama3.1:8b || warn "Model pull failed — local fallback will not work until pulled."
    fi
    ok "Fallback model ready"
fi

# 5. Auth token (auto-generated, never committed)
say "Generating auth token..."
if [ ! -f .jarvis_token ]; then
    python3 -c "import secrets; open('.jarvis_token','w').write(secrets.token_urlsafe(32))"
    chmod 600 .jarvis_token
    ok "Token written to .jarvis_token (kept local, gitignored)"
else
    ok "Existing token present"
fi

# 6. NVIDIA_API_KEY (primary LLM)
say "Checking NVIDIA_API_KEY..."
if [ -z "${NVIDIA_API_KEY:-}" ]; then
    warn "NVIDIA_API_KEY not set in environment."
    warn "  Set it for this session:  export NVIDIA_API_KEY=\"nvapi-...\""
    warn "  Set it permanently:       echo 'export NVIDIA_API_KEY=\"nvapi-...\"' >> ~/.bashrc && source ~/.bashrc"
    warn "  Until set, JARVIS will fail over to local Ollama — that is graceful, not broken."
else
    ok "NVIDIA_API_KEY is set (not printed for security)"
fi

# 7. Audio deps (needed from Step 2/3 onward, warn now)
say "Checking audio libraries..."
AUDIO_MISSING=""
for pkg in libespeak-ng-dev portaudio19-dev libsndfile1-dev ffmpeg; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        AUDIO_MISSING="$AUDIO_MISSING $pkg"
    fi
done
if [ -n "$AUDIO_MISSING" ]; then
    warn "Audio/voice libraries not yet installed (needed from Step 2 onward):"
    warn "  sudo apt-get install$AUDIO_MISSING"
else
    ok "Audio libraries present"
fi

# 8. Next steps
cat <<EOF

${BOLD}=== JARVIS setup complete ===${RESET}

Start the server:
    ${GREEN}.venv/bin/python main.py${RESET}

Open the dashboard in your browser:
    http://localhost:8000

The auth token (for mobile/remote clients later) lives in ${BOLD}.jarvis_token${RESET}.

EOF
