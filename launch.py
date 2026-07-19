"""
JARVIS launcher — fully detaches the server from the launching shell so the
opencode bash tool can return immediately. The trick: close the inherited
stderr/stdout pipe (fd 3+) in BOTH the first and second fork children, before
the parent's sys.exit(0) triggers the bash tool's wait-on-pipe.

Usage:  python3 launch.py
Your server then runs detached; PID in /tmp/jarvis.pid.
"""
import os, sys, signal, time

LOGFILE = "/tmp/opencode/jarvis.log"
PIDFILE = "/tmp/opencode/jarvis.pid"
WORKDIR = "/home/naren/Downloads/jarvis"
VENV_PY = "/home/naren/Downloads/jarvis/.venv/bin/python"

# stop any prior instance — try the recorded uvicorn pid first, then sweep.
def _stop_old():
    # recorded uvicorn pid (if any)
    try:
        with open(PIDFILE) as f:
            old = int(f.read().strip())
        os.kill(old, signal.SIGTERM)
        time.sleep(1.5)
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        pass
    # safety sweep — anything still bound to our port
    import subprocess
    try:
        subprocess.run(
            ["pkill", "-f", "uvicorn main:app"],
            check=False, capture_output=True, timeout=5,
        )
        time.sleep(0.5)
    except Exception:
        pass

_stop_old()

# Writable log fd opened in the parent so children just dup to it.
logfd = os.open(LOGFILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)

def detach_and_exec() -> None:
    """Classic double-fork with full fd closing so no pipe leaks to the shell."""
    if os.fork() != 0:
        return  # parent returns, bash tool can exit
    # first child
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    # second child — reparented to init
    os.chdir(WORKDIR)
    sys.stderr.write(f"[jarvis] second child pid={os.getpid()}, about to closerange\n"); sys.stderr.flush()
    # Close every fd the parent gave us — this is what releases the bash tool's
    # pipe so it can return. After this, std fds are gone too.
    try:
        os.closerange(0, 4096)
    except OSError:
        pass
    # Reopen everything fresh: stdin from /dev/null, stdout/stderr to the log.
    os.open("/dev/null", os.O_RDONLY)                          # fd 0
    logfd2 = os.open(LOGFILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(logfd2, 1)
    os.dup2(logfd2, 2)
    os.close(logfd2)
    os.write(2, f"[jarvis] fds reopened, about to write pidfile\n".encode())
    # write pidfile placeholder — overwritten below with the uvicorn pid
    try:
        with open(PIDFILE, "w") as f:
            f.write("0")
    except Exception as e:
        os.write(2, f"pidfile-write-failed: {e}\n".encode())
    os.write(2, f"[jarvis] about to spawn uvicorn\n".encode())
    env = dict(os.environ)
    env["PATH"] = f"{WORKDIR}/.venv/bin:{env.get('PATH','/usr/bin:/bin')}"
    # Use subprocess.Popen with the inherited (re-jiggered) std fds so uvicorn
    # starts in a fresh Python process — avoids the logging-formatter corruption
    # that bit us when execv-ing into a forked interpreter that inherited a
    # half-initialised logging.config from the parent.
    import subprocess
    try:
        proc = subprocess.Popen(
            [VENV_PY, "-m", "uvicorn", "main:app",
             "--host", "127.0.0.1", "--port", "8000"],
            cwd=WORKDIR, env=env,
            stdin=subprocess.DEVNULL,
            stdout=open(LOGFILE, "ab"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception as e:
        os.write(2, f"spawn-failed: {e}\n".encode())
        os._exit(1)
    # Record the actual uvicorn pid for clean shutdown later.
    try:
        with open(PIDFILE, "w") as f:
            f.write(str(proc.pid))
    except Exception:
        pass
    # The launched subprocess is reparented to init by start_new_session; this
    # second child can exit cleanly now.
    os._exit(0)

detach_and_exec()
# Give the detached process a moment to actually exec, then close our log fd
# (children have their own dup of it).
time.sleep(0.3)
os.close(logfd)
print("launched; pidfile at", PIDFILE)
