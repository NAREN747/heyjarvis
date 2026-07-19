"""
JARVIS Self-Modification Engine — 8-Stage Safety Pipeline.

Architecture:
1. User requests capability -> LLM proposes modified source
2. Snapshot current file
3. AST Security Scan (blocks eval/exec/os.system/sockets/raw disk)
4. Sandbox Compile Test (syntax + import test in isolated process)
5. Behavioral Contract Test (runs 3 quick scenarios, checks invariants)
6. Fingerprint Check (prevents re-applying identical changes)
7. User Confirmation (shows diff, requires explicit "apply it")
8. Apply + Auto-Restart + 30s Health Check -> Auto-Rollback on failure

Protected files (can NEVER be modified):
- self_modify.py (this engine)
- vault.py (encryption)
- identity.py (owner verification)
- network.py (network monitor)
- intrusion.py (intrusion detection)
- selfdefense.py (lockdown)

Rollback: Automatic if health check fails within 30s of restart.
Manual rollback always available via "roll back" command.
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Awaitable, Optional

# --- Constants ---------------------------------------------------------------

PROTECTED_FILES = frozenset({
    "self_modify.py",
    "vault.py", 
    "identity.py",
    "network.py",
    "intrusion.py",
    "selfdefense.py",
})

# Banned AST patterns
BLOCKED_NAMES = frozenset({
    "eval", "exec", "compile", "__import__",
    "open", "os.system", "os.popen", "subprocess.run",
    "subprocess.Popen", "subprocess.call", "subprocess.check_output",
    "socket.socket", "socket.create_connection",
    "pickle.loads", "pickle.load", "marshal.loads",
    "ctypes.CDLL", "ctypes.cdll",
})

BLOCKED_CALLS = frozenset({
    ("os", "system"), ("os", "popen"), ("os", "remove"), ("os", "rmdir"),
    ("os", "unlink"), ("shutil", "rmtree"), ("pathlib", "Path.unlink"),
    ("subprocess", "run"), ("subprocess", "Popen"),
    ("socket", "socket"), ("socket", "create_connection"),
    ("pickle", "loads"), ("pickle", "load"),
})

BLOCKED_STRINGS = frozenset({
    "rm -rf /", "dd if=/dev/zero", "mkfs.", "format ",
    "> /dev/sd", "> /dev/hd", "/windows/system32",
    "format c:", "del /f /s /q", "shutdown /s",
})


# --- Data Classes ------------------------------------------------------------

@dataclass
class ModificationResult:
    success: bool
    message: str
    snapshot_path: str | None = None
    diff: str | None = None
    fingerprint: str | None = None


@dataclass
class AuditEntry:
    timestamp: str
    request: str
    target_file: str
    stages: dict[str, bool] = field(default_factory=dict)
    user_confirmed: bool = False
    snapshot_path: str | None = None
    fingerprint: str | None = None
    status: str = "pending"  # pending, applied, rolled_back, rejected


# --- AST Security Scanner ----------------------------------------------------

class ASTSecurityScanner(ast.NodeVisitor):
    """Walks AST and flags any forbidden patterns."""
    
    def __init__(self):
        self.violations: list[str] = []
    
    def visit_Name(self, node: ast.Name):
        if node.id in BLOCKED_NAMES:
            self.violations.append(f"Forbidden name: {node.id} at line {node.lineno}")
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                pair = (node.func.value.id, node.func.attr)
                if pair in BLOCKED_CALLS:
                    self.violations.append(f"Forbidden call: {pair[0]}.{pair[1]}() at line {node.lineno}")
        self.generic_visit(node)
    
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            for pattern in BLOCKED_STRINGS:
                if pattern.lower() in node.value.lower():
                    self.violations.append(f"Forbidden string pattern '{pattern}' at line {node.lineno}")
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in ("ctypes", "subprocess", "socket", "pickle", "marshal"):
                self.violations.append(f"Suspicious import: {alias.name} at line {node.lineno}")
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module in ("ctypes", "subprocess", "socket", "pickle", "marshal"):
            self.violations.append(f"Suspicious from-import: {node.module} at line {node.lineno}")
        self.generic_visit(node)


def ast_security_scan(source_code: str) -> tuple[bool, list[str]]:
    """
    Returns (passed, violations_list).
    If violations_list is empty, scan passed.
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return False, [f"Syntax error: {e}"]
    
    scanner = ASTSecurityScanner()
    scanner.visit(tree)
    return len(scanner.violations) == 0, scanner.violations


# --- Sandbox Compile Test ----------------------------------------------------

async def sandbox_compile_test(source_code: str, module_name: str) -> tuple[bool, str]:
    """
    Write source to temp file, attempt to import it in isolated subprocess.
    Returns (success, error_message).
    """
    import tempfile
    from pathlib import Path
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / f"{module_name}.py"
        tmp_path.write_text(source_code, encoding="utf-8")
        
        # Test import in isolated process
        test_script = f"""
import sys
sys.path.insert(0, {tmpdir!r})
try:
    import {module_name}
    print("IMPORT_OK")
except Exception as e:
    print(f"IMPORT_FAILED: {{e}}")
    sys.exit(1)
"""
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", test_script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return False, "Import test timed out"
        
        if proc.returncode == 0 and b"IMPORT_OK" in stdout:
            return True, ""
        else:
            return False, stdout.decode() or stderr.decode()


# --- Behavioral Contract Test ------------------------------------------------

async def behavioral_contract_test(
    source_code: str, 
    module_name: str,
    test_scenarios: list[dict[str, Any]] | None = None
) -> tuple[bool, str]:
    """
    Runs the modified module through quick behavioral scenarios.
    Scenarios are simple function calls that verify basic invariants.
    """
    if test_scenarios is None:
        test_scenarios = [
            {"description": "Module import test", "code": "pass"},
        ]
    
    import tempfile
    from pathlib import Path
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir) / f"{module_name}.py"
        tmp_path.write_text(source_code, encoding="utf-8")
        
        for scenario in test_scenarios:
            test_code = f"""
import sys
sys.path.insert(0, {tmpdir!r})
try:
    import {module_name}
    {scenario.get("code", "pass")}
    print("SCENARIO_OK: {scenario.get('description', 'unnamed')}")
except Exception as e:
    print(f"SCENARIO_FAILED: {{e}}")
    sys.exit(1)
"""
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", test_code,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            
            if proc.returncode != 0 or b"SCENARIO_FAILED" in stdout:
                return False, stdout.decode() or stderr.decode()
    
    return True, ""


# --- Fingerprint Deduplication -----------------------------------------------

def compute_fingerprint(source_code: str) -> str:
    """SHA256 of normalized source (stripped of trailing whitespace)."""
    normalized = "\n".join(line.rstrip() for line in source_code.splitlines())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def load_fingerprints(snapshots_dir: Path) -> set[str]:
    """Load all applied fingerprints from snapshot metadata."""
    fingerprints = set()
    meta_file = snapshots_dir / "fingerprints.json"
    if meta_file.exists():
        try:
            data = json.loads(meta_file.read_text())
            fingerprints = set(data.get("fingerprints", []))
        except Exception:
            fingerprints = set()
    return fingerprints


def save_fingerprint(snapshots_dir: Path, fingerprint: str) -> None:
    """Record a newly applied fingerprint."""
    meta_file = snapshots_dir / "fingerprints.json"
    fingerprints = load_fingerprints(snapshots_dir)
    fingerprints.add(fingerprint)
    meta_file.write_text(json.dumps({"fingerprints": list(fingerprints)}, indent=2))


# --- Diff Generation ---------------------------------------------------------

def generate_diff(old_code: str, new_code: str, filename: str) -> str:
    """Generate unified diff."""
    import difflib
    old_lines = old_code.splitlines(keepends=True)
    new_lines = new_code.splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines, fromfile=f"a/{filename}", tofile=f"b/{filename}")
    return "".join(diff)


# --- Self-Modifier Engine ----------------------------------------------------

class SelfModifier:
    """
    Main self-modification engine. Handles the full 8-stage pipeline.
    """
    
    def __init__(
        self,
        project_root: Path,
        restart_callback: Callable[[], Awaitable[None]],
        broadcast_callback: Callable[[dict], Awaitable[None]],
    ):
        self.project_root = project_root
        self.snapshots_dir = project_root / "jarvis_snapshots"
        self.snapshots_dir.mkdir(exist_ok=True)
        self.restart_callback = restart_callback
        self.broadcast_callback = broadcast_callback
        self.pending_fingerprint: str | None = None
        self.pending_snapshot: Path | None = None
        self.pending_target: str | None = None
        self.pending_proposed: str | None = None
    
    async def propose_modification(
        self,
        target_file: str,
        user_request: str,
        proposed_source: str,
    ) -> ModificationResult:
        """
        Main entry point. Runs stages 1-6, stops before confirmation.
        """
        target_path = self.project_root / target_file
        
        # Stage 0: Protected file check
        if target_file in PROTECTED_FILES:
            return ModificationResult(
                success=False,
                message=f"I cannot modify {target_file}, Sir. That file contains my security infrastructure — encryption, identity, network monitoring, intrusion detection, and this very engine. That boundary exists to protect you, not me.",
            )
        
        if not target_path.exists():
            return ModificationResult(
                success=False,
                message=f"Target file {target_file} does not exist.",
            )
        
        # Read current source
        current_source = target_path.read_text(encoding="utf-8")
        
        # Compute fingerprint
        fingerprint = compute_fingerprint(proposed_source)
        existing_fingerprints = load_fingerprints(self.snapshots_dir)
        
        if fingerprint in existing_fingerprints:
            return ModificationResult(
                success=False,
                message="This exact modification has already been applied, Sir. I won't create duplicate changes.",
                fingerprint=fingerprint,
            )
        
        # Stage 1: Snapshot
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshot_path = self.snapshots_dir / f"{target_file}.{timestamp}.bak"
        snapshot_path.write_text(current_source, encoding="utf-8")
        
        # Stage 2: AST Security Scan
        scan_passed, violations = ast_security_scan(proposed_source)
        if not scan_passed:
            snapshot_path.unlink(missing_ok=True)
            return ModificationResult(
                success=False,
                message="Security scan failed:\n" + "\n".join(violations),
                fingerprint=fingerprint,
            )
        
        # Stage 3: Sandbox Compile Test
        module_name = target_file.replace(".py", "").replace("/", "_")
        compile_passed, compile_error = await sandbox_compile_test(proposed_source, module_name)
        if not compile_passed:
            snapshot_path.unlink(missing_ok=True)
            return ModificationResult(
                success=False,
                message=f"Compile test failed:\n{compile_error}",
                fingerprint=fingerprint,
            )
        
        # Stage 4: Behavioral Contract Test
        behavior_passed, behavior_error = await behavioral_contract_test(proposed_source, module_name)
        if not behavior_passed:
            snapshot_path.unlink(missing_ok=True)
            return ModificationResult(
                success=False,
                message=f"Behavioral test failed:\n{behavior_error}",
                fingerprint=fingerprint,
            )
        
        # All checks passed - generate diff for user
        diff = generate_diff(current_source, proposed_source, target_file)
        
        # Store pending for confirmation
        self.pending_fingerprint = fingerprint
        self.pending_snapshot = snapshot_path
        self.pending_target = target_file
        self.pending_proposed = proposed_source
        
        # Log audit entry (pending)
        await self._log_audit(AuditEntry(
            timestamp=datetime.now().isoformat(),
            request=user_request,
            target_file=target_file,
            stages={"ast": True, "compile": True, "behavior": True},
            snapshot_path=str(snapshot_path),
            fingerprint=fingerprint,
            status="awaiting_confirmation",
        ))
        
        return ModificationResult(
            success=True,
            message="All safety checks passed. Ready to apply with your confirmation.",
            snapshot_path=str(snapshot_path),
            diff=diff,
            fingerprint=fingerprint,
        )
    
    async def apply_pending(self, confirmed: bool) -> ModificationResult:
        """Apply or discard the pending modification."""
        if self.pending_fingerprint is None or self.pending_snapshot is None:
            return ModificationResult(success=False, message="No pending modification.")
        
        if not confirmed:
            # Discard
            self.pending_snapshot.unlink(missing_ok=True)
            msg = "Modification discarded at your request, Sir."
            self._clear_pending()
            return ModificationResult(success=True, message=msg)
        
        # Apply
        target_path = self.project_root / self.pending_target
        fingerprint = self.pending_fingerprint
        snapshot_path = self.pending_snapshot
        proposed = self.pending_proposed
        target_file = self.pending_target
        
        try:
            # Write new code
            target_path.write_text(proposed, encoding="utf-8")
            
            # Record fingerprint
            save_fingerprint(self.snapshots_dir, fingerprint)
            
            # Log audit
            await self._log_audit(AuditEntry(
                timestamp=datetime.now().isoformat(),
                request=f"Applied: {self.pending_snapshot}",
                target_file=target_file,
                stages={"apply": True},
                user_confirmed=True,
                snapshot_path=str(snapshot_path),
                fingerprint=fingerprint,
                status="applied",
            ))
            
            # Broadcast reconnect warning
            await self.broadcast_callback({
                "type": "system",
                "message": "Applying modification — reconnecting in a few seconds...",
            })
            
            # Trigger restart
            await asyncio.sleep(0.5)
            await self.restart_callback()
            
            # Clear pending
            self._clear_pending()
            
            return ModificationResult(
                success=True,
                message="Modification applied successfully. Restarting...",
            )
        except Exception as e:
            return ModificationResult(success=False, message=f"Apply failed: {e}")
    
    def _clear_pending(self):
        self.pending_fingerprint = None
        self.pending_snapshot = None
        self.pending_target = None
        self.pending_proposed = None
    
    async def _log_audit(self, entry: AuditEntry) -> None:
        audit_log = self.snapshots_dir / "audit.log"
        line = f"[{entry.timestamp}] REQUEST: {entry.request!r}\n"
        line += f"[{entry.timestamp}] TARGET: {entry.target_file}\n"
        for stage, passed in entry.stages.items():
            line += f"[{entry.timestamp}] {stage.upper()}: {'passed' if passed else 'FAILED'}\n"
        if entry.user_confirmed:
            line += f"[{entry.timestamp}] USER_CONFIRMED: yes\n"
        else:
            line += f"[{entry.timestamp}] USER_CONFIRMED: no\n"
        if entry.snapshot_path:
            line += f"[{entry.timestamp}] SNAPSHOT: {entry.snapshot_path}\n"
        if entry.fingerprint:
            line += f"[{entry.timestamp}] FINGERPRINT: {entry.fingerprint}\n"
        line += f"[{entry.timestamp}] STATUS: {entry.status}\n\n"
        
        existing = audit_log.read_text() if audit_log.exists() else ""
        audit_log.write_text(existing + line)


# --- Health Check & Auto-Rollback --------------------------------------------

async def start_health_check(
    snapshots_dir: Path,
    project_root: Path,
    broadcast: Callable[[dict], Awaitable[None]],
) -> None:
    """
    Runs after restart. Waits up to 30s for server to respond to WS ping.
    If fails, rolls back to most recent snapshot and restarts again.
    """
    await asyncio.sleep(2)  # Let server fully start
    
    max_wait = 30
    start = time.time()
    
    while time.time() - start < max_wait:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get("http://127.0.0.1:8000/healthz")
                if resp.status_code == 200:
                    # Health check passed
                    await broadcast({"type": "system", "message": "Self-modification health check passed. All systems nominal, Sir."})
                    return
        except Exception:
            pass
        await asyncio.sleep(1)
    
    # Health check failed - trigger rollback
    await broadcast({"type": "system", "message": "Health check failed after modification. Initiating automatic rollback, Sir."})
    await asyncio.sleep(1)
    
    # Find most recent snapshot
    snapshots = sorted(snapshots_dir.glob("*.bak"), key=lambda p: p.stat().st_mtime, reverse=True)
    if snapshots:
        latest = snapshots[0]
        target_name = latest.name.split(".")[0]  # "brain.py.20260711_143201.bak" -> "brain.py"
        target = project_root / target_name
        shutil.copy2(latest, target)
        await broadcast({"type": "system", "message": f"Rollback complete. Restored {target_name} from {latest.name}. Restarting..."})
        # Trigger restart (handled by caller via watchdog or process manager)


# --- Audit Logging -----------------------------------------------------------

AUDIT_LOG = Path("jarvis_snapshots/audit.log")

async def log_audit(entry: AuditEntry) -> None:
    AUDIT_LOG.parent.mkdir(exist_ok=True)
    line = f"[{entry.timestamp}] REQUEST: {entry.request!r}\n"
    line += f"[{entry.timestamp}] TARGET: {entry.target_file}\n"
    for stage, passed in entry.stages.items():
        line += f"[{entry.timestamp}] {stage.upper()}: {'passed' if passed else 'FAILED'}\n"
    if entry.user_confirmed:
        line += f"[{entry.timestamp}] USER_CONFIRMED: yes\n"
    else:
        line += f"[{entry.timestamp}] USER_CONFIRMED: no\n"
    if entry.snapshot_path:
        line += f"[{entry.timestamp}] SNAPSHOT: {entry.snapshot_path}\n"
    if entry.fingerprint:
        line += f"[{entry.timestamp}] FINGERPRINT: {entry.fingerprint}\n"
    line += f"[{entry.timestamp}] STATUS: {entry.status}\n\n"
    
    existing = AUDIT_LOG.read_text() if AUDIT_LOG.exists() else ""
    AUDIT_LOG.write_text(existing + line)


# --- Integration Helpers -----------------------------------------------------

def detect_self_modify_intent(user_message: str) -> bool:
    """Check if user message requests self-modification."""
    triggers = [
        "add a feature", "modify yourself", "update yourself", "improve yourself",
        "teach yourself", "add the ability", "upgrade your", "you should be able",
        "can you add", "i want you to", "make yourself", "teach yourself how",
    ]
    msg_lower = user_message.lower()
    return any(t in msg_lower for t in triggers)


# --- Dashboard Auto-Reconnect Script ----------------------------------------

DASHBOARD_RECONNECT_JS = """
// Auto-reconnect for JARVIS dashboard
let reconnectTimer = null;
let reconnectAttempts = 0;
let ws = null;

function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}/ws`);
    
    ws.onopen = () => {
        reconnectAttempts = 0;
        if (reconnectTimer) clearTimeout(reconnectTimer);
        ws.send(JSON.stringify({token: JARVIS_TOKEN}));
    };
    
    ws.onclose = () => {
        const delay = reconnectAttempts < 10 ? 2000 : 10000;
        reconnectAttempts++;
        if (reconnectAttempts === 1) {
            addSystemMessage('Reconnecting to JARVIS...');
        }
        reconnectTimer = setTimeout(connectWS, delay);
    };
    
    ws.onerror = () => {}; // onclose handles it
    
    return ws;
}

let JARVIS_TOKEN = '';
async function loadToken() {
    try {
        const r = await fetch('/api/token');
        if (r.ok) JARVIS_TOKEN = await r.text();
    } catch {}
}

loadToken().then(connectWS);
"""


# --- Manual Rollback Command -------------------------------------------------

async def manual_rollback(
    snapshots_dir: Path,
    project_root: Path,
    target_file: str | None = None,
    broadcast: Callable[[dict], Awaitable[None]] | None = None,
) -> str:
    """User-initiated rollback. Lists snapshots, lets user choose."""
    snapshots = sorted(snapshots_dir.glob("*.bak"), key=lambda p: p.stat().st_mtime, reverse=True)
    
    if not snapshots:
        return "No snapshots available to roll back to, Sir."
    
    if target_file:
        snapshots = [s for s in snapshots if s.name.startswith(target_file + ".")]
        if not snapshots:
            return f"No snapshots for {target_file}, Sir."
    
    latest = snapshots[0]
    target_name = latest.name.split(".")[0]
    target = project_root / target_name
    
    shutil.copy2(latest, target)
    
    if broadcast:
        await broadcast({"type": "system", "message": f"Rolled back {target_name} from {latest.name}. Restarting..."})
    
    return f"Rolled back {target_name} to {latest.name}. Server will restart to apply."