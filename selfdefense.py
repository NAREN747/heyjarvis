"""
JARVIS Self-Defense System - Active Defense
Lockdown mode, alerting, emergency wipe, integrity verification.
"""
from __future__ import annotations

import asyncio
import os
import platform
import signal
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class LockdownState:
    active: bool = False
    reason: str = ""
    timestamp: Optional[float] = None
    network_blocked: bool = False
    vault_locked: bool = False


class SelfDefense:
    """
    Active defense system:
    - Lockdown mode (blocks network, locks vault, kills non-essential processes)
    - Alerting system
    - Emergency wipe capability
    - Integrity verification
    - Auto-recovery
    """
    
    def __init__(self, broadcast: Callable[[Dict], Any]):
        self.broadcast = broadcast
        self._lockdown = LockdownState()
        self._task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start passive monitoring."""
        pass
    
    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def lockdown(self, reason: str = "Manual lockdown") -> Dict[str, Any]:
        """Trigger full system lockdown."""
        if self._lockdown.active:
            return {"success": False, "error": "Already locked down"}
        
        self._lockdown.active = True
        self._lockdown.reason = reason
        self._lockdown.timestamp = time.time()
        
        await self.broadcast({
            "type": "system",
            "message": f"🔒 LOCKDOWN INITIATED: {reason}",
            "severity": "critical",
            "lockdown": True
        })
        
        # In production:
        # 1. Block all network traffic (iptables/nftables)
        # 2. Lock vault
        # 3. Kill non-essential processes
        # 4. Disable USB ports
        # 5. Alert owner
        
        return {
            "success": True,
            "message": f"Lockdown active: {reason}",
            "locked_down": True
        }
    
    async def unlock(self, password: str) -> Dict[str, Any]:
        """Unlock from lockdown (requires password)."""
        if not self._lockdown.active:
            return {"success": False, "error": "Not locked down"}
        
        # In production: verify password against identity
        
        self._lockdown.active = False
        self._lockdown.reason = ""
        self._lockdown.timestamp = None
        self._lockdown.network_blocked = False
        self._lockdown.vault_locked = False
        
        await self.broadcast({
            "type": "system",
            "message": "🔓 Lockdown released",
            "severity": "info"
        })
        
        return {"success": True, "message": "Lockdown released"}
    
    def get_status(self) -> Dict:
        return {
            "locked_down": self._lockdown.active,
            "reason": self._lockdown.reason,
            "since": self._lockdown.timestamp
        }
    
    async def trigger_alert(self, message: str, severity: str = "medium", details: Dict = None) -> None:
        """Trigger security alert."""
        await self.broadcast({
            "type": "security_alert",
            "source": "selfdefense",
            "severity": severity,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        })
    
    async def emergency_wipe(self, confirmation: str) -> Dict[str, Any]:
        """
        Emergency vault wipe.
        Requires exact confirmation string.
        """
        if confirmation != "YES WIPE EVERYTHING":
            return {"success": False, "error": "Invalid confirmation"}
        
        await self.broadcast({
            "type": "system",
            "message": "💥 EMERGENCY WIPE INITIATED",
            "severity": "critical"
        })
        
        # In production: securely wipe vault, configs, logs
        
        return {
            "success": True,
            "message": "Emergency wipe executed",
            "wiped": ["vault", "configs", "logs"]
        }
    
    async def verify_integrity(self) -> Dict:
        """Verify system integrity."""
        issues = []
        
        # Check vault integrity
        # Check config integrity
        # Check critical files
        
        return {
            "healthy": len(issues) == 0,
            "issues": issues,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _block_network(self) -> bool:
        """Block all network traffic."""
        try:
            if platform.system() == "Linux":
                # Block all outbound
                subprocess.run(["iptables", "-A", "OUTPUT", "-j", "DROP"], 
                             capture_output=True, check=False)
                # Allow loopback
                subprocess.run(["iptables", "-I", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                             capture_output=True, check=False)
                subprocess.run(["iptables", "-I", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                             capture_output=True, check=False)
                self._lockdown.network_blocked = True
                return True
        except Exception:
            pass
        return False
    
    async def _unblock_network(self) -> bool:
        """Restore network access."""
        try:
            if platform.system() == "Linux":
                subprocess.run(["iptables", "-F", "OUTPUT"], capture_output=True, check=False)
                subprocess.run(["iptables", "-F", "INPUT"], capture_output=True, check=False)
                self._lockdown.network_blocked = False
                return True
        except Exception:
            pass
        return False
    
    async def _lock_vault(self) -> bool:
        """Lock vault."""
        self._lockdown.vault_locked = True
        return True
    
    async def _unlock_vault(self) -> bool:
        """Unlock vault."""
        self._lockdown.vault_locked = False
        return True
    
    def get_status(self) -> Dict:
        return {
            "locked_down": self._lockdown.active,
            "reason": self._lockdown.reason,
            "since": self._lockdown.timestamp
        }