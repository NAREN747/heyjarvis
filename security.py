"""
JARVIS Privacy & Security - Step 8
Encrypted vault, network monitor, intrusion detection, identity verification, self-defense.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import secrets
import shutil
import sqlite3
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional, List

import psutil
import httpx

from brain import think, provider_status
from voice import speak, get_provider_status
from voice_input import start_voice_input, stop_voice_input
from self_modify import SelfModifier, start_health_check
from vault import Vault
from network import NetworkMonitor
from intrusion import IntrusionDetector
from identity import IdentityVerifier
from selfdefense import SelfDefense
from youtube_automation import YouTubeAutomation

# --- Security Manager --------------------------------------------------------

class SecurityManager:
    """
    Central coordinator for all privacy/security subsystems.
    Initializes vault, network monitor, intrusion detector, identity, self-defense.
    """
    
    def __init__(self, project_root: Path, broadcast: Callable[[dict], Any]):
        self.project_root = project_root
        self.broadcast = broadcast
        
        # Initialize subsystems
        self.vault = Vault(project_root / "vault")
        self.network = NetworkMonitor(broadcast)
        self.intrusion = IntrusionDetector(project_root, broadcast)
        self.identity = IdentityVerifier(project_root)
        self.selfdefense = SelfDefense(broadcast)
        self.youtube = YouTubeAutomation(
            client_secrets_path=project_root / "client_secrets.json",
            token_path=project_root / "youtube_token.json",
            broadcast=broadcast,
        )
        
        self._running = False
        self._monitor_tasks: list[asyncio.Task] = []
        self._voice_input_task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start all monitoring subsystems."""
        if self._running:
            return
        self._running = True
        
        # Start network monitor
        await self.network.start()
        
        # Start intrusion detector
        await self.intrusion.start()
        
        # Start voice input (wake word + STT) — runs in background
        print("[jarvis] Starting voice input...")
        async def on_voice_transcript(text: str):
            await self.process_user_message(text)
        await start_voice_input(on_voice_transcript)
        print("[jarvis] Voice input started")
        
        # Initialize YouTube automation (if credentials exist)
        if (self.project_root / "client_secrets.json").exists():
            print("[jarvis] Initializing YouTube automation...")
            await self.youtube.authenticate()
            print("[jarvis] YouTube automation ready")
        
        # Initialize self-modifier (placeholder for future implementation)
        # self.self_modifier = SelfModifier(project_root, self._restart_server, self.broadcast)
        # await start_health_check(project_root / "jarvis_snapshots", project_root, self.broadcast)
    
    async def stop(self) -> None:
        """Stop all monitoring subsystems."""
        if not self._running:
            return
        self._running = False
        
        # Stop voice input
        await stop_voice_input()
        
        for task in self._monitor_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        await self.network.stop()
        await self.intrusion.stop()
        await self.selfdefense.stop()
    
    async def process_user_message(self, text: str) -> None:
        """Process a user message through the brain."""
        if not text.strip():
            return
        
        await self.broadcast({"type": "message", "role": "user", "content": text, "ts": datetime.now().isoformat()})
        
        try:
            result = await think(text, http_client=httpx.AsyncClient())
            await self.broadcast({"type": "message", "role": "assistant", "content": result, "ts": datetime.now().isoformat()})
            await speak(result)
        except Exception as e:
            await self.broadcast({"type": "error", "message": str(e)})

    async def _periodic_security_audit(self) -> None:
        """Run security audit every 5 minutes."""
        while self._running:
            try:
                await asyncio.sleep(300)
                if not self._running:
                    break
                
                # Quick integrity check
                vault_ok = await self.vault.verify_integrity()
                net_ok = self.network.check_integrity()
                intrusion_ok = self.intrusion.check_integrity()
                
                if not (vault_ok and net_ok and intrusion_ok):
                    await self.selfdefense.trigger_alert(
                        "Security audit failed", 
                        severity="high",
                        details={"vault": vault_ok, "network": net_ok, "intrusion": intrusion_ok}
                    )
            except asyncio.CancelledError:
                break
            except Exception as e:
                await self.broadcast({
                    "type": "error",
                    "message": f"Security audit error: {e}"
                })
    
    async def _periodic_vault_integrity(self) -> None:
        """Verify vault integrity every hour."""
        while self._running:
            try:
                await asyncio.sleep(3600)
                if not self._running:
                    break
                await self.vault.verify_integrity(full=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                await self.broadcast({
                    "type": "error",
                    "message": f"Vault integrity check error: {e}"
                })

    # --- Vault Proxy Methods -------------------------------------------------

    async def _unlock_vault(self, password: str) -> bool:
        """Unlock the vault with the given password."""
        if self.vault.is_locked():
            return self.vault.unlock(password)
        return True

    async def store_secret(self, key: str, value: str, password: str) -> bool:
        """Store a secret in the vault."""
        if not await self._unlock_vault(password):
            return False
        try:
            return self.vault.store(key, value)
        finally:
            self.vault.lock()

    async def retrieve_secret(self, key: str, password: str) -> Optional[str]:
        """Retrieve a secret from the vault."""
        if not await self._unlock_vault(password):
            return None
        try:
            return self.vault.retrieve(key)
        finally:
            self.vault.lock()

    async def list_secrets(self, password: str) -> List[str]:
        """List all secret keys in the vault."""
        if not await self._unlock_vault(password):
            return []
        try:
            return self.vault.list_keys()
        finally:
            self.vault.lock()

    async def delete_secret(self, key: str, password: str) -> bool:
        """Delete a secret from the vault."""
        if not await self._unlock_vault(password):
            return False
        try:
            return self.vault.delete(key)
        finally:
            self.vault.lock()

    async def export_vault(self, password: str) -> bytes:
        """Export the entire vault encrypted with a password."""
        if not await self._unlock_vault(password):
            return b""
        try:
            return self.vault.export_encrypted(password)
        finally:
            self.vault.lock()

    async def import_vault(self, data: bytes, password: str) -> bool:
        """Import a vault from an encrypted export."""
        if not await self._unlock_vault(password):
            return False
        try:
            return self.vault.import_encrypted(data, password)
        finally:
            self.vault.lock()

    async def change_vault_password(self, old_password: str, new_password: str) -> bool:
        """Change the vault password and re-encrypt all data."""
        if not await self._unlock_vault(old_password):
            return False
        try:
            return self.vault.rekey(old_password, new_password)
        finally:
            self.vault.lock()

    def get_status(self) -> dict:
        """Get overall security system status."""
        return {
            "running": self._running,
            "vault": {
                "locked": self.vault.is_locked(),
            },
            "network": self.network.get_status() if self._running else {},
            "intrusion": self.intrusion.get_status() if self._running else {},
            "identity": self.identity.get_status(),
            "selfdefense": self.selfdefense.get_status() if self._running else {},
        }


# --- Re-export for main.py ---
__all__ = [
    "Vault", "NetworkMonitor", "IntrusionDetector", 
    "IdentityVerifier", "SelfDefense",
    "SecurityManager",
]