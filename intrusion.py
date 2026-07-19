"""
JARVIS Intrusion Detector - System Integrity Monitoring
Monitors for signs of compromise: file changes, process anomalies, port scans, brute force, privilege escalation.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import platform
import psutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from pathlib import Path


@dataclass
class Alert:
    id: str
    timestamp: str
    source: str
    severity: str  # info, warning, high, critical
    message: str
    acknowledged: bool = False


class IntrusionDetector:
    """
    Monitors for signs of system compromise:
    - File system changes (critical system files)
    - Unexpected process execution
    - Port scanning activity
    - Brute force attempts
    - Privilege escalation attempts
    - Suspicious network activity
    """
    
    def __init__(self, project_root: Path, broadcast: Callable[[Dict], Any]):
        self.project_root = project_root
        self.broadcast = broadcast
        self._running = False
        self._alerts: List[Dict] = []
        self._file_hashes: Dict[str, str] = {}
        self._process_baseline: Set[int] = set()
        self._task: Optional[asyncio.Task] = None
        self._watched_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/hosts",
            "/etc/crontab", "/etc/fstab",
        ]
        self._suspicious_processes = {
            "nc", "netcat", "ncat", "socat",
            "hydra", "medusa", "john", "hashcat",
            "mimikatz", "meterpreter", "powershell.exe",
        }
        self._task: Optional[asyncio.Task] = None
        self._alert_id = 0
    
    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._build_baseline()
        self._task = asyncio.create_task(self._monitor_loop())
    
    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    def _build_baseline(self) -> None:
        """Build baseline of file hashes and running processes."""
        for f in self._watched_files:
            if os.path.exists(f):
                self._file_hashes[f] = self._hash_file(f)
        
        for proc in psutil.process_iter(['pid']):
            try:
                self._process_baseline.add(proc.info['pid'])
            except Exception:
                pass
    
    async def _monitor_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(5)
                await self._check_file_integrity()
                await self._check_processes()
                await self._check_network_anomalies()
                await self._check_log_anomalies()
            except asyncio.CancelledError:
                break
            except Exception as e:
                await self._alert(f"Intrusion detector error: {e}")
    
    async def _check_file_integrity(self) -> None:
        for f in self._watched_files:
            if not os.path.exists(f):
                if f in self._file_hashes:
                    await self._alert(f"Critical file deleted: {f}", "critical")
                    del self._file_hashes[f]
                continue
            
            current_hash = self._hash_file(f)
            if f in self._file_hashes and self._file_hashes[f] != current_hash:
                await self._alert(f"Critical file modified: {f}", "critical")
                self._file_hashes[f] = current_hash
            elif f not in self._file_hashes:
                self._file_hashes[f] = self._hash_file(f)
    
    async def _check_processes(self) -> None:
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                user = proc.info['username']
                cmdline = proc.info['cmdline']
                current_pids.add(pid)
                
                if pid not in self._process_baseline:
                    await self._check_process_suspicion(pid, name, user, cmdline)
                
                if name and name.lower() in self._suspicious_processes:
                    await self._alert(f"Suspicious process running: {name} (PID: {pid})", "high")
                
            except Exception:
                pass
        
        terminated = self._process_baseline - current_pids
        for pid in terminated:
            await self._alert(f"Process terminated: PID {pid}", "info")
        
        self._process_baseline = current_pids
    
    async def _check_process_suspicion(self, pid: int, name: str, user: str, cmdline: Optional[List[str]]) -> None:
        reasons = []
        
        if user == "root" and os.geteuid() != 0:
            reasons.append("root process spawned by non-root user")
        
        if cmdline:
            cmd = " ".join(cmdline)
            suspicious_patterns = [
                "base64 -d", "curl | sh", "wget | sh",
                "/dev/tcp", "/dev/udp",
                "chmod +s", "chmod 777",
                "echo", "base64", "perl -e", "python -c",
            ]
            for pattern in suspicious_patterns:
                if pattern.lower() in cmd.lower():
                    await self._alert(f"Suspicious command: {cmd[:200]}", "high")
        
        if reasons:
            await self._alert(
                f"Suspicious process: {name} (PID: {pid}, User: {user}) - {', '.join(reasons)}",
                "warning"
            )
    
    async def _check_network_anomalies(self) -> None:
        try:
            connections = psutil.net_connections(kind='inet')
            ip_port_counts = {}
            
            for conn in connections:
                if conn.raddr and conn.status == 'ESTABLISHED':
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    if ip not in ip_port_counts:
                        ip_port_counts[ip] = set()
                    ip_port_counts[ip].add(port)
            
            for ip, ports in ip_port_counts.items():
                if len(ports) > 30:
                    await self._alert(f"Possible port scan from {ip} ({len(ports)} ports)", "high")
            
            port_counts = {}
            for conn in connections:
                if conn.raddr:
                    key = (conn.raddr.ip, conn.raddr.port)
                    port_counts[key] = port_counts.get(key, 0) + 1
            
            for (ip, port), count in port_counts.items():
                if count > 50 and port in (22, 3389, 445, 1433, 3306, 5432):
                    await self._alert(f"Possible brute force on {ip}:{port} ({count} connections)", "high")
        
        except Exception:
            pass
    
    async def _check_log_anomalies(self) -> None:
        if platform.system() != "Linux":
            return
        
        try:
            result = subprocess.run(
                ["grep", "Failed password", "/var/log/auth.log"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout:
                failed_count = len(result.stdout.strip().split('\n'))
                if failed_count > 20:
                    await self._alert(f"High failed login count: {failed_count}", "warning")
        except Exception:
            pass
    
    def _hash_file(self, filepath: str) -> str:
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""
    
    async def _alert(self, message: str, severity: str = "info") -> None:
        self._alert_id += 1
        alert = {
            "id": f"ALERT-{self._alert_id:04d}",
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "message": message,
            "acknowledged": False
        }
        self._alerts.append(alert)
        if len(self._alerts) > 500:
            self._alerts = self._alerts[-500:]
        
        await self.broadcast({
            "type": "security_alert",
            "source": "intrusion",
            "severity": severity,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "alert_id": alert["id"]
        })
    
    def get_status(self) -> Dict:
        return {
            "running": self._running,
            "alerts_count": len(self._alerts),
            "unacknowledged": sum(1 for a in self._alerts if not a["acknowledged"]),
            "watched_files": len(self._file_hashes),
            "process_baseline": len(self._process_baseline)
        }
    
    def get_recent_alerts(self, limit: int = 20) -> List[Dict]:
        return self._alerts[-limit:]
    
    def acknowledge(self, alert_id: str) -> bool:
        for a in self._alerts:
            if a["id"] == alert_id:
                a["acknowledged"] = True
                return True
        return False
    
    def check_integrity(self) -> bool:
        return self._running