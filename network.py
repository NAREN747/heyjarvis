"""
JARVIS Network Monitor - Outbound Connection Tracking
Monitors all outbound connections, tracks processes, alerts on anomalies.
"""
from __future__ import annotations

import asyncio
import platform
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import psutil


@dataclass
class Connection:
    timestamp: datetime
    pid: int
    process_name: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str  # TCP/UDP
    state: str


class NetworkMonitor:
    """
    Monitors outbound network connections.
    Tracks process, destination, protocol.
    Alerts on: new connections, blocked IPs, port scans, unusual traffic.
    """
    
    def __init__(self, broadcast: Callable[[Dict], Any]):
        self.broadcast = broadcast
        self._running = False
        self._connections: List[Dict] = []
        self._blocked_ips: Set[str] = set()
        self._baseline: Set[tuple] = set()
        self._ip_port_counts: Dict[str, Set[int]] = defaultdict(set)
        self._ip_connection_times: Dict[str, List[float]] = defaultdict(list)
        self._task: Optional[asyncio.Task] = None
        self._scan_threshold_ports = 20  # ports from same IP = port scan
        self._scan_threshold_time = 60  # seconds
        self._max_connections = 1000
    
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
        """Establish baseline of normal connections."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    self._baseline.add((
                        conn.pid,
                        conn.raddr.ip,
                        conn.raddr.port
                    ))
        except Exception:
            pass
    
    async def _monitor_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(2)
                await self._scan_connections()
                self._cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                await self._alert(f"Network monitor error: {e}")
    
    async def _scan_connections(self) -> None:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue
            
            key = (conn.pid, conn.raddr.ip, conn.raddr.port)
            
            # Check blocked IPs
            if conn.raddr.ip in self._blocked_ips:
                await self._alert(f"Blocked IP connection: {conn.raddr.ip}", "high")
                continue
            
            # Track IP port counts (port scan detection)
            self._ip_port_counts[conn.raddr.ip].add(conn.raddr.port)
            self._ip_connection_times[conn.raddr.ip].append(time.time())
            
            # Check if new connection
            if key not in self._baseline:
                proc_name = "unknown"
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except Exception:
                    pass
                
                conn_info = {
                    "timestamp": datetime.now().isoformat(),
                    "pid": conn.pid,
                    "process": proc_name,
                    "local_ip": conn.laddr.ip if conn.laddr else "",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "protocol": "TCP" if conn.type == 1 else "UDP",
                    "state": conn.status,
                }
                
                self._connections.append(conn_info)
                if len(self._connections) > self._max_connections:
                    self._connections = self._connections[-self._max_connections:]
                
                # Alert on new outbound
                await self._alert(
                    f"New connection: {proc_name} -> {conn.raddr.ip}:{conn.raddr.port}", 
                    "info"
                )
                
                self._baseline.add(key)
            
            # Port scan detection
            ports = self._ip_port_counts[conn.raddr.ip]
            if len(ports) >= self._scan_threshold_ports:
                await self._alert(
                    f"Possible port scan from {conn.raddr.ip} ({len(ports)} ports)",
                    "high"
                )
            
            # Connection frequency detection
            times = self._ip_connection_times[conn.raddr.ip]
            recent = [t for t in times if time.time() - t < self._scan_threshold_time]
            if len(recent) > 100:  # 100 connections in 60 seconds
                await self._alert(
                    f"High connection rate from {conn.raddr.ip} ({len(recent)}/60s)",
                    "medium"
                )
    
    def _cleanup_old_data(self) -> None:
        now = time.time()
        # Clean old connection times
        for ip, times in self._ip_connection_times.items():
            self._ip_connection_times[ip] = [t for t in times if now - t < 300]
            if not self._ip_connection_times[ip]:
                del self._ip_connection_times[ip]
                self._ip_port_counts.pop(ip, None)
        
        # Clean old connections
        if len(self._connections) > self._max_connections:
            self._connections = self._connections[-self._max_connections:]
    
    async def _alert(self, message: str, severity: str = "info") -> None:
        await self.broadcast({
            "type": "security_alert",
            "source": "network",
            "severity": severity,
            "message": message,
            "timestamp": datetime.now().isoformat()
        })
    
    def get_status(self) -> Dict:
        return {
            "running": self._running,
            "connections_tracked": len(self._connections),
            "blocked_ips": len(self._blocked_ips),
            "baseline_size": len(self._baseline),
            "ip_tracked": len(self._ip_port_counts)
        }
    
    def get_recent_connections(self, limit: int = 50) -> List[Dict]:
        return self._connections[-limit:]
    
    def check_integrity(self) -> bool:
        return self._running
    
    def scan(self) -> Dict:
        """Manual network scan."""
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except Exception:
                    proc_name = "unknown"
                connections.append({
                    "pid": conn.pid,
                    "process": proc_name,
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "protocol": "TCP" if conn.type == 1 else "UDP"
                })
        return {"connections": connections, "count": len(connections)}
    
    def block_ip(self, ip: str) -> bool:
        """Block IP via firewall."""
        try:
            self._blocked_ips.add(ip)
            if platform.system() == "Linux":
                subprocess.run(
                    ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                    capture_output=True, check=False
                )
            return True
        except Exception:
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        try:
            self._blocked_ips.discard(ip)
            if platform.system() == "Linux":
                subprocess.run(
                    ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                    capture_output=True, check=False
                )
            return True
        except Exception:
            return False