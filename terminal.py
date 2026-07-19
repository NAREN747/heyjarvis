"""
JARVIS Terminal Control — Real shell execution with safety tiers.

No keyword matching. The LLM decides what command to run.
Safety tiers gate execution:
    SAFE      → runs immediately (ls, cat, ps, df, whoami)
    REVIEW    → runs, logged, shown after (pip install, curl, kill)
    CONFIRM   → holds until user says yes (rm, mv, sudo, chmod)
    BLOCKED   → never runs (rm -rf /, fork bombs, disk format)

OS-level shortcuts for speed: open apps, lock screen, volume, screenshot, sysinfo.
"""
from __future__ import annotations

import asyncio
import os
import platform
import shlex
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class SafetyTier(Enum):
    SAFE = "safe"
    REVIEW = "review"
    CONFIRM = "confirm"
    BLOCKED = "blocked"


# --- Patterns by tier --------------------------------------------------------

SAFE_PATTERNS = [
    r"^ls\b", r"^dir\b", r"^cat\b", r"^head\b", r"^tail\b", r"^less\b", r"^more\b",
    r"^ps\b", r"^top\b", r"^htop\b", r"^df\b", r"^du\b", r"^free\b", r"^whoami\b",
    r"^id\b", r"^pwd\b", r"^date\b", r"^uptime\b", r"^uname\b", r"^which\b", r"^whereis\b",
    r"^file\b", r"^stat\b", r"^echo\b", r"^printenv\b", r"^env\b", r"^history\b",
    r"^git\s+(status|log|diff|branch|remote)\b",
    r"^python3?\s+--version\b", r"^python3?\s+-c\b",
    r"^pip\s+(list|show|freeze)\b",
    r"^systemctl\s+(status|is-active|is-enabled)\b",
    r"^journalctl\s+(-u|-f|--no-pager)\b",
    r"^ss\s+(-t|-u|-l|-n)\b", r"^netstat\b",
    r"^ip\s+(addr|route|link)\b", r"^ifconfig\b",
    r"^ping\b", r"^traceroute\b", r"^dig\b", r"^nslookup\b",
    r"^curl\s+(-I|--head)\b", r"^wget\s+--spider\b",
]

REVIEW_PATTERNS = [
    r"^pip\s+install\b", r"^pip3\s+install\b",
    r"^curl\s+(?!-I|--head)", r"^wget\s+(?!--spider)",
    r"^kill\b", r"^pkill\b", r"^killall\b",
    r"^systemctl\s+(start|stop|restart|reload|enable|disable)\b",
    r"^service\s+\w+\s+(start|stop|restart)\b",
    r"^docker\s+(pull|run|build|push|exec)\b",
    r"^npm\s+install\b", r"^yarn\s+add\b", r"^cargo\s+install\b",
    r"^apt\s+(update|install|upgrade)\b", r"^apt-get\s+(update|install|upgrade)\b",
    r"^dnf\s+install\b", r"^yum\s+install\b", r"^pacman\s+-S\b",
    r"^git\s+(push|pull|fetch|merge|rebase|reset\s+--hard)\b",
]

CONFIRM_PATTERNS = [
    r"^rm\b", r"^del\b", r"^mv\b", r"^cp\s+-r\b",
    r"^sudo\b", r"^su\b", r"^doas\b",
    r"^chmod\b", r"^chown\b", r"^chgrp\b",
    r"^dd\b", r"^fdisk\b", r"^parted\b", r"^mkfs\b", r"^format\b",
    r"^shutdown\b", r"^reboot\b", r"^poweroff\b", r"^halt\b",
    r"^systemctl\s+(reboot|poweroff|halt)\b",
    r">\s*/dev/(sd|hd|vd)", r"^>\s*/dev/null\s*$",  # raw disk writes
]

BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/", r"rm\s+-rf\s+\*", r":\(\)\{\s*:\|\:&\s*\}",  # fork bomb
    r"dd\s+if=/dev/zero\s+of=/dev/(sd|hd|vd)",
    r"mkfs\.(ext4|xfs|btrfs|ntfs|fat32)\s+/dev/",
    r">\s*/dev/(sd|hd|vd)[a-z]",
    r"curl.*\|\s*sh", r"wget.*\|\s*sh", r"curl.*\|\s*bash", r"wget.*\|\s*bash",
    r"chmod\s+-R\s+777\s+/", r"chown\s+-R\s+.*\s+/",
]


@dataclass
class CommandResult:
    command: str
    tier: SafetyTier
    stdout: str
    stderr: str
    returncode: int
    confirmed: bool = False


def classify_command(cmd: str) -> SafetyTier:
    """Determine safety tier of a command string."""
    cmd_stripped = cmd.strip()
    if not cmd_stripped:
        return SAFE
    
    # Check blocked first (most restrictive)
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, cmd_stripped, re.IGNORECASE):
            return SafetyTier.BLOCKED
    
    # Then confirm
    for pattern in CONFIRM_PATTERNS:
        if re.search(pattern, cmd_stripped, re.IGNORECASE):
            return SafetyTier.CONFIRM
    
    # Then review
    for pattern in REVIEW_PATTERNS:
        if re.search(pattern, cmd_stripped, re.IGNORECASE):
            return SafetyTier.REVIEW
    
    # Then safe
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, cmd_stripped, re.IGNORECASE):
            return SafetyTier.SAFE
    
    # Default: review (cautious)
    return SafetyTier.REVIEW


async def execute_shell(
    command: str,
    confirm: bool = False,
    cwd: Optional[str] = None,
    timeout: float = 60.0,
    confirm_callback: Optional[callable] = None,
) -> CommandResult:
    """
    Execute a shell command with safety tier gating.
    
    Args:
        command: Shell command to run
        confirm: If True, treat as CONFIRM tier regardless of pattern
        cwd: Working directory
        timeout: Max seconds to run
        confirm_callback: Async function(msg) -> bool for user confirmation
    
    Returns:
        CommandResult with stdout, stderr, returncode, tier
    """
    tier = SafetyTier.CONFIRM if confirm else classify_command(command)
    
    # BLOCKED: never run
    if tier == SafetyTier.BLOCKED:
        return CommandResult(
            command=command,
            tier=tier,
            stdout="",
            stderr="BLOCKED: Command matches permanently blocked pattern.",
            returncode=-1,
            confirmed=False,
        )
    
    # CONFIRM: need user approval
    if tier == SafetyTier.CONFIRM and not confirm:
        if confirm_callback:
            approved = await confirm_callback(
                f"Confirm command: {command}\nTier: CONFIRM — type 'yes' to proceed."
            )
            if not approved:
                return CommandResult(
                    command=command,
                    tier=tier,
                    stdout="",
                    stderr="Cancelled by user.",
                    returncode=-1,
                    confirmed=False,
                )
        else:
            return CommandResult(
                command=command,
                tier=tier,
                stdout="",
                stderr="CONFIRM required but no callback available.",
                returncode=-1,
                confirmed=False,
            )
    
    # Execute
    try:
        # Use shell=True for pipes, redirects, etc. but be careful
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "TERM": "dumb"},
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return CommandResult(
                command=command,
                tier=tier,
                stdout="",
                stderr=f"TIMEOUT after {timeout}s",
                returncode=-1,
                confirmed=confirm,
            )
        
        return CommandResult(
            command=command,
            tier=tier,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            returncode=proc.returncode or 0,
            confirmed=confirm,
        )
    except Exception as e:
        return CommandResult(
            command=command,
            tier=tier,
            stdout="",
            stderr=f"Execution error: {e}",
            returncode=-1,
            confirmed=confirm,
        )


# --- OS-level shortcuts (instant, no LLM call needed) ------------------------

async def os_open_app(app: str) -> CommandResult:
    """Open a common application."""
    system = platform.system().lower()
    app_lower = app.lower()
    
    try:
        if system == "windows":
            apps = {
                "chrome": "start chrome",
                "firefox": "start firefox",
                "edge": "start msedge",
                "vscode": "code",
                "code": "code",
                "notepad": "notepad",
                "terminal": "wt",
                "cmd": "cmd",
                "powershell": "powershell",
                "explorer": "explorer",
            }
        elif system == "darwin":
            apps = {
                "chrome": "open -a 'Google Chrome'",
                "firefox": "open -a Firefox",
                "safari": "open -a Safari",
                "vscode": "open -a 'Visual Studio Code'",
                "code": "open -a 'Visual Studio Code'",
                "terminal": "open -a Terminal",
                "finder": "open -a Finder",
            }
        else:  # Linux
            apps = {
                "chrome": "google-chrome",
                "firefox": "firefox",
                "vscode": "code",
                "code": "code",
                "terminal": "gnome-terminal",
            }
        
        cmd = apps.get(app_lower)
        if not cmd:
            return CommandResult(
                command=f"open {app}",
                tier=SafetyTier.SAFE,
                stdout="",
                stderr=f"Unknown app: {app}",
                returncode=-1,
            )
        
        if system == "windows":
            # Use start for GUI apps
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
        else:
            proc = await asyncio.create_subprocess_shell(
                cmd + " &", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
        await proc.wait()
        return CommandResult(command=cmd, tier=SafetyTier.SAFE, stdout=f"Opened {app}", stderr="", returncode=0)
    except Exception as e:
        return CommandResult(command=cmd, tier=SafetyTier.SAFE, stdout="", stderr=str(e), returncode=-1)


async def os_lock_screen() -> CommandResult:
    """Lock the screen."""
    system = platform.system().lower()
    try:
        if system == "windows":
            await asyncio.create_subprocess_exec(
                "rundll32.exe", "user32.dll,LockWorkStation"
            )
        elif system == "darwin":
            await asyncio.create_subprocess_exec(
                "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"
            )
        else:
            # Try common Linux lockers
            for cmd in [["gnome-screensaver-command", "-l"], ["loginctl", "lock-session"], ["dm-tool", "lock"]]:
                try:
                    proc = await asyncio.create_subprocess_exec(*cmd)
                    await proc.wait()
                    break
                except FileNotFoundError:
                    continue
        return CommandResult(command="lock", tier=SafetyTier.SAFE, stdout="Screen locked", stderr="", returncode=0)
    except Exception as e:
        return CommandResult(command="lock", tier=SafetyTier.SAFE, stdout="", stderr=str(e), returncode=-1)


async def os_volume(action: str) -> CommandResult:
    """Volume control: up, down, mute, set <0-100>."""
    system = platform.system().lower()
    try:
        if system == "windows":
            from ctypes import cast, POINTER
            from comtypes import CLSCTX_ALL
            from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
            devices = AudioUtilities.GetSpeakers()
            interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
            volume = cast(interface, POINTER(IAudioEndpointVolume))
            if action == "up":
                volume.SetMasterVolumeLevelScalar(min(1.0, volume.GetMasterVolumeLevelScalar() + 0.1), None)
            elif action == "down":
                volume.SetMasterVolumeLevelScalar(max(0.0, volume.GetMasterVolumeLevelScalar() - 0.1), None)
            elif action == "mute":
                volume.SetMute(1, None)
            elif action == "unmute":
                volume.SetMute(0, None)
            else:
                try:
                    level = float(action) / 100.0
                    volume.SetMasterVolumeLevelScalar(max(0.0, min(1.0, level)), None)
                except ValueError:
                    return CommandResult(command=f"volume {action}", tier=SafetyTier.SAFE, stdout="", stderr="Invalid level", returncode=-1)
        elif system == "darwin":
            if action in ("up", "down"):
                step = 10 if action == "up" else -10
                await asyncio.create_subprocess_exec("osascript", "-e", f"set volume output volume (output volume of (get volume settings) + {step})")
            elif action in ("mute", "unmute"):
                await asyncio.create_subprocess_exec("osascript", "-e", f"set volume output muted {action == 'mute'}")
            else:
                await asyncio.create_subprocess_exec("osascript", "-e", f"set volume output volume {action}")
        else:
            # Linux: use pactl or amixer
            if action in ("up", "down"):
                step = "+5%" if action == "up" else "-5%"
                await asyncio.create_subprocess_exec("pactl", "set-sink-volume", "@DEFAULT_SINK@", step)
            elif action in ("mute", "unmute"):
                await asyncio.create_subprocess_exec("pactl", "set-sink-mute", "@DEFAULT_SINK@", "1" if action == "mute" else "0")
            else:
                await asyncio.create_subprocess_exec("pactl", "set-sink-volume", "@DEFAULT_SINK@", f"{action}%")
        return CommandResult(command=f"volume {action}", tier=SafetyTier.SAFE, stdout=f"Volume {action}", stderr="", returncode=0)
    except Exception as e:
        return CommandResult(command=f"volume {action}", tier=SafetyTier.SAFE, stdout="", stderr=str(e), returncode=-1)


async def os_screenshot(path: Optional[str] = None) -> CommandResult:
    """Take a screenshot."""
    system = platform.system().lower()
    if not path:
        from datetime import datetime
        path = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    
    try:
        if system == "windows":
            from PIL import ImageGrab
            img = ImageGrab.grab()
            img.save(path)
        elif system == "darwin":
            await asyncio.create_subprocess_exec("screencapture", path)
        else:
            # Try gnome-screenshot, then grim, then scrot
            for cmd in [["gnome-screenshot", "-f", path], ["grim", path], ["scrot", path]]:
                try:
                    proc = await asyncio.create_subprocess_exec(*cmd)
                    await proc.wait()
                    break
                except FileNotFoundError:
                    continue
        return CommandResult(command="screenshot", tier=SafetyTier.SAFE, stdout=f"Saved to {path}", stderr="", returncode=0)
    except Exception as e:
        return CommandResult(command="screenshot", tier=SafetyTier.SAFE, stdout="", stderr=str(e), returncode=-1)


async def os_sysinfo() -> CommandResult:
    """System information summary."""
    import psutil
    try:
        cpu = psutil.cpu_percent(interval=0.5, percpu=True)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        boot = psutil.boot_time()
        from datetime import datetime
        uptime = datetime.now() - datetime.fromtimestamp(boot)
        
        lines = [
            f"OS: {platform.system()} {platform.release()} ({platform.machine()})",
            f"CPU: {psutil.cpu_count()} cores @ {psutil.cpu_freq().current:.0f}MHz" if psutil.cpu_freq() else "CPU: info unavailable",
            f"CPU Usage: {sum(cpu)/len(cpu):.1f}% (per-core: {', '.join(f'{c:.1f}%' for c in cpu)})",
            f"RAM: {mem.used/1e9:.1f}/{mem.total/1e9:.1f} GB ({mem.percent:.1f}%)",
            f"Disk: {disk.used/1e9:.1f}/{disk.total/1e9:.1f} GB ({disk.percent:.1f}%)",
            f"Uptime: {uptime.days}d {uptime.seconds//3600}h {(uptime.seconds%3600)//60}m",
        ]
        return CommandResult(command="sysinfo", tier=SafetyTier.SAFE, stdout="\n".join(lines), stderr="", returncode=0)
    except Exception as e:
        return CommandResult(command="sysinfo", tier=SafetyTier.SAFE, stdout="", stderr=str(e), returncode=-1)


import re