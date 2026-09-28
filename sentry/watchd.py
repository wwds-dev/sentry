"""Install / remove / query the continuous background watch (launchd).

The background watcher is a launchd *StartInterval* agent — launchd re-runs
``main.py --headless`` (one watch pass) every N seconds rather than us keeping a
long-lived daemon alive. Each pass reuses the same baseline and findings log the
in-app panel reads, so the app shows whatever the background watcher found while
it was closed.

Everything here is guarded: launchctl output is parsed defensively, and every
call returns a plain result dict the panel can render rather than raising into
the UI thread.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path

LABEL = "com.sentinel.sentry.watch"
PROJECT = Path(__file__).resolve().parents[1]  # agents/sentry
MAIN = PROJECT / "main.py"
MIN_INTERVAL = 60
DEFAULT_INTERVAL = 300


def _launch_agents_dir() -> Path:
    path = Path.home() / "Library" / "LaunchAgents"
    path.mkdir(parents=True, exist_ok=True)
    return path


def plist_path() -> Path:
    return _launch_agents_dir() / f"{LABEL}.plist"


def _python_executable() -> str:
    """Prefer the project's own venv so the watcher matches the app's imports."""
    venv = PROJECT.parents[1] / ".venv" / "bin" / "python"
    if venv.exists():
        return str(venv)
    return sys.executable or "python3"


def _log_path() -> Path:
    try:
        from .baseline import default_state_dir

        return default_state_dir() / "watch.log"
    except Exception:
        return PROJECT / "data" / "watch.log"


def build_plist(interval: int) -> dict:
    interval = max(MIN_INTERVAL, int(interval))
    log = str(_log_path())
    return {
        "Label": LABEL,
        "ProgramArguments": [_python_executable(), str(MAIN), "--headless"],
        "StartInterval": interval,
        "RunAtLoad": True,
        "WorkingDirectory": str(PROJECT),
        "StandardOutPath": log,
        "StandardErrorPath": log,
        "ProcessType": "Background",
    }


def is_installed() -> bool:
    return plist_path().is_file()


def is_loaded() -> bool:
    try:
        proc = subprocess.run(
            ["launchctl", "list"], capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return LABEL in (proc.stdout or "")


def status() -> dict:
    return {
        "installed": is_installed(),
        "loaded": is_loaded(),
        "interval": _installed_interval(),
        "plist": str(plist_path()),
        "log": str(_log_path()),
    }


def _installed_interval() -> int | None:
    path = plist_path()
    if not path.is_file():
        return None
    try:
        with path.open("rb") as handle:
            return int(plistlib.load(handle).get("StartInterval", 0)) or None
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None


def install(interval: int = DEFAULT_INTERVAL) -> dict:
    """Write the plist and load it. Reloads cleanly if already installed."""
    path = plist_path()
    if is_loaded():
        _launchctl_unload(path)
    try:
        with path.open("wb") as handle:
            plistlib.dump(build_plist(interval), handle)
    except OSError as exc:
        return {"ok": False, "message": f"Could not write launch agent: {exc}"}
    result = _launchctl_load(path)
    result["interval"] = max(MIN_INTERVAL, int(interval))
    return result


def remove() -> dict:
    """Unload and delete the launch agent. Idempotent."""
    path = plist_path()
    if is_loaded():
        _launchctl_unload(path)
    try:
        if path.is_file():
            path.unlink()
    except OSError as exc:
        return {"ok": False, "message": f"Could not remove launch agent: {exc}"}
    return {"ok": True, "message": "Background watch removed."}


def _launchctl_load(path: Path) -> dict:
    try:
        proc = subprocess.run(
            ["launchctl", "load", "-w", str(path)],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "message": f"launchctl unavailable: {exc}"}
    if proc.returncode != 0:
        return {"ok": False, "message": proc.stderr.strip() or "launchctl load failed."}
    return {"ok": True, "message": "Background watch installed and running."}


def _launchctl_unload(path: Path) -> None:
    try:
        subprocess.run(
            ["launchctl", "unload", "-w", str(path)],
            capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
