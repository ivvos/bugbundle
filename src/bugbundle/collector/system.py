"""Distribution, kernel and runtime information."""

from __future__ import annotations

import platform
import re
import shlex
from pathlib import Path
from typing import Any

from ..privacy import Redactor

KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_os_release(path: Path | str) -> dict[str, str]:
    """Parse an os-release style file without executing shell code."""
    result: dict[str, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return result
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        key = key.strip()
        raw = raw.strip()
        if not KEY_RE.fullmatch(key):
            continue
        try:
            parts = shlex.split(raw, posix=True)
            value = parts[0] if len(parts) == 1 else " ".join(parts)
        except ValueError:
            value = raw.strip("\"'")
        result[key] = value
    return result


def collect_system(
    redactor: Redactor, os_release_path: Path | str = "/etc/os-release"
) -> dict[str, Any]:
    """Collect redacted system information as a plain dictionary."""
    release = parse_os_release(os_release_path)
    hostname = _hostname()
    redactor.register_secret(hostname, "hostname")
    return {
        "distribution": release.get("PRETTY_NAME") or release.get("NAME") or "Unknown",
        "distribution_id": release.get("ID", "unknown"),
        "version": release.get("VERSION") or release.get("VERSION_ID") or "unknown",
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "hostname": redactor.redact_text(hostname) or "unknown",
        "os_release_available": bool(release),
    }


def _hostname() -> str:
    try:
        return platform.node() or ""
    except (OSError, ValueError):
        return ""
