"""Filesystem helpers with privacy guard rails.

BugBundle only ever needs a handful of world-readable pseudo-files. This
module makes it impossible (by accident) to read a directory that contains
connection secrets through the normal collection helpers.
"""

from __future__ import annotations

import re
from pathlib import Path

# Directories that may contain credentials. No collector is allowed to read
# from them; the test suite verifies that this list is honoured.
FORBIDDEN_PREFIXES = (
    Path("/etc/NetworkManager/system-connections"),
    Path("/var/lib/iwd"),
    Path("/etc/wpa_supplicant"),
    Path("/etc/ppp"),
    Path("/root/.ssh"),
)

IFNAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


class ForbiddenPathError(PermissionError):
    """Raised when code tries to read a credential-bearing location."""


def validate_ifname(name: str) -> str:
    """Validate an interface name before it is used in a command line."""
    if not isinstance(name, str) or not IFNAME_RE.fullmatch(name):
        raise ValueError(f"invalid interface name: {name!r}")
    return name


def safe_read_text(path: Path | str, limit: int = 65_536) -> str | None:
    """Read a small UTF-8 file, refusing secret paths and following no links.

    Returns None for missing or unreadable files instead of raising.
    """
    target = Path(path)
    if any(target == root or root in target.parents for root in FORBIDDEN_PREFIXES):
        raise ForbiddenPathError(f"refusing to read credential path: {target}")
    try:
        if target.is_symlink():
            return None
        return target.read_text(encoding="utf-8", errors="replace")[:limit]
    except (OSError, ValueError):
        return None


def safe_readlink(path: Path | str) -> str | None:
    """Return the basename of a symlink target, or None if unavailable."""
    target = Path(path)
    if any(target == root or root in target.parents for root in FORBIDDEN_PREFIXES):
        raise ForbiddenPathError(f"refusing to read credential path: {target}")
    try:
        if not target.is_symlink():
            return None
        return target.resolve(strict=False).name
    except (OSError, ValueError):
        return None
