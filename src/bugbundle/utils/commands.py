"""Safe subprocess execution.

Every external command goes through :class:`CommandRunner`, which:

* never uses ``shell=True``;
* only runs executables from a fixed allow-list;
* passes a minimal, explicit environment;
* enforces a timeout; and
* converts all failures into data instead of exceptions.

The allow-list also stops a bug in a parser from turning diagnostic text into
a command name.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import replace
from pathlib import Path

from ..models import CommandResult

# Commands that BugBundle is allowed to execute. Nothing else may run.
ALLOWED_COMMANDS = frozenset(
    {
        "ip",
        "iw",
        "iwctl",
        "iwconfig",
        "nmcli",
        "rfkill",
        "lspci",
        "lsusb",
        "ethtool",
        "modinfo",
        "systemctl",
        "journalctl",
        "hostnamectl",
        "uname",
    }
)

MAX_OUTPUT_CHARS = 200_000


def _minimal_env() -> dict[str, str]:
    """Build an environment for child processes; never returned in reports."""
    env: dict[str, str] = {}
    path = os.environ.get("PATH")
    if path:
        env["PATH"] = path
    # C locale keeps command output parseable on every locale.
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    env["TERM"] = "dumb"
    runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
    if runtime_dir:
        env["XDG_RUNTIME_DIR"] = runtime_dir
    return env


class CommandRunner:
    """Run allow-listed commands safely and return structured results."""

    def __init__(
        self,
        timeout: float = 5.0,
        allowed: frozenset[str] | set[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = float(timeout)
        self.allowed = frozenset(ALLOWED_COMMANDS if allowed is None else allowed)
        self.env = _minimal_env() if env is None else dict(env)

    def has(self, command: str) -> bool:
        """Return True when an allow-listed executable is on PATH."""
        if Path(command).name not in self.allowed:
            return False
        return shutil.which(command) is not None

    def run(self, argv: list[str] | tuple[str, ...], timeout: float | None = None) -> CommandResult:
        """Execute ``argv`` without a shell. Failures become CommandResult data."""
        if not isinstance(argv, (list, tuple)) or not argv:
            return CommandResult((), error="invalid_command")
        if not all(isinstance(part, str) and part for part in argv):
            return CommandResult(tuple(str(p) for p in argv), error="invalid_command")
        args = tuple(argv)
        if any("\x00" in part for part in args):
            return CommandResult(args, error="invalid_command")

        executable = Path(args[0]).name
        if executable not in self.allowed:
            return CommandResult(
                args,
                error="blocked_command",
                stderr=f"command is not in the BugBundle allow-list: {executable}",
            )
        if shutil.which(executable) is None:
            return CommandResult(
                args, error="not_found", stderr=f"command not found on PATH: {executable}"
            )

        limit = self.timeout if timeout is None else timeout
        started = time.monotonic()
        try:
            completed = subprocess.run(
                list(args),
                shell=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=limit,
                check=False,
                env=self.env,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                args,
                error="timeout",
                stderr=f"command timed out after {limit:g}s",
                stdout=_safe_decode(exc.stdout),
                duration_ms=_elapsed_ms(started),
            )
        except FileNotFoundError:
            return CommandResult(
                args, error="not_found", stderr="command disappeared from PATH", duration_ms=_elapsed_ms(started)
            )
        except PermissionError:
            return CommandResult(
                args, error="permission_denied", stderr="permission denied", duration_ms=_elapsed_ms(started)
            )
        except OSError as exc:
            return CommandResult(
                args,
                error="os_error",
                stderr=f"OS error: {exc.__class__.__name__}",
                duration_ms=_elapsed_ms(started),
            )

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        truncated = False
        if len(stdout) > MAX_OUTPUT_CHARS:
            stdout = stdout[:MAX_OUTPUT_CHARS]
            truncated = True
        if len(stderr) > MAX_OUTPUT_CHARS:
            stderr = stderr[:MAX_OUTPUT_CHARS]
            truncated = True
        return CommandResult(
            argv=args,
            ok=completed.returncode == 0,
            exit_code=completed.returncode,
            stdout=stdout.strip(),
            stderr=(stderr + ("\n[output truncated]" if truncated else "")).strip(),
            error=None if completed.returncode == 0 else "nonzero_exit",
            duration_ms=_elapsed_ms(started),
        )

    def run_json(
        self, argv: list[str] | tuple[str, ...], timeout: float | None = None
    ) -> tuple[object | None, CommandResult]:
        """Run a command and parse its stdout as JSON.

        Returns ``(data, result)``. On invalid JSON, ``data`` is None and the
        returned result has ``error="invalid_json"``.
        """
        result = self.run(argv, timeout=timeout)
        if not result.ok:
            return None, result
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            return None, replace(
                result,
                ok=False,
                error="invalid_json",
                stderr="command output was not valid JSON",
            )
        return data, result


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _safe_decode(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
