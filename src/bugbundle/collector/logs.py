"""Optional, explicitly opt-in journal collection.

No command in this module runs unless the user passes ``--include-logs``.
Only journalctl is used; log files are never read directly.
"""

from __future__ import annotations

from typing import Any

from ..models import CommandIssue, CommandResult, NetworkServices
from ..privacy import Redactor
from ..utils.commands import CommandRunner

MAX_LINES_PER_UNIT = 120
MAX_CHARS_PER_UNIT = 20_000
# Units are chosen from a fixed set; user input is never interpolated.
ALLOWED_UNITS = ("NetworkManager", "iwd", "systemd-networkd")


def _issue(result: CommandResult, redactor: Redactor, command: str) -> CommandIssue:
    return CommandIssue(
        command=command,
        error=result.error or "unknown",
        detail=redactor.redact_text(result.stderr)[:300],
        exit_code=result.exit_code,
    )


def selected_units(services: NetworkServices) -> list[str]:
    """Choose relevant units based on the already-collected service state."""
    units: list[str] = []
    candidates = (
        ("NetworkManager", services.network_manager, services.nm_available),
        ("iwd", services.iwd, services.iwctl_available),
        ("systemd-networkd", services.systemd_networkd, False),
    )
    for name, state, tool_available in candidates:
        if name in ALLOWED_UNITS and (state.state == "active" or tool_available):
            units.append(name)
    return units


def collect_logs(
    runner: CommandRunner,
    redactor: Redactor,
    services: NetworkServices,
    include_logs: bool,
) -> tuple[dict[str, Any] | None, list[CommandIssue], dict[str, bool]]:
    """Collect redacted journal excerpts only when explicitly requested."""
    utilities = {"journalctl": runner.has("journalctl")}
    if not include_logs:
        return None, [], utilities

    issues: list[CommandIssue] = []
    units = selected_units(services)
    collected: dict[str, Any] = {}
    for unit in units:
        command = ["journalctl", "-u", unit, "-n", str(MAX_LINES_PER_UNIT), "--no-pager", "--since=-24h"]
        result = runner.run(command)
        if not result.ok:
            issues.append(_issue(result, redactor, " ".join(command[:3])))
            collected[unit] = {
                "available": False,
                "issue": result.error or "nonzero_exit",
                "lines": [],
            }
            continue
        lines: list[str] = []
        total = 0
        for raw in result.stdout.splitlines():
            clean = redactor.redact_text(raw, scope="logs").strip()
            if not clean:
                continue
            total += len(clean) + 1
            if total > MAX_CHARS_PER_UNIT:
                lines.append("[further log lines omitted to limit exposure]")
                break
            lines.append(clean)
        collected[unit] = {
            "available": True,
            "issue": None,
            "line_count": len(lines),
            "lines": lines,
        }

    logs: dict[str, Any] = {
        "included": True,
        "source": "journalctl (explicitly opted in)",
        "time_window": "last 24 hours, at most 120 entries per unit",
        "units": collected,
    }
    return logs, issues, utilities
