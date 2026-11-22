"""Orchestration of the Wi-Fi diagnostic module."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..models import Report
from ..privacy import Redactor
from ..utils.commands import CommandRunner
from . import findings as analysis
from .hardware import collect_drivers, collect_hardware
from .logs import collect_logs
from .network import collect_network
from .system import collect_system
from .wireless import collect_iw, collect_radio, collect_services


def collect_wifi_report(
    runner: CommandRunner,
    redactor: Redactor,
    *,
    sysfs_root: Path | str = "/sys",
    os_release_path: Path | str = "/etc/os-release",
    include_logs: bool = False,
) -> Report:
    """Run every collector and combine their results into one Report.

    Collectors are independent: a failure in one becomes a CommandIssue and
    does not prevent the others from running.
    """
    system = collect_system(redactor, os_release_path)

    wireless_devices, iw_issues, iw_utils = collect_iw(runner, redactor)
    wireless_names = {device.interface for device in wireless_devices}
    interfaces, routes, net_issues, net_utils = collect_network(
        runner, redactor, sysfs_root, wireless_names
    )
    radio, radio_issues, radio_utils = collect_radio(runner, redactor, sysfs_root)
    services, service_issues, service_utils = collect_services(runner, redactor, radio)
    adapters, hardware_issues, hardware_utils = collect_hardware(runner, redactor)
    drivers, driver_issues, driver_utils = collect_drivers(
        runner, redactor, interfaces, sysfs_root
    )
    logs, log_issues, log_utils = collect_logs(runner, redactor, services, include_logs)

    utilities: dict[str, bool] = {}
    for group in (
        iw_utils,
        net_utils,
        radio_utils,
        service_utils,
        hardware_utils,
        driver_utils,
        log_utils,
    ):
        utilities.update(group)

    command_issues = [
        *net_issues,
        *iw_issues,
        *radio_issues,
        *service_issues,
        *hardware_issues,
        *driver_issues,
        *log_issues,
    ]
    routes_available = not any(
        issue.command == "ip -j route show" for issue in command_issues
    )

    observed_findings = analysis.analyze(
        interfaces=interfaces,
        wireless_devices=wireless_devices,
        radio=radio,
        services=services,
        adapters=adapters,
        drivers=drivers,
        utilities=utilities,
        routes=routes,
        routes_available=routes_available,
        command_issues=command_issues,
        logs_included=bool(logs and logs.get("included")),
    )

    privacy: dict[str, Any] = {
        "logs_included": bool(logs and logs.get("included")),
        "ip_addresses_redacted": True,
        "mac_addresses_redacted": True,
        "note": "Redaction is best-effort. Inspect the entire report before sharing it.",
    }

    return Report(
        module="wifi",
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        tool_version=__version__,
        system=system,
        interfaces=interfaces,
        wireless_devices=wireless_devices,
        radio=radio,
        services=services,
        adapters=adapters,
        drivers=drivers,
        utilities=utilities,
        default_routes=routes,
        findings=observed_findings,
        command_issues=command_issues,
        logs=logs,
        privacy=privacy,
    )
