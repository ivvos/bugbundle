"""Wireless-specific collection: iw, rfkill, NetworkManager and iwd.

This module never asks any tool for a scanned SSID/BSSID list and never reads
NetworkManager connection profiles or iwd provisioning files.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..models import (
    CommandIssue,
    CommandResult,
    NMDevice,
    NetworkServices,
    RadioStatus,
    ServiceState,
    WirelessDevice,
)
from ..privacy import Redactor
from ..utils.commands import CommandRunner
from ..utils.fs import safe_read_text

CHANNEL_RE = re.compile(
    r"channel\s+(\d+)\s*\((\d+)\s*MHz\)(?:,\s*width:\s*([^,]+))?", re.IGNORECASE
)
TXPOWER_RE = re.compile(r"txpower\s+([0-9.]+)\s*dBm", re.IGNORECASE)
RFKILL_HEADER_RE = re.compile(r"^\d+:\s+([^:]+):\s+(.+)$")
IWD_STATION_RE = re.compile(
    r"\b(\w[\w.-]*)\s+(connected|disconnected|scanning|connecting)\b", re.IGNORECASE
)


def _issue(result: CommandResult, redactor: Redactor, command: str) -> CommandIssue:
    return CommandIssue(
        command=command,
        error=result.error or "unknown",
        detail=redactor.redact_text(result.stderr)[:300],
        exit_code=result.exit_code,
    )


def parse_iw_dev(text: str, redactor: Redactor) -> list[WirelessDevice]:
    """Parse ``iw dev`` output into one entry per netdev interface."""
    devices: list[WirelessDevice] = []
    current: WirelessDevice | None = None
    phy: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("phy#"):
            phy = stripped
            current = None
            continue
        if stripped.startswith("Interface "):
            name = stripped[len("Interface ") :].strip()
            if name:
                current = WirelessDevice(interface=name, phy=phy)
                devices.append(current)
            continue
        if not line.startswith((" ", "\t")) or not current:
            current = None
            continue
        if stripped.startswith("addr "):
            current.address = redactor.redact_text(stripped[5:].strip())
        elif stripped.startswith("type "):
            current.interface_type = stripped[5:].strip()
        elif (match := CHANNEL_RE.search(stripped)) is not None:
            current.channel = int(match.group(1))
            current.frequency_mhz = int(match.group(2))
            if match.group(3):
                current.channel_width = match.group(3).strip()
        elif (match := TXPOWER_RE.search(stripped)) is not None:
            try:
                current.txpower_dbm = float(match.group(1))
            except ValueError:
                pass
    return devices


def parse_rfkill_json(payload: Any) -> list[dict[str, Any]]:
    """Parse ``rfkill -J`` output."""
    if not isinstance(payload, dict):
        return []
    entries = payload.get("rfkilldevices")
    if not isinstance(entries, list):
        return []
    result: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, dict):
            result.append(
                {
                    "device": str(entry.get("device", "unknown")),
                    "type": str(entry.get("type", "unknown")),
                    "soft_blocked": str(entry.get("soft", "")).lower() == "blocked",
                    "hard_blocked": str(entry.get("hard", "")).lower() == "blocked",
                }
            )
    return result


def parse_rfkill_text(text: str) -> list[dict[str, Any]]:
    """Parse plain ``rfkill list`` output (fallback for older versions)."""
    result: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if (match := RFKILL_HEADER_RE.match(stripped)) is not None:
            current = {
                "device": match.group(1).strip(),
                "type": match.group(2).strip(),
                "soft_blocked": False,
                "hard_blocked": False,
            }
            result.append(current)
        elif current is not None:
            if stripped.lower().startswith("soft blocked:"):
                current["soft_blocked"] = stripped.split(":", 1)[1].strip().lower() == "yes"
            elif stripped.lower().startswith("hard blocked:"):
                current["hard_blocked"] = stripped.split(":", 1)[1].strip().lower() == "yes"
    return result


def rfkill_from_sysfs(sysfs_root: Path | str) -> list[dict[str, Any]]:
    """Last-resort rfkill state from /sys/class/rfkill (no privileges needed)."""
    root = Path(sysfs_root) / "class" / "rfkill"
    try:
        entries = sorted(root.glob("rfkill*"))
    except OSError:
        return []
    result: list[dict[str, Any]] = []
    for entry in entries:
        kind = safe_read_text(entry / "type") or "unknown"
        soft = safe_read_text(entry / "soft")
        hard = safe_read_text(entry / "hard")
        name = safe_read_text(entry / "name") or entry.name
        result.append(
            {
                "device": name.strip(),
                "type": kind.strip(),
                "soft_blocked": (soft or "").strip() == "1",
                "hard_blocked": (hard or "").strip() == "1",
            }
        )
    return result


def summarize_radio(entries: list[dict[str, Any]], source: str, available: bool = True) -> RadioStatus:
    """Reduce rfkill entries to Wi-Fi-relevant state."""
    wlan = [
        entry
        for entry in entries
        if str(entry.get("type", "")).lower() in {"wlan", "wireless lan"}
    ]
    return RadioStatus(
        available=available,
        source=source,
        soft_blocked=any(bool(entry.get("soft_blocked")) for entry in wlan),
        hard_blocked=any(bool(entry.get("hard_blocked")) for entry in wlan),
        wlan_devices=wlan,
    )


def collect_radio(
    runner: CommandRunner,
    redactor: Redactor,
    sysfs_root: Path | str = "/sys",
) -> tuple[RadioStatus, list[CommandIssue], dict[str, bool]]:
    """Collect radio state via rfkill, falling back to sysfs."""
    issues: list[CommandIssue] = []
    utilities = {"rfkill": runner.has("rfkill")}
    if utilities["rfkill"]:
        payload, result = runner.run_json(["rfkill", "-J"])
        if result.ok and payload is not None:
            entries = parse_rfkill_json(payload)
            return summarize_radio(entries, "rfkill -J"), issues, utilities
        issues.append(_issue(result, redactor, "rfkill -J"))
        text_result = runner.run(["rfkill", "list"])
        if text_result.ok:
            return summarize_radio(parse_rfkill_text(text_result.stdout), "rfkill list"), issues, utilities
        issues.append(_issue(text_result, redactor, "rfkill list"))
    entries = rfkill_from_sysfs(sysfs_root)
    if entries:
        return summarize_radio(entries, "sysfs /sys/class/rfkill"), issues, utilities
    return (
        RadioStatus(available=False, source="unavailable"),
        issues,
        utilities,
    )


def collect_iw(
    runner: CommandRunner, redactor: Redactor
) -> tuple[list[WirelessDevice], list[CommandIssue], dict[str, bool]]:
    """Collect wireless device details via iw, with iwconfig fallback."""
    issues: list[CommandIssue] = []
    utilities = {"iw": runner.has("iw"), "iwconfig": runner.has("iwconfig")}
    if utilities["iw"]:
        result = runner.run(["iw", "dev"])
        if result.ok:
            return parse_iw_dev(result.stdout, redactor), issues, utilities
        issues.append(_issue(result, redactor, "iw dev"))
    if utilities["iwconfig"]:
        result = runner.run(["iwconfig"])
        if result.ok:
            # Only interface names are used; ESSID/AP lines are deliberately ignored.
            devices = [
                WirelessDevice(interface=line.split()[0])
                for line in result.stdout.splitlines()
                if line and not line[0].isspace() and "IEEE 802.11" in line
            ]
            return devices, issues, utilities
        issues.append(_issue(result, redactor, "iwconfig"))
    return [], issues, utilities


def _split_nmcli_fields(line: str, maxsplit: int = 3) -> list[str]:
    """Split nmcli ``-t`` output on unescaped colons only.

    nmcli escapes literal colons in values as ``\\:``, so splitting the raw
    line first and unescaping afterwards would corrupt device names such as
    ``50\\:49\\:B0...``.
    """
    fields: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and index + 1 < len(line) and line[index + 1] in (":", "\\"):
            current.append(line[index + 1])
            index += 2
            continue
        if char == ":" and len(fields) < maxsplit:
            fields.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    fields.append("".join(current))
    return fields


def parse_nmcli_devices(text: str, redactor: Redactor) -> list[NMDevice]:
    """Parse ``nmcli -t -f DEVICE,TYPE,STATE,CONNECTION dev`` output.

    Connection names are frequently SSIDs, so they are registered as secrets
    and never stored in the report.
    """
    devices: list[NMDevice] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = _split_nmcli_fields(line, 3)
        if len(parts) < 3:
            continue
        name, kind, state = parts[0], parts[1], parts[2]
        connection = parts[3] if len(parts) == 4 else ""
        if connection:
            redactor.register_secret(connection, "ssid", scope="logs")
        devices.append(
            NMDevice(
                device=name,
                device_type=kind,
                state=state,
                connection_redacted=bool(connection),
            )
        )
    return devices


def _service_state(
    runner: CommandRunner, redactor: Redactor, unit: str, issues: list[CommandIssue]
) -> ServiceState:
    result = runner.run(["systemctl", "is-active", unit])
    state = result.stdout.strip().lower() if result.ok else "inactive"
    if state not in {"active", "inactive", "activating", "deactivating", "failed", "unknown"}:
        state = "unknown"
    available = runner.has("systemctl") and state != "unknown"
    if result.error in {"not_found", "timeout", "permission_denied", "os_error", "blocked_command"}:
        issues.append(_issue(result, redactor, f"systemctl is-active {unit}"))
    return ServiceState(name=unit, available=available, state=state)


def collect_services(
    runner: CommandRunner,
    redactor: Redactor,
    radio: RadioStatus,
) -> tuple[NetworkServices, list[CommandIssue], dict[str, bool]]:
    """Collect NetworkManager / iwd / systemd-networkd status without touching them."""
    issues: list[CommandIssue] = []
    utilities = {
        "nmcli": runner.has("nmcli"),
        "systemctl": runner.has("systemctl"),
        "iwctl": runner.has("iwctl"),
    }
    services = NetworkServices(
        network_manager=_service_state(runner, redactor, "NetworkManager", issues),
        iwd=_service_state(runner, redactor, "iwd", issues),
        systemd_networkd=_service_state(runner, redactor, "systemd-networkd", issues),
        nm_available=utilities["nmcli"],
        iwctl_available=utilities["iwctl"],
    )

    if radio.soft_blocked or radio.hard_blocked:
        services.wifi_radio = "disabled"
    elif radio.available and radio.wlan_devices:
        services.wifi_radio = "enabled"

    if utilities["nmcli"]:
        general = runner.run(["nmcli", "-t", "-f", "RUNNING,STATE", "general"])
        if general.ok:
            fields = general.stdout.strip().split(":", 1)
            services.nm_running = fields[0].strip().lower() == "running"
            services.nm_state = fields[1].strip() if len(fields) > 1 else None
        else:
            issues.append(_issue(general, redactor, "nmcli general"))

        radio_result = runner.run(["nmcli", "radio", "wifi"])
        if radio_result.ok:
            value = radio_result.stdout.strip().lower()
            services.wifi_radio = value if value in {"enabled", "disabled"} else services.wifi_radio
        else:
            issues.append(_issue(radio_result, redactor, "nmcli radio wifi"))

        devices_result = runner.run(
            ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev"]
        )
        if devices_result.ok:
            services.nm_devices = parse_nmcli_devices(devices_result.stdout, redactor)
        else:
            issues.append(_issue(devices_result, redactor, "nmcli dev"))

    if utilities["iwctl"]:
        stations = runner.run(["iwctl", "station", "list"])
        if stations.ok:
            for match in IWD_STATION_RE.finditer(stations.stdout):
                entry = f"{match.group(1)}: {match.group(2).lower()}"
                if entry not in services.iwd_stations:
                    services.iwd_stations.append(redactor.redact_text(entry))
        else:
            issues.append(_issue(stations, redactor, "iwctl station list"))

    return services, issues, utilities
