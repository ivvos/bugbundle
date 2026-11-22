"""PCI/USB adapter and driver information."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..models import (
    AdapterInfo,
    CommandIssue,
    CommandResult,
    DriverInfo,
    InterfaceInfo,
)
from ..privacy import Redactor
from ..utils.commands import CommandRunner
from ..utils.fs import safe_readlink, validate_ifname

PCI_HEADER_RE = re.compile(r"^([0-9a-fA-F]{2}:[0-9a-fA-F]{2}(?:\.[0-9a-fA-F])?)\s+(.+)$")
PCI_ID_RE = re.compile(r"\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]")
USB_LINE_RE = re.compile(
    r"^Bus\s+\d+\s+Device\s+\d+:\s+ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s+(.+)$"
)
NETWORK_WORDS = re.compile(r"network|wireless|wi-fi|wifi|wlan|ethernet", re.IGNORECASE)
VENDORS = (
    "Intel Corporation",
    "Qualcomm Atheros",
    "Qualcomm",
    "Broadcom Inc. and subsidiaries",
    "Broadcom",
    "Realtek Semiconductor Co., Ltd.",
    "Realtek",
    "MEDIATEK Corp.",
    "MediaTek",
    "Marvell",
    "Atheros",
    "Ralink",
    "Samsung",
    "Apple",
    "Cisco",
    "ASUSTeK",
    "D-Link",
)


def _issue(result: CommandResult, redactor: Redactor, command: str) -> CommandIssue:
    return CommandIssue(
        command=command,
        error=result.error or "unknown",
        detail=redactor.redact_text(result.stderr)[:300],
        exit_code=result.exit_code,
    )


def _split_vendor(description: str) -> tuple[str | None, str]:
    for vendor in VENDORS:
        if description.lower().startswith(vendor.lower()):
            remainder = description[len(vendor) :].strip(" ,-")
            return vendor, remainder
    return None, description


def parse_lspci_nnk(text: str) -> list[AdapterInfo]:
    """Parse ``lspci -nnk`` output, keeping only network controllers."""
    adapters: list[AdapterInfo] = []
    current: AdapterInfo | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            current = None
            match = PCI_HEADER_RE.match(line)
            if not match:
                continue
            slot, description = match.group(1), match.group(2)
            if not NETWORK_WORDS.search(description):
                continue
            ids = PCI_ID_RE.findall(description)
            # Drop generic class IDs ([0280]) and revision suffixes, then the
            # "Network controller:" prefix, so the vendor is at the start.
            clean = re.sub(r"\[[0-9a-fA-F]{4}\]", "", description)
            clean = re.sub(r"\s*\(rev [^)]*\)", "", clean).strip(" :")
            if ":" in clean:
                class_part, _, rest = clean.partition(":")
                if NETWORK_WORDS.search(class_part) and rest.strip():
                    clean = rest.strip()
            vendor, device = _split_vendor(clean)
            current = AdapterInfo(
                name=clean or description,
                vendor=vendor,
                device=device or None,
                bus="pci",
                slot=slot,
                pci_ids=f"{ids[0][0]}:{ids[0][1]}" if ids else None,
                source="lspci -nnk",
            )
            adapters.append(current)
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("Subsystem:"):
            current.subsystem = stripped.split(":", 1)[1].strip() or None
        elif stripped.startswith("Kernel driver in use:"):
            current.driver = stripped.split(":", 1)[1].strip() or None
        elif stripped.startswith("Kernel modules:"):
            current.kernel_modules = stripped.split(":", 1)[1].strip() or None
    return adapters


def parse_lsusb(text: str) -> list[AdapterInfo]:
    """Parse ``lsusb`` output, keeping only likely network adapters."""
    adapters: list[AdapterInfo] = []
    for line in text.splitlines():
        match = USB_LINE_RE.match(line.strip())
        if not match or not NETWORK_WORDS.search(match.group(3)):
            continue
        description = match.group(3).strip()
        vendor, device = _split_vendor(description)
        adapters.append(
            AdapterInfo(
                name=description,
                vendor=vendor,
                device=device,
                bus="usb",
                pci_ids=f"{match.group(1)}:{match.group(2)}".upper(),
                source="lsusb",
            )
        )
    return adapters


def collect_hardware(
    runner: CommandRunner, redactor: Redactor
) -> tuple[list[AdapterInfo], list[CommandIssue], dict[str, bool]]:
    """Collect adapter inventory. Missing tools are reported, not fatal."""
    issues: list[CommandIssue] = []
    utilities = {"lspci": runner.has("lspci"), "lsusb": runner.has("lsusb")}
    adapters: list[AdapterInfo] = []

    if utilities["lspci"]:
        result = runner.run(["lspci", "-nnk"])
        if result.ok:
            adapters.extend(parse_lspci_nnk(result.stdout))
        else:
            issues.append(_issue(result, redactor, "lspci -nnk"))
    if utilities["lsusb"]:
        result = runner.run(["lsusb"])
        if result.ok:
            adapters.extend(parse_lsusb(result.stdout))
        else:
            issues.append(_issue(result, redactor, "lsusb"))

    seen: set[tuple[str | None, str]] = set()
    unique: list[AdapterInfo] = []
    for adapter in adapters:
        key = (adapter.pci_ids, adapter.name.casefold())
        if key not in seen:
            seen.add(key)
            unique.append(adapter)
    return unique, issues, utilities


def parse_ethtool(text: str) -> dict[str, str]:
    """Parse the simple ``key: value`` lines of ``ethtool -i`` output."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip().lower()] = value.strip()
    return result


def parse_modinfo(text: str, limit: int = 8) -> dict[str, str]:
    """Parse a few safe fields from ``modinfo`` output."""
    wanted = {"version", "description", "license", "author", "alias"}
    result: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key in wanted and key not in result:
            result[key] = value.strip()[:200]
        if len(result) >= limit:
            break
    return result


def collect_drivers(
    runner: CommandRunner,
    redactor: Redactor,
    interfaces: list[InterfaceInfo],
    sysfs_root: Path | str = "/sys",
) -> tuple[list[DriverInfo], list[CommandIssue], dict[str, bool]]:
    """Collect driver/firmware details for wireless interfaces only."""
    issues: list[CommandIssue] = []
    utilities = {"ethtool": runner.has("ethtool"), "modinfo": runner.has("modinfo")}
    drivers: list[DriverInfo] = []
    for interface in interfaces:
        if not interface.is_wireless:
            continue
        try:
            name = validate_ifname(interface.name)
        except ValueError:
            continue
        info = DriverInfo(interface=name)
        if utilities["ethtool"]:
            result = runner.run(["ethtool", "-i", name])
            if result.ok:
                fields = parse_ethtool(result.stdout)
                info.driver = fields.get("driver") or None
                info.version = fields.get("version") or None
                info.firmware_version = fields.get("firmware-version") or None
                info.bus_info = fields.get("bus-info") or None
                if info.driver:
                    info.source = "ethtool -i"
            else:
                issues.append(_issue(result, redactor, f"ethtool -i {name}"))
        if not info.driver:
            info.driver = safe_readlink(
                Path(sysfs_root) / "class" / "net" / name / "device" / "driver"
            )
            if info.driver:
                info.source = "sysfs"
        if info.driver and utilities["modinfo"]:
            result = runner.run(["modinfo", info.driver])
            if result.ok:
                fields = parse_modinfo(result.stdout)
                info.version = info.version or fields.get("version")
                info.description = fields.get("description")
                info.license = fields.get("license")
            else:
                issues.append(_issue(result, redactor, f"modinfo {info.driver}"))
        drivers.append(info)
    return drivers, issues, utilities
