"""Network interface and routing discovery using ``ip`` and sysfs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import AddressInfo, CommandIssue, CommandResult, InterfaceInfo, RouteInfo
from ..privacy import Redactor
from ..utils.commands import CommandRunner
from ..utils.fs import safe_readlink

RELEVANT_FLAGS = ("UP", "LOWER_UP", "RUNNING", "NO-CARRIER", "BROADCAST", "MULTICAST", "DORMANT")


def is_wireless(sysfs_root: Path | str, ifname: str) -> bool:
    """Detect 802.11 interfaces from sysfs markers (no commands required)."""
    base = Path(sysfs_root) / "class" / "net" / ifname
    return (base / "wireless").exists() or (base / "phy80211").exists()


def _issue(result: CommandResult, redactor: Redactor, command: str) -> CommandIssue:
    detail = redactor.redact_text(result.stderr)[:300]
    return CommandIssue(
        command=command,
        error=result.error or "unknown",
        detail=detail,
        exit_code=result.exit_code,
    )


def parse_addr_payload(
    payload: Any,
    redactor: Redactor,
    sysfs_root: Path | str = "/sys",
    wireless_names: set[str] | None = None,
) -> list[InterfaceInfo]:
    """Convert ``ip -j addr show`` JSON into redacted InterfaceInfo objects."""
    if not isinstance(payload, list):
        return []
    names = wireless_names or set()
    interfaces: list[InterfaceInfo] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = item.get("ifname")
        if not isinstance(name, str) or not name:
            continue
        flags = [str(flag) for flag in item.get("flags", []) if isinstance(flag, str)]
        raw_addresses = item.get("addr_info", [])
        addresses: list[AddressInfo] = []
        if isinstance(raw_addresses, list):
            for address in raw_addresses:
                if not isinstance(address, dict):
                    continue
                family = address.get("family")
                raw_ip = address.get("local")
                if not isinstance(family, str) or not isinstance(raw_ip, str):
                    continue
                prefix = address.get("prefixlen")
                addresses.append(
                    AddressInfo(
                        family=family,
                        address=redactor.redact_text(raw_ip),
                        prefixlen=int(prefix) if isinstance(prefix, int) else None,
                        scope=str(address.get("scope")) if address.get("scope") else None,
                    )
                )
        interfaces.append(
            InterfaceInfo(
                name=name,
                ifindex=int(item["ifindex"]) if isinstance(item.get("ifindex"), int) else None,
                link_type=str(item["link_type"]) if item.get("link_type") else None,
                operstate=str(item["operstate"]) if item.get("operstate") else None,
                mtu=int(item["mtu"]) if isinstance(item.get("mtu"), int) else None,
                mac=redactor.redact_text(item["address"]) if item.get("address") else None,
                flags=[flag for flag in flags if flag in RELEVANT_FLAGS],
                is_wireless=is_wireless(sysfs_root, name) or name in names,
                is_up="UP" in flags,
                has_carrier="LOWER_UP" in flags and item.get("operstate") != "DOWN",
                addresses=addresses,
                driver=safe_readlink(Path(sysfs_root) / "class" / "net" / name / "device" / "driver"),
            )
        )
    return interfaces


def parse_routes(payload: Any, redactor: Redactor) -> list[RouteInfo]:
    """Convert ``ip -j route show`` JSON into redacted RouteInfo objects."""
    if not isinstance(payload, list):
        return []
    routes: list[RouteInfo] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        destination = item.get("dst")
        if not isinstance(destination, str):
            continue
        gateway = item.get("gateway")
        source = item.get("prefsrc")
        metric = item.get("metric")
        routes.append(
            RouteInfo(
                destination=destination,
                device=str(item["dev"]) if item.get("dev") else None,
                gateway=redactor.redact_text(gateway) if gateway else None,
                metric=int(metric) if isinstance(metric, int) else None,
                protocol=str(item["protocol"]) if item.get("protocol") else None,
                source_ip=redactor.redact_text(source) if source else None,
            )
        )
    return routes


def collect_network(
    runner: CommandRunner,
    redactor: Redactor,
    sysfs_root: Path | str = "/sys",
    wireless_names: set[str] | None = None,
) -> tuple[list[InterfaceInfo], list[RouteInfo], list[CommandIssue], dict[str, bool]]:
    """Collect interfaces and routes. Missing commands produce issues, not crashes."""
    issues: list[CommandIssue] = []
    utilities: dict[str, bool] = {"ip": runner.has("ip")}
    interfaces: list[InterfaceInfo] = []
    routes: list[RouteInfo] = []

    if not utilities["ip"]:
        issues.append(
            CommandIssue(command="ip", error="not_found", detail="interface and route data unavailable")
        )
        return interfaces, routes, issues, utilities

    payload, result = runner.run_json(["ip", "-j", "addr", "show"])
    if not result.ok or payload is None:
        issues.append(_issue(result, redactor, "ip -j addr show"))
    else:
        interfaces = parse_addr_payload(payload, redactor, sysfs_root, wireless_names)

    route_payload, route_result = runner.run_json(["ip", "-j", "route", "show"])
    if not route_result.ok or route_payload is None:
        issues.append(_issue(route_result, redactor, "ip -j route show"))
    else:
        routes = parse_routes(route_payload, redactor)

    return interfaces, routes, issues, utilities
