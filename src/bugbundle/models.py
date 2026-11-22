"""Data structures shared by collectors and reporters.

Collectors fill these structures with *already redacted* values where the
value itself is sensitive (MAC addresses, IP addresses, home paths, SSIDs).
The reporters apply a second, idempotent redaction pass as a safety net.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one non-shell subprocess invocation."""

    argv: tuple[str, ...]
    ok: bool = False
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    duration_ms: int = 0

    @property
    def command(self) -> str:
        """Return the executable name (never the whole command line)."""
        return self.argv[0] if self.argv else ""


@dataclass
class CommandIssue:
    """A command that could not be used during collection."""

    command: str
    error: str
    detail: str = ""
    exit_code: int | None = None


@dataclass
class AddressInfo:
    family: str
    address: str
    prefixlen: int | None = None
    scope: str | None = None


@dataclass
class InterfaceInfo:
    name: str
    ifindex: int | None = None
    link_type: str | None = None
    operstate: str | None = None
    mtu: int | None = None
    mac: str | None = None
    flags: list[str] = field(default_factory=list)
    is_wireless: bool = False
    is_up: bool = False
    has_carrier: bool = False
    addresses: list[AddressInfo] = field(default_factory=list)
    driver: str | None = None


@dataclass
class WirelessDevice:
    interface: str
    phy: str | None = None
    interface_type: str | None = None
    channel: int | None = None
    frequency_mhz: int | None = None
    channel_width: str | None = None
    txpower_dbm: float | None = None
    address: str | None = None


@dataclass
class RadioStatus:
    available: bool = False
    source: str = "unavailable"
    soft_blocked: bool | None = None
    hard_blocked: bool | None = None
    wlan_devices: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ServiceState:
    name: str
    available: bool = False
    state: str = "unknown"
    detail: str = ""


@dataclass
class NMDevice:
    device: str
    device_type: str
    state: str
    connection_redacted: bool = False


@dataclass
class NetworkServices:
    network_manager: ServiceState = field(
        default_factory=lambda: ServiceState("NetworkManager")
    )
    iwd: ServiceState = field(default_factory=lambda: ServiceState("iwd"))
    systemd_networkd: ServiceState = field(
        default_factory=lambda: ServiceState("systemd-networkd")
    )
    nm_available: bool = False
    nm_running: bool | None = None
    nm_state: str | None = None
    nm_devices: list[NMDevice] = field(default_factory=list)
    wifi_radio: str = "unknown"
    iwctl_available: bool = False
    iwd_stations: list[str] = field(default_factory=list)


@dataclass
class AdapterInfo:
    name: str
    vendor: str | None = None
    device: str | None = None
    bus: str | None = None
    slot: str | None = None
    pci_ids: str | None = None
    subsystem: str | None = None
    driver: str | None = None
    kernel_modules: str | None = None
    source: str = "unknown"


@dataclass
class DriverInfo:
    interface: str
    driver: str | None = None
    version: str | None = None
    firmware_version: str | None = None
    bus_info: str | None = None
    description: str | None = None
    license: str | None = None
    source: str = "unavailable"


@dataclass
class Finding:
    """An observation, explicitly labelled confirmed or possible."""

    status: str  # "confirmed" | "possible"
    severity: str  # "info" | "warning" | "error"
    category: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class RouteInfo:
    destination: str
    device: str | None = None
    gateway: str | None = None
    metric: int | None = None
    protocol: str | None = None
    source_ip: str | None = None


@dataclass
class Report:
    module: str
    generated_at: str
    tool_version: str
    system: dict[str, Any]
    interfaces: list[InterfaceInfo]
    wireless_devices: list[WirelessDevice]
    radio: RadioStatus
    services: NetworkServices
    adapters: list[AdapterInfo]
    drivers: list[DriverInfo]
    utilities: dict[str, bool]
    default_routes: list[RouteInfo]
    findings: list[Finding]
    command_issues: list[CommandIssue]
    logs: dict[str, Any] | None
    privacy: dict[str, Any]
