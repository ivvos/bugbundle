"""Shared fixtures: deterministic, fake command outputs.

Tests never depend on the host's actual interfaces, IPs or installed tools.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from bugbundle.collector.wifi import collect_wifi_report
from bugbundle.models import CommandResult
from bugbundle.privacy import Redactor

TEST_HOME = "/home/alice"
TEST_USER = "alice"
TEST_HOST = "testbox"
TEST_SSID = "MyHomeNetwork"
TEST_MAC = "aa:bb:cc:11:22:33"
TEST_IP = "192.168.50.23"
TEST_IPV6 = "fe80::1234:5678:9abc:def0"
JOURNAL_CMD = (
    "journalctl",
    "-u",
    "NetworkManager",
    "-n",
    "120",
    "--no-pager",
    "--since=-24h",
)

IP_ADDR_JSON = [
    {
        "ifindex": 1,
        "ifname": "lo",
        "flags": ["LOOPBACK", "UP", "LOWER_UP"],
        "mtu": 65536,
        "operstate": "UNKNOWN",
        "link_type": "loopback",
        "address": "00:00:00:00:00:00",
        "addr_info": [
            {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
            {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"},
        ],
    },
    {
        "ifindex": 2,
        "ifname": "enp1s0",
        "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"],
        "mtu": 1500,
        "operstate": "DOWN",
        "link_type": "ether",
        "address": "aa:bb:cc:44:55:66",
        "addr_info": [],
    },
    {
        "ifindex": 3,
        "ifname": "wlp2s0",
        "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        "mtu": 1500,
        "operstate": "UP",
        "link_type": "ether",
        "address": TEST_MAC,
        "addr_info": [
            {
                "family": "inet",
                "local": TEST_IP,
                "prefixlen": 24,
                "scope": "global",
                "broadcast": "192.168.50.255",
            },
            {"family": "inet6", "local": TEST_IPV6, "prefixlen": 64, "scope": "link"},
        ],
    },
]

IP_ROUTE_JSON = [
    {
        "dst": "default",
        "gateway": "192.168.50.1",
        "dev": "wlp2s0",
        "protocol": "dhcp",
        "prefsrc": TEST_IP,
        "metric": 600,
    },
    {
        "dst": "default",
        "gateway": "10.0.0.1",
        "dev": "enp1s0",
        "protocol": "dhcp",
        "prefsrc": "10.0.0.25",
        "metric": 100,
    },
    {"dst": "192.168.50.0/24", "dev": "wlp2s0", "protocol": "kernel", "scope": "link"},
]

IW_DEV_OUTPUT = """phy#0
\tUnnamed/non-netdev interface
\t\twdev 0x2
\t\taddr aa:bb:cc:11:22:33
\t\ttype P2P-device
\tInterface wlp2s0
\t\tifindex 3
\t\twdev 0x1
\t\taddr aa:bb:cc:11:22:33
\t\ttype managed
\t\tchannel 6 (2437 MHz), width: 40 MHz, center1: 2452 MHz
\t\ttxpower 22.00 dBm
"""

RFKILL_JSON = {
    "rfkilldevices": [
        {"id": 0, "type": "wlan", "device": "phy0", "soft": "unblocked", "hard": "unblocked"},
        {"id": 1, "type": "bluetooth", "device": "hci0", "soft": "blocked", "hard": "unblocked"},
    ]
}

RFKILL_TEXT = """0: phy0: Wireless LAN
\tSoft blocked: no
\tHard blocked: no
1: hci0: Bluetooth
\tSoft blocked: yes
\tHard blocked: no
"""

NMCLI_DEVICES = (
    "enp1s0:ethernet:unavailable:\n"
    f"wlp2s0:wifi:connected:{TEST_SSID}\n"
    "lo:loopback:connected (externally):lo\n"
    "50\\:49\\:B0\\:50\\:8C\\:1A:bt:disconnected:\n"
)

LSPCI_OUTPUT = """00:1f.6 Ethernet controller [0200]: Intel Corporation Ethernet Connection [8086:156f]
\tSubsystem: Lenovo Device [17aa:2245]
\tKernel driver in use: e1000e
\tKernel modules: e1000e
04:00.0 Network controller [0280]: Intel Corporation Wireless 8260 [8086:24f3] (rev 3a)
\tSubsystem: Intel Corporation Dual Band Wireless-AC 8260 [8086:0010]
\tKernel driver in use: iwlwifi
\tKernel modules: iwlwifi
"""

LSUSB_OUTPUT = (
    "Bus 001 Device 004: ID 0cf3:e300 Qualcomm Atheros QCA61x4 Bluetooth\n"
    "Bus 001 Device 007: ID 148f:5372 Ralink Technology, Corp. RT5372 Wireless Adapter\n"
)

ETHTOOL_OUTPUT = (
    "driver: iwlwifi\n"
    "version: 6.6.1\n"
    "firmware-version: 36.c8e8e144.0 8000C-36.ucode\n"
    "expansion-rom-version: \n"
    "bus-info: 0000:04:00.0\n"
)

MODINFO_OUTPUT = (
    "filename:       /lib/modules/6.6.1/kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko\n"
    "license:        GPL\n"
    "description:    Intel Wireless WiFi Next Gen AGN - Wireless-N/Advanced-N/Ultimate-N\n"
    "version:        6.6.1\n"
)

JOURNAL_OUTPUT = (
    f"2026-01-02T10:00:00+00:00 testbox NetworkManager[435]: <info> connected to {TEST_SSID}\n"
    f"2026-01-02T10:00:01+00:00 testbox NetworkManager[435]: dhcp4: address={TEST_IP}\n"
    f"2026-01-02T10:00:02+00:00 testbox NetworkManager[435]: device aa:bb:cc:11:22:33 up\n"
    f"2026-01-02T10:00:03+00:00 testbox NetworkManager[435]: psk=SuperSecretPassphrase\n"
    f"2026-01-02T10:00:04+00:00 testbox NetworkManager[435]: home {TEST_HOME}/alice.conf\n"
)


def result(
    argv,
    stdout: str = "",
    *,
    ok: bool = True,
    exit_code: int = 0,
    error: str | None = None,
    stderr: str = "",
) -> CommandResult:
    """Build a CommandResult; argv is filled in by FakeRunner."""
    return CommandResult(
        tuple(argv),
        ok=ok,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        error=error,
    )


DEFAULT_RESPONSES = {
    ("ip", "-j", "addr", "show"): result(("ip",), json.dumps(IP_ADDR_JSON)),
    ("ip", "-j", "route", "show"): result(("ip",), json.dumps(IP_ROUTE_JSON)),
    ("iw", "dev"): result(("iw",), IW_DEV_OUTPUT),
    ("iwconfig",): result(("iwconfig",), ""),
    ("rfkill", "-J"): result(("rfkill",), json.dumps(RFKILL_JSON)),
    ("rfkill", "list"): result(("rfkill",), RFKILL_TEXT),
    ("systemctl", "is-active", "NetworkManager"): result(("systemctl",), "active"),
    ("systemctl", "is-active", "iwd"): result(("systemctl",), "inactive", ok=False, exit_code=3),
    ("systemctl", "is-active", "systemd-networkd"): result(("systemctl",), "inactive", ok=False, exit_code=3),
    ("nmcli", "-t", "-f", "RUNNING,STATE", "general"): result(("nmcli",), "running:connected"),
    ("nmcli", "radio", "wifi"): result(("nmcli",), "enabled"),
    ("nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev"): result(("nmcli",), NMCLI_DEVICES),
    ("lspci", "-nnk"): result(("lspci",), LSPCI_OUTPUT),
    ("lsusb",): result(("lsusb",), LSUSB_OUTPUT),
    ("ethtool", "-i", "wlp2s0"): result(("ethtool",), ETHTOOL_OUTPUT),
    ("modinfo", "iwlwifi"): result(("modinfo",), MODINFO_OUTPUT),
    JOURNAL_CMD: result(("journalctl",), JOURNAL_OUTPUT),
}

ALL_TOOLS = {
    "ip", "iw", "iwconfig", "nmcli", "rfkill", "lspci", "lsusb",
    "ethtool", "modinfo", "systemctl", "journalctl",
}


class FakeRunner:
    """Drop-in CommandRunner replacement with scripted outputs."""

    def __init__(self, responses=None, available=None) -> None:
        self.responses = dict(DEFAULT_RESPONSES)
        if responses:
            self.responses.update(responses)
        self.available = set(ALL_TOOLS if available is None else available)
        self.calls: list[tuple[str, ...]] = []

    def has(self, command: str) -> bool:
        return command in self.available

    def run(self, argv, timeout=None) -> CommandResult:
        key = tuple(argv)
        self.calls.append(key)
        value = self.responses.get(key)
        if value is None:
            if key and Path(key[0]).name not in self.available:
                return replace(result(key, error="not_found", stderr="command not found"), argv=key)
            return replace(result(key, ok=False, error="nonzero_exit", exit_code=1), argv=key)
        return replace(value, argv=key)

    def run_json(self, argv, timeout=None):
        value = self.run(argv, timeout)
        try:
            data = json.loads(value.stdout)
        except (ValueError, TypeError):
            return None, replace(value, ok=False, error="invalid_json")
        return data, value


def make_redactor() -> Redactor:
    return Redactor(home=TEST_HOME, username=TEST_USER, hostname=TEST_HOST)


@pytest.fixture
def redactor() -> Redactor:
    return make_redactor()


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def sysfs_root(tmp_path: Path) -> Path:
    root = tmp_path / "sys"
    net = root / "class" / "net" / "wlp2s0"
    (net / "wireless").mkdir(parents=True)
    driver_dir = root / "bus" / "pci" / "drivers" / "iwlwifi"
    driver_dir.mkdir(parents=True)
    (net / "device").mkdir()
    (net / "device" / "driver").symlink_to(driver_dir)
    return root


@pytest.fixture
def make_report(sysfs_root):
    def factory(
        fake_runner: FakeRunner | None = None,
        active_redactor: Redactor | None = None,
        include_logs: bool = False,
    ):
        return collect_wifi_report(
            fake_runner or FakeRunner(),
            active_redactor or make_redactor(),
            sysfs_root=sysfs_root,
            os_release_path="/nonexistent/os-release",
            include_logs=include_logs,
        )

    return factory
