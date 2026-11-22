"""Hardware and driver collection."""

from __future__ import annotations

import pytest

from bugbundle.collector.hardware import (
    collect_drivers,
    collect_hardware,
    parse_ethtool,
    parse_lspci_nnk,
    parse_lsusb,
    parse_modinfo,
)
from bugbundle.models import InterfaceInfo
from bugbundle.utils.fs import ForbiddenPathError, safe_read_text, validate_ifname
from tests.conftest import (
    ETHTOOL_OUTPUT,
    LSPCI_OUTPUT,
    LSUSB_OUTPUT,
    MODINFO_OUTPUT,
    FakeRunner,
    make_redactor,
    result,
)


def test_lspci_parsing_finds_wireless_adapter():
    adapters = parse_lspci_nnk(LSPCI_OUTPUT)
    assert len(adapters) == 2
    wifi = adapters[1]
    assert wifi.pci_ids == "8086:24f3"
    assert wifi.driver == "iwlwifi"
    assert wifi.kernel_modules == "iwlwifi"
    assert "Wireless 8260" in wifi.name
    assert wifi.vendor == "Intel Corporation"


def test_lsusb_parsing_filters_non_network_devices():
    adapters = parse_lsusb(LSUSB_OUTPUT)
    assert len(adapters) == 1
    assert "RT5372" in adapters[0].name
    assert adapters[0].bus == "usb"


def test_ethtool_and_modinfo_parsing():
    fields = parse_ethtool(ETHTOOL_OUTPUT)
    assert fields["driver"] == "iwlwifi"
    assert fields["firmware-version"].startswith("36.")
    parsed = parse_modinfo(MODINFO_OUTPUT)
    assert parsed["license"] == "GPL"
    assert "filename" not in parsed


def test_hardware_collection_handles_missing_tools():
    adapters, issues, utilities = collect_hardware(
        FakeRunner(available=set()), make_redactor()
    )
    assert adapters == [] and issues == []
    assert utilities["lspci"] is False and utilities["lsusb"] is False


def test_hardware_collection_handles_failed_command():
    runner = FakeRunner(
        {("lspci", "-nnk"): result(("lspci",), ok=False, error="permission_denied")}
    )
    adapters, issues, _ = collect_hardware(runner, make_redactor())
    assert issues[0].error == "permission_denied"
    assert any(adapter.bus == "usb" for adapter in adapters)


def test_driver_collection(sysfs_root):
    interfaces = [InterfaceInfo(name="wlp2s0", is_wireless=True)]
    drivers, issues, utilities = collect_drivers(
        FakeRunner(), make_redactor(), interfaces, sysfs_root
    )
    assert len(drivers) == 1
    assert drivers[0].driver == "iwlwifi"
    assert drivers[0].firmware_version.startswith("36.")
    assert drivers[0].source == "ethtool -i"
    assert issues == []
    assert utilities["ethtool"]


def test_driver_collection_falls_back_to_sysfs(sysfs_root):
    runner = FakeRunner(available={"modinfo"})
    interfaces = [InterfaceInfo(name="wlp2s0", is_wireless=True)]
    drivers, _, _ = collect_drivers(runner, make_redactor(), interfaces, sysfs_root)
    assert drivers[0].driver == "iwlwifi"
    assert drivers[0].source == "sysfs"
    assert ("ethtool", "-i", "wlp2s0") not in runner.calls


def test_driver_collection_skips_wired_interfaces(sysfs_root):
    runner = FakeRunner()
    drivers, _, _ = collect_drivers(
        runner, make_redactor(), [InterfaceInfo(name="enp1s0", is_wireless=False)], sysfs_root
    )
    assert drivers == []
    assert runner.calls == []


@pytest.mark.parametrize("name", ["wlp2s0; rm -rf /", "", "../etc/passwd", "a" * 70])
def test_invalid_interface_name_rejected(name):
    with pytest.raises(ValueError):
        validate_ifname(name)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/NetworkManager/system-connections/MyWifi.nmconnection",
        "/var/lib/iwd/home.psk",
        "/etc/wpa_supplicant/wpa_supplicant.conf",
    ],
)
def test_secret_paths_are_refused(path):
    with pytest.raises(ForbiddenPathError):
        safe_read_text(path)
