"""iw, rfkill, NetworkManager and iwd collectors."""

from __future__ import annotations

from bugbundle.collector.wireless import (
    collect_iw,
    collect_radio,
    collect_services,
    parse_iw_dev,
    parse_nmcli_devices,
    parse_rfkill_json,
    parse_rfkill_text,
    summarize_radio,
)
from tests.conftest import (
    IW_DEV_OUTPUT,
    NMCLI_DEVICES,
    RFKILL_JSON,
    RFKILL_TEXT,
    TEST_SSID,
    FakeRunner,
    make_redactor,
    result,
)


def test_iw_dev_parsing(redactor):
    devices = parse_iw_dev(IW_DEV_OUTPUT, redactor)
    assert len(devices) == 1
    device = devices[0]
    assert device.interface == "wlp2s0"
    assert device.phy == "phy#0"
    assert device.interface_type == "managed"
    assert device.channel == 6 and device.frequency_mhz == 2437
    assert device.channel_width == "40 MHz"
    assert device.txpower_dbm == 22.0
    assert device.address == "aa:bb:cc:xx:xx:xx"


def test_iw_missing_and_timeout(redactor):
    devices, issues, utilities = collect_iw(
        FakeRunner(available=set()), redactor
    )
    assert devices == [] and utilities["iw"] is False and issues == []

    runner = FakeRunner(
        {("iw", "dev"): result(("iw",), error="timeout", ok=False)},
        available={"iw"},
    )
    devices, issues, utilities = collect_iw(runner, redactor)
    assert devices == [] and issues[0].error == "timeout"


def test_rfkill_json_parsing_and_summary():
    entries = parse_rfkill_json(RFKILL_JSON)
    status = summarize_radio(entries, "rfkill -J")
    assert status.available and status.source == "rfkill -J"
    assert not status.soft_blocked and not status.hard_blocked
    assert len(status.wlan_devices) == 1


def test_rfkill_text_parsing_and_blocked_state():
    entries = parse_rfkill_text(RFKILL_TEXT)
    status = summarize_radio(entries, "rfkill list")
    assert len(entries) == 2
    assert not any(e["soft_blocked"] for e in entries if e["type"] == "Wireless LAN")
    assert any(e["soft_blocked"] for e in entries if e["type"] == "Bluetooth")

    blocked = [
        {"type": "wlan", "device": "phy0", "soft_blocked": True, "hard_blocked": False}
    ]
    assert summarize_radio(blocked, "test").soft_blocked
    hard = [
        {"type": "wlan", "device": "phy0", "soft_blocked": False, "hard_blocked": True}
    ]
    assert summarize_radio(hard, "test").hard_blocked


def test_rfkill_falls_back_to_text():
    runner = FakeRunner(
        {("rfkill", "-J"): result(("rfkill",), "not json", ok=False, error="invalid_json")},
        available={"rfkill"},
    )
    status, issues, _ = collect_radio(runner, make_redactor())
    assert status.source == "rfkill list"
    assert issues[0].error == "invalid_json"


def test_rfkill_falls_back_to_sysfs(tmp_path):
    rfkill_dir = tmp_path / "sys" / "class" / "rfkill" / "rfkill0"
    rfkill_dir.mkdir(parents=True)
    (rfkill_dir / "type").write_text("wlan")
    (rfkill_dir / "soft").write_text("1")
    (rfkill_dir / "hard").write_text("0")
    (rfkill_dir / "name").write_text("phy0")
    status, _, utilities = collect_radio(
        FakeRunner(available=set()), make_redactor(), tmp_path / "sys"
    )
    assert status.source.endswith("/sys/class/rfkill")
    assert status.soft_blocked and utilities["rfkill"] is False


def test_nmcli_devices_are_parsed_and_names_registered(redactor):
    devices = parse_nmcli_devices(NMCLI_DEVICES, redactor)
    assert [dev.device_type for dev in devices] == ["ethernet", "wifi", "loopback", "bt"]
    assert devices[3].device == "50:49:B0:50:8C:1A"
    assert devices[1].connection_redacted
    assert redactor.redact_text(f"connected to {TEST_SSID}", scope="logs") == (
        "connected to [REDACTED_SSID]"
    )
    assert TEST_SSID not in str(devices)


def test_services_without_nmcli():
    radio = summarize_radio([], "unavailable", available=False)
    services, _, utilities = collect_services(
        FakeRunner(available={"systemctl"}), make_redactor(), radio
    )
    assert utilities["nmcli"] is False
    assert services.nm_devices == []
    assert services.network_manager.state == "active"
    assert services.wifi_radio == "unknown"


def test_iwd_and_iwctl_stations():
    runner = FakeRunner(
        {
            ("systemctl", "is-active", "iwd"): result(("systemctl",), "active"),
            ("iwctl", "station", "list"): result(
                ("iwctl",), "wlp2s0  connected\np2p-dev  disconnected"
            ),
        },
        available={"systemctl", "iwctl", "nmcli", "rfkill"},
    )
    services, _, _ = collect_services(runner, make_redactor(), summarize_radio([], "test"))
    assert services.iwd.state == "active"
    assert "wlp2s0: connected" in services.iwd_stations
