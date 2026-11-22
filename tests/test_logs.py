"""Opt-in log collection and its redaction/failure handling."""

from __future__ import annotations

from bugbundle.collector.logs import collect_logs, selected_units
from tests.conftest import (
    JOURNAL_CMD,
    JOURNAL_OUTPUT,
    TEST_HOST,
    TEST_IP,
    TEST_MAC,
    TEST_SSID,
    TEST_USER,
    FakeRunner,
    make_redactor,
    result,
)


def test_logs_are_never_collected_without_opt_in():
    runner = FakeRunner()
    logs, issues, _ = collect_logs(runner, make_redactor(), _services(), False)
    assert logs is None and issues == []
    assert not any(call[0] == "journalctl" for call in runner.calls)


def test_optional_logs_are_redacted():
    runner = FakeRunner()
    redactor = make_redactor()
    # In a real run, nmcli registers the active connection name before logs
    # are collected; emulate that ordering here.
    redactor.register_secret(TEST_SSID, "ssid", scope="logs")
    logs, issues, utilities = collect_logs(runner, redactor, _services(), True)
    assert logs is not None and logs["included"]
    assert utilities["journalctl"]
    assert JOURNAL_CMD in runner.calls
    assert issues == []
    text = "\n".join(logs["units"]["NetworkManager"]["lines"])
    for secret in (TEST_IP, TEST_MAC, TEST_SSID, TEST_HOST, TEST_USER, "SuperSecretPassphrase"):
        assert secret not in text
    assert "[REDACTED_IPV4]" in text
    assert "aa:bb:cc:xx:xx:xx" in text  # OUI kept, device-specific tail removed
    assert "[REDACTED_SSID]" in text
    assert "[REDACTED_SECRET]" in text
    assert logs["time_window"]


def test_permission_and_timeout_failures_are_recorded():
    for error in ("permission_denied", "timeout"):
        runner = FakeRunner({JOURNAL_CMD: result(JOURNAL_CMD, ok=False, error=error)})
        logs, issues, _ = collect_logs(runner, make_redactor(), _services(), True)
        assert issues[0].error == error
        assert logs["units"]["NetworkManager"]["available"] is False
        assert logs["units"]["NetworkManager"]["lines"] == []


def test_units_are_selected_from_service_state():
    from bugbundle.collector.wireless import collect_services, summarize_radio

    runner = FakeRunner(
        {
            ("systemctl", "is-active", "iwd"): result(("systemctl",), "active"),
            ("iwctl", "station", "list"): result(("iwctl",), ""),
        }
    )
    services, _, _ = collect_services(runner, make_redactor(), summarize_radio([], "test"))
    assert set(selected_units(services)) == {"NetworkManager", "iwd"}


def _services():
    from bugbundle.models import NetworkServices, ServiceState

    return NetworkServices(
        network_manager=ServiceState("NetworkManager", available=True, state="active"),
        nm_available=True,
    )
