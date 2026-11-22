"""Privacy redaction guarantees at the unit level."""

from __future__ import annotations

import pytest

from bugbundle.privacy import Redactor
from tests.conftest import (
    TEST_HOME,
    TEST_HOST,
    TEST_IP,
    TEST_IPV6,
    TEST_MAC,
    TEST_SSID,
    TEST_USER,
)


@pytest.fixture
def redactor() -> Redactor:
    return Redactor(home="/home/alice", username=TEST_USER, hostname=TEST_HOST)


def test_mac_is_redacted_but_oui_is_preserved(redactor):
    assert redactor.redact_text(f"addr {TEST_MAC}") == "addr aa:bb:cc:xx:xx:xx"
    assert redactor.redact_text("AA-BB-CC-11-22-33") == "AA-BB-CC-xx-xx-xx"
    assert "11:22:33" not in redactor.redact_text(TEST_MAC)


def test_mac_redaction_is_idempotent(redactor):
    once = redactor.redact_text(TEST_MAC)
    assert redactor.redact_text(once) == once


def test_ipv4_and_cidr_are_redacted(redactor):
    assert redactor.redact_text(TEST_IP) == "[REDACTED_IPV4]"
    assert redactor.redact_text(f"{TEST_IP}/24") == "[REDACTED_IPV4]/24"
    assert "192.168.50" not in redactor.redact_text(TEST_IP)


def test_loopback_and_invalid_ipv4_are_untouched(redactor):
    assert redactor.redact_text("127.0.0.1") == "127.0.0.1"
    assert redactor.redact_text("999.1.2.3") == "999.1.2.3"


def test_ipv6_is_redacted_but_loopback_kept(redactor):
    assert redactor.redact_text(TEST_IPV6) == "[REDACTED_IPV6]"
    assert redactor.redact_text("::1") == "::1"
    assert "1234:5678" not in redactor.redact_text(TEST_IPV6)


def test_known_ssid_is_redacted_in_logs_only(redactor):
    redactor.register_secret(TEST_SSID, "ssid", scope="logs")
    assert redactor.redact_text(f"connected to {TEST_SSID}", scope="logs") == (
        f"connected to [REDACTED_SSID]"
    )
    assert redactor.redact_text(TEST_SSID) == TEST_SSID


def test_home_directory_is_redacted(redactor):
    redacted = redactor.redact_text(f"config in {TEST_HOME}/.config/wifi")
    assert "/home/alice" not in redacted
    assert "[REDACTED_" in redacted
    assert redactor.redact_text("/root/.ssh/id_rsa") == "[REDACTED_HOME]/.ssh/id_rsa"


def test_username_and_hostname_are_redacted(redactor):
    assert redactor.redact_text(f"user {TEST_USER} on {TEST_HOST}") == (
        "user [REDACTED_USER] on [REDACTED_HOST]"
    )


def test_secret_assignments_are_redacted(redactor):
    text = "wifi-sec.psk=SuperSecret psk: 'another' password=abc123"
    redacted = redactor.redact_text(text)
    assert "SuperSecret" not in redacted
    assert "another" not in redacted
    assert "abc123" not in redacted
    assert redact_twice(redactor, redacted) == redacted


def test_email_and_ansi_are_handled(redactor):
    assert redactor.redact_text("mail alice@example.com") == "mail [REDACTED_EMAIL]"
    assert "\x1b" not in redactor.redact_text("\x1b[31mred\x1b[0m")


def test_structured_redaction_walks_nested_data(redactor):
    data = {"a": [{"ip": TEST_IP, "mac": TEST_MAC}, "nested"], "b": 7}
    result = redactor.redact_structured(data)
    assert result["a"][0]["ip"] == "[REDACTED_IPV4]"
    assert result["a"][0]["mac"] == "aa:bb:cc:xx:xx:xx"
    assert result["b"] == 7


def test_summary_reports_redaction_counts(redactor):
    redactor.redact_text(f"{TEST_IP} {TEST_MAC}")
    summary = redactor.summary()
    assert summary["best_effort"] is True
    assert summary["redacted_values"]["ipv4"] >= 1
    assert summary["redacted_values"]["mac"] >= 1
    assert "Wi-Fi passwords / PSKs" in summary["not_collected"]


def redact_twice(redactor, value):
    return redactor.redact_text(value)
