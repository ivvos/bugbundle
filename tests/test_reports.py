"""Markdown and JSON report generation."""

from __future__ import annotations

import json

from bugbundle.reporter import json_report, markdown
from tests.conftest import (
    TEST_HOST,
    TEST_IP,
    TEST_MAC,
    TEST_SSID,
    TEST_USER,
)

SECTIONS = [
    "## 1. Report metadata",
    "## 2. System information",
    "## 3. Network interfaces",
    "## 4. Wireless adapter information",
    "## 5. Driver information",
    "## 6. Network service status",
    "## 7. Diagnostic findings",
    "## 8. Command execution issues",
    "## 9. Privacy and redaction summary",
]


def assert_no_secrets(text: str) -> None:
    for secret in (TEST_IP, TEST_MAC, TEST_SSID, TEST_HOST, TEST_USER, "192.168.50.1"):
        assert secret not in text, f"leaked {secret!r}"


def test_markdown_report_structure(make_report, redactor):
    text = markdown.render(make_report(), redactor)
    for section in SECTIONS:
        assert section in text
    assert "Confirmed findings" in text
    assert "Possible causes" in text
    assert "Report fingerprint (SHA-256)" in text
    assert "| wlp2s0 |" in text
    assert "iwlwifi" in text
    assert "best-effort" in text.lower()
    assert_no_secrets(text)


def test_markdown_has_no_logs_section_without_opt_in(make_report, redactor):
    text = markdown.render(make_report(), redactor)
    assert "## 10. Optional logs" not in text
    assert "Logs were not included" in text


def test_json_report_structure(make_report, redactor):
    payload = json.loads(json_report.render(make_report(), redactor))
    assert payload["schema_version"] == "1.0"
    assert payload["metadata"]["module"] == "wifi"
    assert payload["logs"] is None
    assert payload["privacy"]["logs_included"] is False
    assert payload["privacy"]["redaction_summary"]["best_effort"] is True
    assert len(payload["integrity"]["sha256"]) == 64
    assert [i["name"] for i in payload["network"]["interfaces"]][0] == "lo"
    assert payload["wireless"]["devices"][0]["channel"] == 6
    assert_no_secrets(json.dumps(payload))


def test_optional_logs_appear_in_both_formats(make_report, redactor):
    report = make_report(include_logs=True)
    text = markdown.render(report, redactor)
    payload = json.loads(json_report.render(report, redactor))
    assert "## 10. Optional logs (explicitly opted in)" in text
    assert "NetworkManager" in text
    assert payload["logs"]["included"] is True
    assert payload["privacy"]["logs_included"] is True
    assert payload["logs"]["units"]["NetworkManager"]["line_count"] > 0
    assert_no_secrets(text)
    assert_no_secrets(json.dumps(payload))


def test_findings_are_separated_by_status(make_report, redactor):
    payload = json.loads(json_report.render(make_report(), redactor))
    statuses = {finding["status"] for finding in payload["diagnostics"]["findings"]}
    assert statuses <= {"confirmed", "possible"}
    assert "confirmed" in statuses
    assert "possible" in statuses
    assert all("detail" in finding for finding in payload["diagnostics"]["findings"])


def test_rendering_twice_is_deterministic(make_report, redactor):
    report = make_report()
    first = json_report.render(report, redactor)
    second = json_report.render(report, redactor)
    assert first == second
    assert json.loads(first)["integrity"]["sha256"] == json.loads(second)["integrity"]["sha256"]


def test_fingerprint_changes_with_content(make_report, redactor):
    first = json.loads(json_report.render(make_report(), redactor))
    second = json.loads(json_report.render(make_report(include_logs=True), redactor))
    assert first["integrity"]["sha256"] != second["integrity"]["sha256"]
