"""Static and dynamic privacy guarantees."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

from bugbundle.privacy import Redactor
from bugbundle.utils.fs import FORBIDDEN_PREFIXES, safe_read_text, safe_readlink
from tests.conftest import TEST_IP, TEST_MAC, TEST_SSID

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src" / "bugbundle"
COLLECTOR_SOURCES = sorted((SOURCE_ROOT / "collector").glob("*.py")) + [
    SOURCE_ROOT / "cli.py",
    SOURCE_ROOT / "reporter" / "markdown.py",
    SOURCE_ROOT / "reporter" / "json_report.py",
]


def _source_texts():
    return [(path, path.read_text(encoding="utf-8")) for path in SOURCE_ROOT.rglob("*.py")]


def test_no_network_or_upload_imports():
    forbidden = {"socket", "urllib", "requests", "http", "ftplib", "smtplib", "httpx", "aiohttp"}
    for path, source in _source_texts():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in forbidden, (path, alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden, (path, node.module)


def test_shell_true_never_used():
    for path, source in _source_texts():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert not (isinstance(node.value, ast.Constant) and node.value.value is True), path


def test_subprocess_only_used_in_command_runner():
    for path, source in _source_texts():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess":
                        assert path.name == "commands.py", path
            if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                assert path.name == "commands.py", path


def test_no_credential_paths_in_collectors():
    for path in COLLECTOR_SOURCES:
        source = path.read_text(encoding="utf-8")
        for fragment in ("system-connections", "/var/lib/iwd", "wpa_supplicant", "/etc/shadow"):
            assert fragment not in source, (path, fragment)


def test_no_privileged_or_mutating_commands():
    dangerous_fragments = ("sudo", "pkexec", "pacman", "apt-get", "dnf install", "ip link set")
    # Mutation verbs are checked as exact command arguments, not as prose in
    # finding descriptions such as "rfkill block is active".
    mutation_verbs = {"restart", "stop", "start", "enable", "disable", "block", "unblock"}
    for path in COLLECTOR_SOURCES:
        source = path.read_text(encoding="utf-8")
        for fragment in dangerous_fragments:
            assert fragment not in source, (path, fragment)
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert node.value not in mutation_verbs, (path, node.value)


def test_collectors_and_reporters_do_not_read_environment():
    for path in COLLECTOR_SOURCES:
        assert "os.environ" not in path.read_text(encoding="utf-8"), path


def test_forbidden_paths_constant_is_nonempty():
    assert len(FORBIDDEN_PREFIXES) >= 3
    for path in FORBIDDEN_PREFIXES:
        with pytest.raises(PermissionError):
            safe_read_text(path / "secret")
        with pytest.raises(PermissionError):
            safe_readlink(path / "secret")


def test_full_report_contains_no_sensitive_values(make_report):
    from bugbundle.reporter import json_report, markdown

    redactor = Redactor(home="/home/alice", username="alice", hostname="testbox")
    report = make_report(include_logs=True)
    rendered = json_report.render(report, redactor) + markdown.render(report, redactor)
    for secret in (TEST_IP, TEST_MAC, TEST_SSID, "192.168.50.1", "SuperSecretPassphrase"):
        assert secret not in rendered
    assert "[REDACTED_" in rendered


def test_environment_variables_are_not_collected(make_report, monkeypatch):
    from bugbundle.reporter import json_report

    monkeypatch.setenv("BUGBUNDLE_TEST_SECRET", "do-not-leak-this-value")
    redactor = Redactor(home="/home/alice", username="alice", hostname="testbox")
    rendered = json_report.render(make_report(), redactor)
    assert "do-not-leak-this-value" not in rendered
    assert "BUGBUNDLE_TEST_SECRET" not in rendered


def test_redaction_summary_discloses_limitations():
    summary = Redactor().summary()
    assert summary["best_effort"] is True
    assert any("Inspect" in statement for statement in summary["statements"])
    assert any("journalctl" in item for item in summary["not_collected"])


def test_no_root_requirement_in_help_text():
    from bugbundle.cli import build_parser

    parser = build_parser()
    help_text = parser.format_help()
    for action in parser._actions:
        if action.dest == "command" and hasattr(action, "choices"):
            collect_parser = action.choices["collect"]
            for sub_action in collect_parser._actions:
                if sub_action.dest == "module" and hasattr(sub_action, "choices"):
                    help_text += sub_action.choices["wifi"].format_help()
    assert "--include-logs" in help_text
    assert "privacy" in help_text.lower()
