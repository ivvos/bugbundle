"""CLI behaviour and end-to-end smoke tests."""

from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from bugbundle.cli import main
from tests.conftest import JOURNAL_CMD, FakeRunner, make_redactor

SRC = Path(__file__).resolve().parents[1] / "src"


def _module(*args):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    return subprocess.run(
        [sys.executable, "-m", "bugbundle", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )


def test_module_version_and_modules_command():
    version = _module("--version")
    assert version.returncode == 0
    assert "bugbundle 0.1.0" in version.stdout

    modules = _module("modules")
    assert modules.returncode == 0
    assert "wifi" in modules.stdout
    assert "bluetooth" in modules.stdout


def test_collect_stdout_prints_valid_json():
    out = io.StringIO()
    runner = FakeRunner()
    code = main(
        ["collect", "wifi", "--stdout", "--format", "json"],
        stdout=out,
        interactive=False,
        runner=runner,
        redactor=make_redactor(),
    )
    assert code == 0
    payload = json.loads(out.getvalue())
    assert payload["metadata"]["module"] == "wifi"
    assert ("ip", "-j", "addr", "show") in runner.calls


def test_output_file_is_written_with_private_permissions(tmp_path):
    destination = tmp_path / "report.json"
    out = io.StringIO()
    code = main(
        ["collect", "wifi", "--output", str(destination), "--yes"],
        stdout=out,
        interactive=False,
        runner=FakeRunner(),
        redactor=make_redactor(),
    )
    assert code == 0
    assert destination.exists()
    assert json.loads(destination.read_text())["schema_version"] == "1.0"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert "Report preview" in out.getvalue()
    assert f"Report written to: {destination}" in out.getvalue()


def test_interactive_decline_writes_nothing(tmp_path, monkeypatch):
    destination = tmp_path / "declined.md"
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    code = main(
        ["collect", "wifi", "--output", str(destination)],
        stdout=io.StringIO(),
        interactive=True,
        runner=FakeRunner(),
        redactor=make_redactor(),
    )
    assert code == 1
    assert not destination.exists()


def test_format_is_inferred_from_output_suffix(tmp_path):
    destination = tmp_path / "inferred.json"
    code = main(
        ["collect", "wifi", "--output", str(destination), "--yes"],
        stdout=io.StringIO(),
        interactive=False,
        runner=FakeRunner(),
        redactor=make_redactor(),
    )
    assert code == 0
    assert json.loads(destination.read_text())["schema_version"] == "1.0"


def test_include_logs_flag_reaches_collector():
    runner = FakeRunner()
    code = main(
        ["collect", "wifi", "--stdout", "--format", "json", "--include-logs"],
        stdout=io.StringIO(),
        interactive=False,
        runner=runner,
        redactor=make_redactor(),
    )
    assert code == 0
    assert JOURNAL_CMD in runner.calls


def test_invalid_timeout_returns_usage_error():
    code = main(
        ["collect", "wifi", "--timeout", "0", "--stdout"],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        runner=FakeRunner(),
    )
    assert code == 2


def test_real_end_to_end_module_run():
    """Deterministic assertions only; no assumption about host network state."""
    result = _module("collect", "wifi", "--stdout", "--format", "json", "--timeout", "4")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["metadata"]["module"] == "wifi"
    assert isinstance(payload["network"]["interfaces"], list)
    assert isinstance(payload["diagnostics"]["findings"], list)
    assert payload["privacy"]["redaction_summary"]["best_effort"] is True
