"""CommandRunner safety and failure handling."""

from __future__ import annotations

import subprocess
from dataclasses import replace

from bugbundle.utils.commands import CommandRunner


def test_never_uses_shell_and_minimal_env(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(kwargs)
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = CommandRunner(allowed={"ip"}, env={"PATH": "/usr/bin", "LC_ALL": "C"})
    result = runner.run(["ip", "addr"])

    assert result.ok and result.stdout == "ok"
    assert captured["shell"] is False
    assert captured["check"] is False
    assert captured["capture_output"] is True
    assert captured["argv"] == ["ip", "addr"]
    assert "PYTHONPATH" not in captured["env"]


def test_blocked_command_is_not_executed(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("shell ran"))
    )
    runner = CommandRunner(allowed={"ip"})
    result = runner.run(["rm", "-rf", "/tmp/bugbundle-should-not-exist"])
    assert result.error == "blocked_command"
    assert result.exit_code is None


def test_missing_command_returns_not_found():
    runner = CommandRunner(allowed={"bugbundle_missing_executable_xyz"})
    result = runner.run(["bugbundle_missing_executable_xyz"])
    assert result.error == "not_found"


def test_real_timeout_is_captured_as_data():
    runner = CommandRunner(timeout=0.05, allowed={"sleep"})
    result = runner.run(["sleep", "1"])
    assert result.error == "timeout"
    assert not result.ok
    assert "timed out" in result.stderr


def test_nonzero_exit_is_captured():
    runner = CommandRunner(allowed={"false"})
    result = runner.run(["false"])
    assert result.error == "nonzero_exit"
    assert result.exit_code == 1


def test_run_json_parses_valid_json():
    runner = CommandRunner(allowed={"echo"})
    data, result = runner.run_json(["echo", '{"ok": true}'])
    assert data == {"ok": True}
    assert result.ok


def test_run_json_reports_invalid_json():
    runner = CommandRunner(allowed={"echo"})
    data, result = runner.run_json(["echo", "not json"])
    assert data is None
    assert result.error == "invalid_json"


def test_invalid_argv_is_rejected():
    runner = CommandRunner()
    assert runner.run([]).error == "invalid_command"
    assert runner.run(["ip", ""]).error == "invalid_command"
    assert runner.run(["ip\x00"]).error == "invalid_command"


def test_has_respects_allowlist():
    runner = CommandRunner(allowed={"ip"})
    assert runner.has("ip")
    assert not runner.has("journalctl")


def test_timeout_result_can_be_replaced():
    from bugbundle.models import CommandResult

    original = CommandResult(("ip",), error="timeout")
    changed = replace(original, error="fixed")
    assert changed.error == "fixed" and original.error == "timeout"
