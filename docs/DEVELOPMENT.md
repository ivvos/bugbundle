# Development guide

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m pytest
```

Python 3.10+ is supported. The runtime has no third-party dependencies; pytest
is a development dependency only.

## Layout

```
src/bugbundle/
  cli.py                 argparse CLI and preview/confirmation
  models.py              report dataclasses
  collector/             one module per data source + wifi orchestration
  privacy/redactor.py    redaction engine
  reporter/              shared payload finalisation, markdown, json
  utils/commands.py      safe subprocess wrapper
  utils/fs.py            guarded file reads
tests/                   pytest suite with scripted command outputs
docs/                    architecture, privacy, development
```

## Testing approach

- `tests/conftest.py` defines `FakeRunner`, which implements `has()`, `run()`
  and `run_json()` exactly like `CommandRunner`, plus deterministic fixtures
  for `ip`, `iw`, `rfkill`, `nmcli`, `lspci`, `ethtool` and journal output.
- Parsers are pure functions, so they are tested with fixture strings.
- `CommandRunner` itself is tested with real, harmless subprocesses (`echo`,
  `false`, `sleep` with a tiny timeout) and with `monkeypatch` to assert
  `shell=False` and a minimal environment.
- `tests/test_privacy.py` statically checks the source tree for network
  imports, `shell=True`, privileged commands and credential paths.

Tests must not depend on the host's interfaces or installed tools.

## Adding a diagnostic module

1. Add a collector under `src/bugbundle/collector/` that returns dataclasses
   from `models.py` and a list of `CommandIssue` objects. Use `CommandRunner`
   only; never import `subprocess` or read network-command output directly.
2. Redact sensitive values as you collect them. If a value is an SSID, register
   it with `redactor.register_secret(value, "ssid", scope="logs")`.
3. Add pure parser functions and tests with mocked output, including a test for
   missing commands, a timeout and malformed output.
4. Wire the collector into a new orchestration function (for example
   `collect_audio_report`) and add a CLI subcommand in `cli.py`.
5. Extend the shared payload in `reporter/__init__.py` and the Markdown
   renderer so both formats always agree.
6. Register the module in `bugbundle modules`.

## Adding a redaction rule

Add a regex/helper in `privacy/redactor.py`, increment the category through
`_hit()`, and add tests for: a positive case, a negative case (a value that
must survive), and idempotence (`redact(redact(x)) == redact(x)`).

## Roadmap (not in v0.1)

Audio (PipeWire/PulseAudio/ALSA), Bluetooth, display/GPU, boot/systemd,
storage and USB modules. The collector/reporter split and the `modules` command
are designed for this extension.

## Release checklist

- `python -m pytest` passes
- `python -m bugbundle collect wifi --stdout --format json` works on Arch Linux
- `python -m bugbundle collect wifi --include-logs --stdout` leaks no secrets
- README, privacy policy and limitations are updated
