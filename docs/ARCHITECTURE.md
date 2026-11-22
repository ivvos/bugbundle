# Technical architecture (v0.1)

## Flow

```
CLI (argparse)
  -> Redactor (register host/user/home/SSID context)
  -> collect_wifi_report()
       -> independent collectors: system, network, wireless, hardware, logs
       -> findings analyzer
  -> Report (dataclasses)
  -> finalize_payload()  [final redaction pass + SHA-256 fingerprint]
  -> Markdown or JSON renderer
  -> preview -> user confirmation -> local file / stdout
```

There is no network layer and no upload path.

## Modules

| Path | Responsibility |
| --- | --- |
| `cli.py` | Argument parsing, preview/confirmation, file output |
| `models.py` | Dataclasses for all collected data and findings |
| `utils/commands.py` | Allow-listed, timeout-bounded, non-shell subprocess execution |
| `utils/fs.py` | Small-file reads with forbidden credential paths |
| `privacy/redactor.py` | Pattern redaction, registered secrets, audit summary |
| `collector/system.py` | os-release / kernel / architecture |
| `collector/network.py` | `ip -j addr/route`, sysfs wireless detection |
| `collector/wireless.py` | `iw dev`, rfkill, nmcli, iwd |
| `collector/hardware.py` | lspci, lsusb, ethtool, modinfo, sysfs drivers |
| `collector/logs.py` | Opt-in journalctl excerpts only |
| `collector/findings.py` | Confirmed/possible finding rules |
| `collector/wifi.py` | Orchestration of the above |
| `reporter/*` | Shared payload finalisation, Markdown and JSON rendering |

## Data structures

All collector output is made of plain dataclasses in `models.py`:
`InterfaceInfo`, `AddressInfo`, `RouteInfo`, `WirelessDevice`, `RadioStatus`,
`ServiceState`, `NMDevice`, `NetworkServices`, `AdapterInfo`, `DriverInfo`,
`Finding`, `CommandIssue` and `Report`.

`CommandResult` is immutable and records exit code, error class, duration and
captured output. Failures are values, never exceptions crossing collector
boundaries.

## Privacy boundary

1. Collectors redact sensitive values *at the point of collection*.
2. Registered values (SSIDs from nmcli connection names, hostname, username,
   home path) are scrubbed in their declared scope. SSIDs are scoped to logs so
   an SSID equal to the distribution name cannot corrupt system fields.
3. `finalize_payload()` runs a second recursive redaction pass on the complete
   report, then computes a SHA-256 fingerprint over the canonical redacted
   payload.
4. The redactor is cloned for rendering so repeated renders are identical.

## Command execution boundary

Every command is a list passed to `subprocess.run(..., shell=False)`. The
executable must appear in `ALLOWED_COMMANDS`; PATH, locale and (optionally)
XDG_RUNTIME_DIR are the only environment values passed. No collector ever
imports `subprocess` directly. Interface names are validated before being used
as arguments.

## Reliability

- Each collector catches missing tools, timeouts, permission errors, invalid
  JSON and malformed output, returning a `CommandIssue` instead of crashing.
- Output is capped (200k characters per command, 120 log lines per unit).
- Parsers are pure functions with scripted fixtures in `tests/conftest.py`, so
  tests never read the host's real network state.
