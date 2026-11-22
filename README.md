# BugBundle

**Privacy-first Linux diagnostics for better bug reports.**

BugBundle is a local-only command-line tool that gathers the technical context
maintainers and support communities ask for, redacts identifying values, and
produces a clean Markdown or JSON report that you review before sharing.

> **No uploads. No passwords. No root. No system changes.**

Version 0.1 ships one module: **Wi-Fi diagnostics**.

---

## Features (v0.1)

**System information**
- Distribution name/ID/version from `/etc/os-release`
- Kernel release, architecture, Python version
- Redacted hostname

**Network information**
- Interface discovery via `ip -j addr show` and sysfs
- Wireless interface detection via sysfs and `iw dev`
- Interface state, flags, MTU, carrier and link mode
- IP addresses (IPv4/IPv6) with redacted values, prefixes and scope retained
- Default routes with redacted gateways
- Wi-Fi radio state (soft/hard block) via `rfkill` or sysfs
- NetworkManager status via `nmcli` (optional)
- iwd status via `systemctl`/`iwctl` (optional)
- systemd-networkd status (optional)
- Channel, frequency, width and TX power via `iw`

**Hardware and drivers**
- Wireless/PCI adapters via `lspci -nnk` and `lsusb`
- Driver, version, firmware version and bus info via `ethtool -i` and `modinfo`
- sysfs driver fallback

**Diagnostics**
- Utility availability and missing dependencies
- Command failures and timeouts recorded as data
- Findings explicitly split into **confirmed observations** and **possible causes**
- Optional, opt-in journal excerpts for NetworkManager / iwd / systemd-networkd
- SHA-256 fingerprint of each report payload

---

## Installation

### Arch Linux (recommended: virtual environment)

```bash
sudo pacman -S python python-pip
git clone https://github.com/ivvos/bugbundle.git
cd bugbundle
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
bugbundle --version
```

### Arch Linux (system tools only)

```bash
sudo pacman -S iproute2 iw rfkill pciutils usbutils ethtool kmod
```

BugBundle works if some of these are missing — it records the gap instead of
failing. `ip` provides the most useful baseline.

### Development install from source (any distribution)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m pytest
```

Requires Python 3.10+. There are **no runtime dependencies** outside the
standard library.

---

## Usage

```bash
# Generate a Wi-Fi report (interactive confirmation before writing)
bugbundle collect wifi

# Write to a specific file
bugbundle collect wifi --output report.md

# JSON output (format can also be inferred from a .json output path)
bugbundle collect wifi --format json
bugbundle collect wifi --output report.json

# Print the report to stdout without writing a file
bugbundle collect wifi --stdout --format json

# Include optional, redacted service logs (off by default)
bugbundle collect wifi --include-logs --output report-with-logs.md

# Skip the confirmation prompt (useful in scripts)
bugbundle collect wifi --yes --output report.md

# Change the per-command timeout (seconds)
bugbundle collect wifi --timeout 10

# Other commands
bugbundle modules
bugbundle --version
python -m bugbundle --version
```

In an interactive terminal, BugBundle prints a report preview and asks before
writing a file. When stdin is not a terminal (for example in a script), it
writes directly; use `--stdout` to avoid creating files entirely. Reports are
written with `0600` permissions.

---

## Example output

A Markdown report contains these sections:

1. Report metadata (including SHA-256 fingerprint)
2. System information
3. Network interfaces and routes
4. Wireless adapter information
5. Driver information
6. Network service status
7. Diagnostic findings (confirmed findings vs. possible causes)
8. Command execution issues and utility availability
9. Privacy and redaction summary
10. Optional logs (only when `--include-logs` was used)

Findings never claim that an issue was fixed. A finding such as "Default route
may not use the Wi-Fi interface" is labelled **possible**, whereas "No default
route is configured" is labelled **confirmed** when the routing table was
actually read.

---

## Privacy policy

BugBundle is built around data minimisation:

- **Everything is generated locally.** No network sockets, no uploads, no
  telemetry, no cloud integrations.
- **No secrets are collected.** Wi-Fi passwords, PSKs, authentication tokens,
  NetworkManager connection files, iwd provisioning files and environment
  variables are never read into a report.
- **Identifiers are redacted.** MAC addresses keep only the vendor OUI
  (`aa:bb:cc:xx:xx:xx`); IP addresses become `[REDACTED_IPV4]` / `[REDACTED_IPV6]`;
  SSIDs/BSSIDs, usernames, home paths, hostnames and e-mail addresses are
  scrubbed. Loopback addresses are kept because they identify no host.
- **Logs are strictly opt-in.** They are only fetched with `--include-logs`,
  through `journalctl`, limited to the last 24 hours and 120 entries per unit,
  and redacted with the same engine.
- **Redaction is best effort.** Pattern-based redaction cannot guarantee that
  unexpected free-form text is clean. **Always inspect the complete report
  before sharing it.** The report itself repeats this warning.
- **No privileged operations.** BugBundle never uses `sudo`, becomes root,
  modifies configuration, restarts services, or installs/removes packages.
- **Safe command execution.** External commands use `subprocess.run` with
  `shell=False`, a fixed allow-list, a minimal environment and timeouts.

See [docs/PRIVACY.md](docs/PRIVACY.md) for the full policy and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for implementation details.

---

## Supported and unsupported capabilities

| Area | Status |
| --- | --- |
| Wi-Fi diagnostics on Arch Linux | Supported (primary target) |
| Fedora, Ubuntu, Debian and other distributions | Expected to work; distribution-independent parsers |
| NetworkManager, iwd, systemd-networkd | Status detected when available |
| Markdown and JSON reports | Supported |
| Optional journal logs | Supported, opt-in |
| Password/secret collection | **Never supported** |
| Automatic fixes, service changes, package changes | **Never supported** |
| Network uploads / telemetry | **Never supported** |
| GUI, AI/cloud integrations | Not in v0.1 |
| Audio, Bluetooth, display/GPU, boot, storage, USB modules | Planned, not implemented |

---

## Contributing

Contributions are welcome. Please keep the privacy guarantees intact and add
tests for every collector.

```bash
git clone https://github.com/ivvos/bugbundle.git
cd bugbundle
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
python -m pytest
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the project layout, testing
approach and the process for adding a new diagnostic module.

## License

MIT — see [LICENSE](LICENSE).
