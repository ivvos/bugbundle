# Privacy policy

BugBundle is a local diagnostic tool. Its purpose is to help you share *useful*
technical information while sharing as little personal information as possible.

## 1. Data flow

All collection, redaction and rendering happens in your Python process.
BugBundle contains no network client code, performs no uploads, and sends no
telemetry. It creates a report file only when you confirm, or writes to stdout
with `--stdout`.

## 2. What is collected

| Category | Examples | Notes |
| --- | --- | --- |
| System | Distribution, kernel, architecture, Python version | Hostname is redacted |
| Network | Interface names, states, MTU, address families/prefixes, default route devices | Address values are redacted |
| Radio | rfkill soft/hard block state, interface channel/frequency/TX power | No scan results |
| Hardware | PCI/USB IDs, adapter descriptions, driver and firmware versions | Vendor IDs are public identifiers |
| Services | Whether NetworkManager/iwd/systemd-networkd are active | Status only, never changed |
| Diagnostics | Utility availability, command errors/timeouts | Error text is redacted and capped |
| Logs | Up to 120 journal lines per relevant unit, last 24 hours | **Only with `--include-logs`** |

## 3. What is never collected

- Wi-Fi passwords, PSKs, WPA keys or any authentication secret
- NetworkManager connection secret files (`/etc/NetworkManager/system-connections/*`)
- iwd provisioning files (`/var/lib/iwd/*`) and wpa_supplicant configuration
- SSH keys, password databases, shell history
- Environment variables (a minimal environment is passed to child processes,
  but it is never written to a report)
- Raw log files outside the `journalctl` output described above
- Scan results containing nearby SSIDs or BSSIDs

## 4. Redaction rules

- **MAC addresses:** the first three octets (OUI) are kept for vendor-level
  diagnosis; the last three become `xx:xx:xx`. Example: `aa:bb:cc:11:22:33`
  becomes `aa:bb:cc:xx:xx:xx`. The redactor also handles hyphen-separated MACs.
- **IPv4:** replaced with `[REDACTED_IPV4]`, preserving a CIDR prefix when
  present (`[REDACTED_IPV4]/24`). Loopback (`127.0.0.1`) and unspecified
  addresses are kept because they identify no host.
- **IPv6:** replaced with `[REDACTED_IPV6]`; `::1` is kept.
- **SSIDs/BSSIDs:** connection names from nmcli are registered as secrets and
  scrubbed from log excerpts. BugBundle does not request a Wi-Fi scan.
- **Usernames / home paths:** `/home/<user>` becomes `/home/[REDACTED_USER]`
  or `[REDACTED_PATH]`; usernames found in filenames and text are scrubbed.
- **Hostnames:** replaced with `[REDACTED_HOST]`, including in journal lines.
- **E-mail addresses and secret assignments** (`psk=`, `password:`, etc.) are
  redacted defensively.

Every redacted token is idempotent, and the report includes a count of
redaction operations by category.

## 5. Limitations

Redaction is **best effort**. It is pattern-based and cannot understand every
possible free-form string. A value that looks harmless but is sensitive in
your environment may survive. Log excerpts deserve particular scrutiny.

**Always read the complete report before sharing it.** BugBundle prints this
reminder, includes it in every report, and never shares anything on your behalf.

## 6. Privileges and system state

BugBundle requires no root privileges and warns if launched as root. It never
uses `sudo` or `pkexec`, never modifies configuration, never starts/stops/
restarts services, and never installs or removes packages.

## 7. Reporting a privacy issue

If you find a value that BugBundle fails to redact, please open an issue with a
synthetic example (never a real secret) so a regression test can be added.
