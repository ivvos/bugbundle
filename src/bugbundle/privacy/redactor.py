"""Best-effort redaction of personally identifying or secret values.

Redaction happens in two places:

1. At collection time, where collectors know that a specific value is an SSID,
   a MAC address or an IP address.
2. On the finished report payload, as a safety net for values that a collector
   did not recognise.

All replacement tokens are idempotent: running the redactor twice never
changes an already-redacted value. Redaction is *best effort* by nature; the
user is always told to inspect the report before sharing it.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from typing import Any

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:.\-])((?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:.\-])"
)
IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?(?![\d.])")
IPV6_RE = re.compile(
    r"(?<![0-9A-Za-z_:/.%])"
    r"((?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:[0-9A-Fa-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})"
    r"(?:%[0-9A-Za-z_.\-]+)?)"
    r"(?![0-9A-Za-z_:/.%])"
)
HOME_RE = re.compile(r"(/(?:home|Users)/)([^\s/]+)")
ROOT_RE = re.compile(r"/root(?=/|\s|$)")
EMAIL_RE = re.compile(r"[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}")
SECRET_RE = re.compile(
    r"(?i)\b(psk|password|passphrase|secret|wpa[_-]?key)\b\s*[:=]\s*(\"[^\"]*\"|'[^']*'|\S+)"
)

TOKENS = {
    "ssid": "[REDACTED_SSID]",
    "bssid": "[REDACTED_MAC]",
    "hostname": "[REDACTED_HOST]",
    "username": "[REDACTED_USER]",
    "path": "[REDACTED_PATH]",
    "secret": "[REDACTED_SECRET]",
    "mac": "[REDACTED_MAC]",
    "ipv4": "[REDACTED_IPV4]",
    "ipv6": "[REDACTED_IPV6]",
    "email": "[REDACTED_EMAIL]",
}


class Redactor:
    """Redact sensitive values from strings and nested data structures."""

    def __init__(
        self,
        home: str | None = None,
        username: str | None = None,
        hostname: str | None = None,
    ) -> None:
        self.counts: Counter[str] = Counter()
        # (value, token, category, scope). SSIDs are scoped to logs because a
        # connection name is often identical to a distribution name and must
        # not replace ordinary system fields.
        self._secrets: list[tuple[str, str, str, str]] = []
        self._username = username
        self._hostname = hostname
        if home:
            self.register_secret(home, "path", category="home")
        if username:
            self.register_secret(username, "username", category="username")
        if hostname:
            self.register_secret(hostname, "hostname", category="hostname")

    def clone(self) -> "Redactor":
        """Return an independent copy with the same registrations and counts.

        Reporters render through a clone so rendering a report twice does not
        accumulate redaction counts or change the report fingerprint.
        """
        copy = Redactor()
        copy.counts = Counter(self.counts)
        copy._secrets = list(self._secrets)
        copy._username = self._username
        copy._hostname = self._hostname
        return copy

    def register_secret(
        self,
        value: str | None,
        label: str,
        category: str | None = None,
        scope: str = "all",
    ) -> None:
        """Register a known-sensitive value (for example, an SSID).

        Registered values are scrubbed in later text within the given scope:
        ``"all"`` (default) or ``"logs"`` only. Short values are ignored so
        ordinary diagnostic text is not destroyed.
        """
        if not value or not isinstance(value, str):
            return
        value = value.strip()
        if len(value) < 3 or value in TOKENS.values():
            return
        token = TOKENS.get(label, "[REDACTED_SECRET]")
        cat = category or label
        if any(existing == value for existing, _, _, _ in self._secrets):
            return
        # Longer values first so overlapping secrets are fully removed.
        self._secrets.append((value, token, cat, scope))
        self._secrets.sort(key=lambda item: len(item[0]), reverse=True)

    def redact_text(self, text: Any, scope: str = "all") -> str:
        """Return ``text`` with all recognised sensitive values replaced."""
        if text is None:
            return ""
        value = str(text)
        value = ANSI_RE.sub("", value)
        value = self._redact_registered(value, scope)
        value = self._redact_secret_assignments(value)
        value = EMAIL_RE.sub(lambda m: self._hit("email", TOKENS["email"]), value)
        value = self._redact_ipv6(value)
        value = self._redact_ipv4(value)
        value = MAC_RE.sub(self._replace_mac, value)
        value = HOME_RE.sub(self._replace_home, value)
        value = ROOT_RE.sub(lambda m: self._hit("home", "[REDACTED_HOME]"), value)
        value = self._redact_word(self._username, TOKENS["username"], "username", value)
        value = self._redact_word(self._hostname, TOKENS["hostname"], "hostname", value)
        return value

    # Individual helpers -------------------------------------------------

    def _hit(self, category: str, token: str) -> str:
        self.counts[category] += 1
        return token

    def _redact_registered(self, value: str, scope: str) -> str:
        for secret, token, category, secret_scope in self._secrets:
            if secret_scope not in {"all", scope}:
                continue
            # Usernames must not match inside an e-mail address. Paths end in a
            # username followed by "/", "." or a quote, so they use simpler
            # word boundaries.
            if category == "username":
                # "@" is excluded to keep e-mail addresses intact for the
                # e-mail pattern; dots and slashes are allowed so usernames
                # inside filenames such as alice.conf are still scrubbed.
                boundary = r"(?<![\w@\-])" + re.escape(secret) + r"(?![\w@\-])"
            else:
                boundary = r"(?<!\w)" + re.escape(secret) + r"(?!\w)"
            pattern = re.compile(boundary, re.IGNORECASE)
            value, count = pattern.subn(
                lambda m, t=token, c=category: self._hit(c, t), value
            )
        return value

    @staticmethod
    def _redact_secret_assignments(value: str) -> str:
        def replace(match: re.Match[str]) -> str:
            secret = match.group(2)
            if secret.strip("\"'").startswith("[REDACTED"):
                return match.group(0)
            return f"{match.group(1)}=[REDACTED_SECRET]"

        return SECRET_RE.sub(replace, value)

    def _replace_mac(self, match: re.Match[str]) -> str:
        mac = match.group(1)
        sep = ":" if ":" in mac else "-"
        octets = re.split(r"[:-]", mac)
        # Keep the OUI (first three octets) so vendor-level diagnosis remains
        # possible, while the device-specific tail is destroyed.
        return self._hit("mac", sep.join(octets[:3] + ["xx", "xx", "xx"]))

    @staticmethod
    def _is_public_ipv4(octets: list[int]) -> bool:
        return all(0 <= part <= 255 for part in octets)

    def _redact_ipv4(self, value: str) -> str:
        def replace(match: re.Match[str]) -> str:
            octets = [int(part) for part in match.group(1).split(".")]
            if not self._is_public_ipv4(octets):
                return match.group(0)
            # Loopback and unspecified addresses identify no host.
            if octets[0] == 127 or match.group(1) in {"0.0.0.0", "255.255.255.255"}:
                return match.group(0)
            prefix = f"/{match.group(2)}" if match.group(2) else ""
            return self._hit("ipv4", TOKENS["ipv4"] + prefix)

        return IPV4_RE.sub(replace, value)

    def _redact_ipv6(self, value: str) -> str:
        def replace(match: re.Match[str]) -> str:
            candidate = match.group(1).split("%", 1)[0]
            try:
                address = ipaddress.IPv6Address(candidate)
            except ipaddress.AddressValueError:
                return match.group(0)
            if address.is_loopback or address.is_unspecified:
                return match.group(0)
            return self._hit("ipv6", TOKENS["ipv6"])

        return IPV6_RE.sub(replace, value)

    def _replace_home(self, match: re.Match[str]) -> str:
        user = match.group(2)
        if user.startswith("[REDACTED"):
            return match.group(0)
        self._hit("username", TOKENS["username"])
        return match.group(1) + TOKENS["username"]

    def _redact_word(self, word: str | None, token: str, category: str, value: str) -> str:
        if not word or len(word) < 3 or word in TOKENS.values():
            return value
        pattern = re.compile(r"(?<![\w@\-])" + re.escape(word) + r"(?![\w@\-])", re.IGNORECASE)
        return pattern.sub(lambda m: self._hit(category, token), value)

    def redact_structured(self, obj: Any) -> Any:
        """Recursively redact every string in a nested dict/list structure."""
        if isinstance(obj, str):
            return self.redact_text(obj)
        if isinstance(obj, dict):
            return {key: self.redact_structured(item) for key, item in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.redact_structured(item) for item in obj]
        return obj

    def summary(self) -> dict[str, Any]:
        """Return an audit-friendly description of what was redacted."""
        return {
            "best_effort": True,
            "method": (
                "Sensitive values are replaced at collection time and again on the "
                "final report. Registered hostnames, usernames and paths are scrubbed "
                "throughout; SSIDs are scrubbed from log excerpts where they can occur."
            ),
            "redacted_values": dict(sorted(self.counts.items())),
            "statements": [
                "Reports are generated locally; BugBundle performs no network uploads.",
                "Wi-Fi passwords, PSKs and authentication secrets are never collected.",
                "NetworkManager connection secret files and iwd provisioning files are never read.",
                "Environment variables are passed to child processes but are never collected.",
                "Logs are collected only with --include-logs and are redacted best-effort.",
                "Inspect the complete report yourself before sharing it.",
            ],
            "not_collected": [
                "Wi-Fi passwords / PSKs",
                "/etc/NetworkManager/system-connections/*",
                "/var/lib/iwd/* (provisioning files)",
                "environment variables",
                "raw log files outside journalctl output",
            ],
        }
