"""Report assembly shared by the Markdown and JSON renderers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from typing import Any

from ..models import Report
from ..privacy import Redactor


def _plain(value: Any) -> Any:
    """Convert dataclasses (and nested containers of them) to plain data."""
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def finalize_payload(report: Report, redactor: Redactor) -> dict[str, Any]:
    """Convert a Report into a redacted, fingerprinted plain dictionary.

    Both output formats use this function, so they cannot disagree about what
    was collected or what was redacted.
    """
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "metadata": {
            "tool": "bugbundle",
            "version": report.tool_version,
            "module": report.module,
            "generated_at": report.generated_at,
        },
        "system": _plain(report.system),
        "network": {
            "interfaces": [asdict(item) for item in report.interfaces],
            "default_routes": [asdict(item) for item in report.default_routes],
        },
        "wireless": {
            "devices": [asdict(item) for item in report.wireless_devices],
            "radio": asdict(report.radio),
        },
        "hardware": {
            "adapters": [asdict(item) for item in report.adapters],
            "drivers": [asdict(item) for item in report.drivers],
        },
        "services": _plain(report.services),
        "diagnostics": {
            "utilities": dict(sorted(report.utilities.items())),
            "findings": [asdict(item) for item in report.findings],
            "command_issues": [asdict(item) for item in report.command_issues],
        },
        "logs": _plain(report.logs) if report.logs is not None else None,
        "privacy": dict(report.privacy),
    }

    # Safety net: redact anything a collector failed to recognise. Use a clone
    # so repeated renders of the same report stay byte-for-byte identical.
    active_redactor = redactor.clone()
    payload = active_redactor.redact_structured(payload)
    payload["privacy"]["redaction_summary"] = active_redactor.summary()

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    payload["integrity"] = {
        "algorithm": "sha256",
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "scope": "redacted report payload (excluding this integrity block)",
    }
    return payload
