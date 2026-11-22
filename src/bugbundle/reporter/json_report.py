"""JSON report renderer."""

from __future__ import annotations

import json
from typing import Any

from ..models import Report
from ..privacy import Redactor
from . import finalize_payload


def build_payload(report: Report, redactor: Redactor) -> dict[str, Any]:
    """Return the redacted JSON-serialisable report structure."""
    return finalize_payload(report, redactor)


def render(report: Report, redactor: Redactor) -> str:
    """Render a UTF-8 JSON report string."""
    return json.dumps(build_payload(report, redactor), indent=2, ensure_ascii=False) + "\n"
