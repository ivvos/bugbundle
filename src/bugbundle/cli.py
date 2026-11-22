"""Command-line interface for BugBundle."""

from __future__ import annotations

import argparse
import os
import platform
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .collector.wifi import collect_wifi_report
from .privacy import Redactor
from .reporter import json_report, markdown
from .utils.commands import CommandRunner

PREVIEW_LINES = 18


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bugbundle",
        description=(
            "Privacy-first Linux diagnostics. Reports are generated locally; "
            "nothing is uploaded."
        ),
    )
    parser.add_argument("--version", action="version", version=f"bugbundle {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("modules", help="list available diagnostic modules")

    collect = subparsers.add_parser("collect", help="collect a diagnostic report")
    collect_sub = collect.add_subparsers(dest="module", required=True)
    wifi = collect_sub.add_parser("wifi", help="collect a Wi-Fi diagnostic report")
    wifi.add_argument("-o", "--output", type=Path, help="report file path")
    wifi.add_argument(
        "-f", "--format", choices=("markdown", "md", "json"), help="report format"
    )
    wifi.add_argument(
        "--include-logs",
        action="store_true",
        help="include opt-in NetworkManager/iwd journal excerpts (redacted)",
    )
    wifi.add_argument(
        "--stdout", action="store_true", help="print the report instead of writing a file"
    )
    wifi.add_argument("--yes", action="store_true", help="skip the write confirmation prompt")
    wifi.add_argument(
        "--timeout", type=float, default=5.0, help="per-command timeout in seconds (default: 5)"
    )
    return parser


def _default_redactor() -> Redactor:
    home = Path.home()
    username = home.name if str(home) not in {"/", "."} else None
    return Redactor(home=str(home), username=username, hostname=platform.node())


def _output_format(args: argparse.Namespace) -> str:
    if args.format in {"md", "markdown"}:
        return "markdown"
    if args.format == "json":
        return "json"
    suffix = (args.output.suffix.lower() if args.output else "") or ""
    return "json" if suffix == ".json" else "markdown"


def _default_output(extension: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(f"bugbundle-wifi-{stamp}.{extension}")


def _warn_if_root(stderr: TextIO) -> None:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        print(
            "warning: running as root is not required or recommended; "
            "BugBundle only reads diagnostic data.",
            file=stderr,
        )


def _collect_wifi(
    args: argparse.Namespace,
    out: TextIO,
    stderr: TextIO,
    *,
    runner: CommandRunner | None = None,
    redactor: Redactor | None = None,
    interactive: bool | None = None,
) -> int:
    if args.timeout <= 0:
        print("error: --timeout must be greater than zero", file=stderr)
        return 2
    _warn_if_root(stderr)
    active_runner = runner if runner is not None else CommandRunner(timeout=args.timeout)
    active_redactor = redactor if redactor is not None else _default_redactor()

    try:
        report = collect_wifi_report(
            active_runner,
            active_redactor,
            include_logs=args.include_logs,
        )
        if _output_format(args) == "json":
            text = json_report.render(report, active_redactor)
            extension = "json"
        else:
            text = markdown.render(report, active_redactor)
            extension = "md"
    except (OSError, ValueError) as exc:
        print(f"error: report generation failed: {exc.__class__.__name__}", file=stderr)
        return 1

    if args.stdout:
        out.write(text)
        return 0

    lines = text.splitlines()
    print("Report preview (first lines):", file=out)
    print("\n".join(lines[:PREVIEW_LINES]), file=out)
    print(f"... ({len(lines)} lines total)", file=out)

    write_report = True
    is_interactive = interactive if interactive is not None else sys.stdin.isatty()
    if is_interactive and not args.yes:
        try:
            answer = input(f"Write this report to disk? [y/N]: ")
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        write_report = answer.strip().lower() in {"y", "yes"}
    if not write_report:
        print("No file was written. Nothing was uploaded.", file=out)
        return 1

    destination = args.output or _default_output(extension)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        # Reports can contain system details; keep them owner-readable only.
        os.chmod(destination, 0o600)
    except OSError as exc:
        print(f"error: could not write {destination}: {exc.__class__.__name__}", file=stderr)
        return 1

    print(f"\nReport written to: {destination}", file=out)
    print(
        "Review the complete report before sharing it. Redaction is best-effort.",
        file=out,
    )
    return 0


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    runner: CommandRunner | None = None,
    redactor: Redactor | None = None,
    interactive: bool | None = None,
) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    out: TextIO = stdout if stdout is not None else sys.stdout
    err: TextIO = stderr if stderr is not None else sys.stderr
    extra: dict[str, Any] = {
        "runner": runner,
        "redactor": redactor,
        "interactive": interactive,
    }

    if args.command is None:
        parser.print_help(file=out)
        return 0
    if args.command == "modules":
        print("Available diagnostic modules:", file=out)
        print("  wifi    Wi-Fi diagnostics (v0.1)", file=out)
        print("", file=out)
        print("Planned for later releases (not implemented):", file=out)
        for name in ("audio", "bluetooth", "display/gpu", "boot/systemd", "storage", "usb"):
            print(f"  {name}", file=out)
        return 0
    if args.command == "collect":
        return _collect_wifi(args, out, err, **extra)
    parser.print_help(file=out)
    return 2
