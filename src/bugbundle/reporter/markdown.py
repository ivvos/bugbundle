"""Professional Markdown report renderer."""

from __future__ import annotations

from typing import Any

from ..models import Report
from ..privacy import Redactor
from . import finalize_payload


def _cell(value: Any) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(item) for item in value) or "—"
    text = str(value).replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")
    return text or "—"


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_cell(item) for item in row) + " |")
    return lines


def _section(number: int, title: str) -> list[str]:
    return [f"## {number}. {title}", ""]


def render(report: Report, redactor: Redactor) -> str:
    """Render a UTF-8 Markdown report string."""
    data = finalize_payload(report, redactor)
    meta = data["metadata"]
    system = data["system"]
    network = data["network"]
    wireless = data["wireless"]
    hardware = data["hardware"]
    services = data["services"]
    diagnostics = data["diagnostics"]
    privacy = data["privacy"]
    logs = data["logs"]
    integrity = data["integrity"]

    lines: list[str] = [
        "# BugBundle Wi-Fi Diagnostic Report",
        "",
        f"**Generated:** {_cell(meta['generated_at'])}  ",
        f"**Tool:** {_cell(meta['tool'])} {_cell(meta['version'])}  ",
        f"**Module:** {_cell(meta['module'])}",
        "",
        "> **Before sharing:** redaction is best-effort. Read the complete report "
        "yourself and remove anything you do not want to share.",
        "",
    ]

    # 1. Metadata
    lines += _section(1, "Report metadata")
    lines += _table(
        ["Field", "Value"],
        [
            ["Schema version", data["schema_version"]],
            ["Generated at (UTC)", meta["generated_at"]],
            ["Tool version", meta["version"]],
            ["Module", meta["module"]],
            ["Report fingerprint (SHA-256)", integrity["sha256"]],
        ],
    )
    lines.append("")

    # 2. System information
    lines += _section(2, "System information")
    lines += _table(
        ["Item", "Value"],
        [
            ["Distribution", system["distribution"]],
            ["Distribution ID", system["distribution_id"]],
            ["Version", system["version"]],
            ["Kernel", system["kernel"]],
            ["Architecture", system["architecture"]],
            ["Python", system["python"]],
            ["Hostname", system["hostname"]],
            ["os-release available", system["os_release_available"]],
        ],
    )
    lines.append("")

    # 3. Network interfaces and routing
    lines += _section(3, "Network interfaces")
    interface_rows = [
        [
            iface["name"],
            iface["link_type"],
            iface["operstate"],
            "yes" if iface["is_up"] else "no",
            "yes" if iface["has_carrier"] else "no",
            "yes" if iface["is_wireless"] else "no",
            iface["mtu"],
            iface["mac"],
            ", ".join(
                f"{addr['family']} {addr['address']}"
                + (f"/{addr['prefixlen']}" if addr["prefixlen"] is not None else "")
                for addr in iface["addresses"]
            )
            or "—",
        ]
        for iface in network["interfaces"]
    ]
    lines += _table(
        ["Interface", "Type", "State", "Up", "Carrier", "Wi-Fi", "MTU", "MAC (redacted)", "Addresses (redacted)"],
        interface_rows,
    )
    lines.append("")
    lines += _table(
        ["Destination", "Device", "Gateway (redacted)", "Metric", "Protocol"],
        [
            [route["destination"], route["device"], route["gateway"], route["metric"], route["protocol"]]
            for route in network["default_routes"]
        ],
    )
    lines.append("")

    # 4. Wireless adapter information
    lines += _section(4, "Wireless adapter information")
    lines += _table(
        ["Interface", "PHY", "Type", "Channel", "Frequency", "Width", "TX power", "Address (redacted)"],
        [
            [
                dev["interface"],
                dev["phy"],
                dev["interface_type"],
                dev["channel"],
                f"{dev['frequency_mhz']} MHz" if dev["frequency_mhz"] else None,
                dev["channel_width"],
                f"{dev['txpower_dbm']} dBm" if dev["txpower_dbm"] is not None else None,
                dev["address"],
            ]
            for dev in wireless["devices"]
        ],
    )
    lines.append("")
    lines += _table(
        ["Bus", "Slot / USB ID", "Adapter", "Vendor", "Subsystem", "Driver"],
        [
            [
                adapter["bus"],
                adapter["slot"] or adapter["pci_ids"],
                adapter["name"],
                adapter["vendor"],
                adapter["subsystem"],
                adapter["driver"],
            ]
            for adapter in hardware["adapters"]
        ],
    )
    lines.append("")
    radio = wireless["radio"]
    lines += _table(
        ["Radio source", "Available", "Soft blocked", "Hard blocked", "WLAN devices"],
        [
            [
                radio["source"],
                radio["available"],
                radio["soft_blocked"],
                radio["hard_blocked"],
                len(radio["wlan_devices"]),
            ]
        ],
    )
    lines.append("")

    # 5. Driver information
    lines += _section(5, "Driver information")
    lines += _table(
        ["Interface", "Driver", "Version", "Firmware", "Bus info", "Description", "Source"],
        [
            [
                driver["interface"],
                driver["driver"],
                driver["version"],
                driver["firmware_version"],
                driver["bus_info"],
                driver["description"],
                driver["source"],
            ]
            for driver in hardware["drivers"]
        ],
    )
    lines.append("")

    # 6. Services
    lines += _section(6, "Network service status")
    lines += _table(
        ["Service", "State", "Status known", "Wi-Fi radio", "NM running", "NM state"],
        [
            [
                "NetworkManager",
                services["network_manager"]["state"],
                services["network_manager"]["available"],
                services["wifi_radio"],
                services["nm_running"],
                services["nm_state"],
            ],
            ["iwd", services["iwd"]["state"], services["iwd"]["available"], None, None, None],
            [
                "systemd-networkd",
                services["systemd_networkd"]["state"],
                services["systemd_networkd"]["available"],
                None,
                None,
                None,
            ],
        ],
    )
    lines.append("")
    if services["nm_devices"] or services["iwd_stations"]:
        lines.append("Observed device states:")
        lines.append("")
        lines += _table(
            ["Source", "Device", "Type", "State", "Connection name"],
            [
                ["NetworkManager", dev["device"], dev["device_type"], dev["state"],
                 "redacted" if dev["connection_redacted"] else None]
                for dev in services["nm_devices"]
            ]
            + [["iwd", station, None, None, None] for station in services["iwd_stations"]],
        )
        lines.append("")

    # 7. Findings
    lines += _section(7, "Diagnostic findings")
    lines.append(
        "**Confirmed findings** are direct observations. **Possible causes** are "
        "hypotheses and have not been proven."
    )
    lines.append("")
    for status, heading in (("confirmed", "Confirmed findings"), ("possible", "Possible causes")):
        lines.append(f"### {heading}")
        lines.append("")
        selected = [f for f in diagnostics["findings"] if f["status"] == status]
        if not selected:
            lines.append("_No findings in this category._")
            lines.append("")
            continue
        for finding in selected:
            lines.append(
                f"- **[{finding['severity'].upper()}] {finding['title']}** "
                f"({finding['category']}) — {finding['detail']}"
            )
            for evidence in finding["evidence"]:
                lines.append(f"  - Evidence: {evidence}")
        lines.append("")

    # 8. Command issues + utilities
    lines += _section(8, "Command execution issues")
    lines += _table(
        ["Command", "Error", "Exit code", "Detail"],
        [
            [issue["command"], issue["error"], issue["exit_code"], issue["detail"]]
            for issue in diagnostics["command_issues"]
        ],
    )
    lines.append("")
    lines.append("Utility availability:")
    lines.append("")
    lines += _table(
        ["Utility", "Available"],
        [[name, available] for name, available in diagnostics["utilities"].items()],
    )
    lines.append("")

    # 9. Privacy
    lines += _section(9, "Privacy and redaction summary")
    redaction_summary = privacy["redaction_summary"]
    counts = redaction_summary["redacted_values"]
    lines += _table(
        ["Category", "Redaction operations"],
        [[category, count] for category, count in counts.items()] or [["none", 0]],
    )
    lines.append("")
    for statement in redaction_summary["statements"]:
        lines.append(f"- {statement}")
    lines.append("")
    lines.append(f"> **Best-effort notice:** {privacy['note']}")
    lines.append("")
    lines.append("Values intentionally not collected:")
    lines.append("")
    for item in redaction_summary["not_collected"]:
        lines.append(f"- `{item}`")
    lines.append("")

    # 10. Optional logs
    if logs is not None:
        lines += _section(10, "Optional logs (explicitly opted in)")
        lines.append(f"Source: {logs['source']} — window: {logs['time_window']}")
        lines.append("")
        for unit, payload in logs["units"].items():
            lines.append(f"### {unit}")
            lines.append("")
            if not payload["available"]:
                lines.append(f"_Unavailable: {payload['issue']}_")
                lines.append("")
                continue
            lines.append("```text")
            lines.extend(payload["lines"])
            lines.append("```")
            lines.append("")
        lines.append(
            "> Log redaction is best-effort. Review every line above before sharing this report."
        )
        lines.append("")

    lines += ["---", "", "End of report. BugBundle did not modify the system."]
    return "\n".join(lines) + "\n"
