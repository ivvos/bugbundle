"""Turn collected observations into clearly labelled findings.

A finding is either:

* ``confirmed`` — directly observed by a diagnostic command; or
* ``possible`` — a hypothesis that *may* explain a symptom.

The analysis never claims that a problem was fixed.
"""

from __future__ import annotations

from typing import Any

from ..models import CommandIssue, Finding


def analyze(
    *,
    interfaces: list[Any],
    wireless_devices: list[Any],
    radio: Any,
    services: Any,
    adapters: list[Any],
    drivers: list[Any],
    utilities: dict[str, bool],
    routes: list[Any],
    routes_available: bool,
    command_issues: list[CommandIssue],
    logs_included: bool,
) -> list[Finding]:
    findings: list[Finding] = []

    def add(status: str, severity: str, category: str, title: str, detail: str, evidence: list[str] | None = None) -> None:
        findings.append(
            Finding(
                status=status,
                severity=severity,
                category=category,
                title=title,
                detail=detail,
                evidence=evidence or [],
            )
        )

    # --- Tool availability ------------------------------------------------
    missing = sorted(name for name, available in utilities.items() if not available)
    essential_missing = [name for name in ("ip", "iw", "rfkill") if name in missing]
    if essential_missing:
        add(
            "confirmed",
            "error" if "ip" in essential_missing else "warning",
            "environment",
            "Diagnostic utilities are missing",
            "Some information could not be collected. Missing utilities: "
            + ", ".join(essential_missing)
            + ". The report lists every missing utility below.",
            missing,
        )
    elif missing:
        add(
            "confirmed",
            "info",
            "environment",
            "Optional utilities are unavailable",
            "Optional utilities not found: " + ", ".join(missing) + ".",
            missing,
        )

    # --- Interfaces -------------------------------------------------------
    if not interfaces and utilities.get("ip"):
        add(
            "confirmed",
            "error",
            "network",
            "No network interfaces were detected",
            "`ip addr` returned no interfaces. The interface listing may be incomplete.",
        )
    wireless_ifaces = [iface for iface in interfaces if iface.is_wireless]
    if not wireless_ifaces and not wireless_devices:
        if utilities.get("ip") and utilities.get("iw"):
            add(
                "confirmed",
                "info",
                "wireless",
                "No Wi-Fi interface was detected",
                "Neither sysfs nor `iw dev` reported a wireless interface. "
                "This is expected on systems without a Wi-Fi adapter.",
            )
        else:
            add(
                "possible",
                "warning",
                "wireless",
                "Wi-Fi interface could not be determined",
                "Required detection utilities were unavailable, so the absence of a "
                "wireless interface is not confirmed.",
            )

    for iface in wireless_ifaces:
        if not iface.is_up:
            add(
                "confirmed",
                "warning",
                "wireless",
                f"Wireless interface {iface.name} is administratively down",
                "The interface flags do not include UP.",
                [f"{iface.name}: operstate={iface.operstate or 'unknown'}"],
            )
        elif not iface.has_carrier:
            add(
                "confirmed",
                "warning",
                "wireless",
                f"Wireless interface {iface.name} has no carrier",
                "The interface is up but reports no lower-layer link.",
                [f"{iface.name}: operstate={iface.operstate or 'unknown'}"],
            )
        elif (iface.operstate or "").upper() == "DORMANT":
            add(
                "possible",
                "info",
                "wireless",
                f"Wireless interface {iface.name} is in DORMANT state",
                "DORMANT can indicate an association or authentication problem, but "
                "it can also be normal for some drivers.",
                [f"{iface.name}: operstate=DORMANT"],
            )
        if not any(addr.family == "inet" for addr in iface.addresses):
            add(
                "confirmed",
                "warning",
                "network",
                f"No IPv4 address on {iface.name}",
                "The interface has no DHCP or static IPv4 lease at collection time.",
            )

    # --- Radio ------------------------------------------------------------
    if radio.hard_blocked:
        add(
            "confirmed",
            "error",
            "radio",
            "Wi-Fi radio is hard blocked",
            "A hardware rfkill switch or firmware state blocks the radio. "
            "BugBundle does not change this state.",
        )
    elif radio.soft_blocked:
        add(
            "confirmed",
            "error",
            "radio",
            "Wi-Fi radio is soft blocked",
            "A software rfkill block is active. BugBundle does not change this state.",
        )
    elif not radio.available:
        add(
            "possible",
            "info",
            "radio",
            "Radio block state is unknown",
            "Neither rfkill nor sysfs rfkill data was available.",
        )

    # --- Routing ----------------------------------------------------------
    defaults = [route for route in routes if route.destination == "default"]
    if routes_available and not defaults:
        add(
            "confirmed",
            "warning",
            "routing",
            "No default route is configured",
            "Outbound traffic has no default gateway according to the routing table.",
        )
    elif len(defaults) > 1:
        add(
            "possible",
            "info",
            "routing",
            "Multiple default routes are present",
            "More than one default route exists; traffic may leave via an interface "
            "other than Wi-Fi.",
            [f"via {route.device or 'unknown'} (metric {route.metric if route.metric is not None else 'n/a'})" for route in defaults],
        )
    wifi_connected = any(
        device.device_type in {"wifi", "wireless"} and device.state.startswith("connected")
        for device in services.nm_devices
    )
    if wifi_connected and defaults and not any(
        route.device in {dev.interface for dev in wireless_devices} for route in defaults
    ):
        add(
            "possible",
            "warning",
            "routing",
            "Default route may not use the Wi-Fi interface",
            "NetworkManager reports a connected Wi-Fi device, but the default route "
            "points to a different interface. This can explain apparent Wi-Fi "
            "connectivity problems.",
        )

    # --- Services ---------------------------------------------------------
    states = (
        services.network_manager.state,
        services.iwd.state,
        services.systemd_networkd.state,
    )
    if states and all(state in {"inactive", "unknown", "failed"} for state in states):
        add(
            "possible",
            "warning",
            "services",
            "No active network management service was detected",
            "NetworkManager, iwd and systemd-networkd were all reported as inactive "
            "or unavailable. Wi-Fi may need to be configured by another mechanism.",
            [f"NetworkManager={states[0]}", f"iwd={states[1]}", f"systemd-networkd={states[2]}"],
        )
    if services.iwd.state == "active" and services.network_manager.state == "active":
        add(
            "possible",
            "info",
            "services",
            "Both iwd and NetworkManager are active",
            "Two wireless management services are running; which one controls an "
            "interface depends on the local configuration.",
        )
    if not adapters and not drivers:
        add(
            "possible",
            "info",
            "hardware",
            "No wireless adapter details were collected",
            "lspci, lsusb, ethtool or sysfs data was unavailable, so hardware "
            "identification is incomplete.",
        )
    for driver in drivers:
        if not driver.driver:
            add(
                "possible",
                "warning",
                "driver",
                f"Driver for {driver.interface} could not be identified",
                "Neither ethtool nor sysfs reported a driver name.",
            )
        elif not driver.firmware_version:
            add(
                "possible",
                "info",
                "driver",
                f"No firmware version reported for {driver.interface}",
                "An absent firmware version is not proof of a firmware problem, but "
                "it may be worth checking the adapter's firmware package.",
            )

    # --- Command execution / privacy --------------------------------------
    for issue in command_issues:
        if issue.error == "timeout":
            add(
                "confirmed",
                "warning",
                "diagnostics",
                f"Diagnostic command timed out: {issue.command}",
                "The command was stopped after the configured timeout. Its output is "
                "not included in this report.",
            )
        elif issue.error in {"permission_denied", "nonzero_exit", "invalid_json", "os_error"}:
            add(
                "confirmed",
                "info",
                "diagnostics",
                f"Diagnostic command failed: {issue.command}",
                f"Failure type: {issue.error}. The collector continued without this data.",
            )

    if not logs_included:
        add(
            "confirmed",
            "info",
            "privacy",
            "Logs were not included",
            "Log collection is opt-in. Re-run with --include-logs if logs are needed; "
            "review them carefully because redaction is best-effort.",
        )

    return findings
