"""Network interface discovery and its failure modes."""

from __future__ import annotations

import json

from bugbundle.collector.network import (
    collect_network,
    is_wireless,
    parse_addr_payload,
    parse_routes,
)
from tests.conftest import (
    IP_ADDR_JSON,
    IP_ROUTE_JSON,
    TEST_IP,
    TEST_MAC,
    FakeRunner,
    make_redactor,
    result,
)


def test_interface_discovery_and_redaction(sysfs_root, redactor):
    interfaces = parse_addr_payload(IP_ADDR_JSON, redactor, sysfs_root)
    assert [iface.name for iface in interfaces] == ["lo", "enp1s0", "wlp2s0"]
    wifi = interfaces[2]
    assert wifi.is_wireless and wifi.is_up and wifi.has_carrier
    assert wifi.mac == "aa:bb:cc:xx:xx:xx"
    assert wifi.driver == "iwlwifi"
    assert [addr.family for addr in wifi.addresses] == ["inet", "inet6"]
    assert wifi.addresses[0].address == "[REDACTED_IPV4]"
    assert wifi.addresses[0].prefixlen == 24
    assert wifi.addresses[1].address == "[REDACTED_IPV6]"
    assert TEST_IP not in json.dumps([iface.__dict__ for iface in interfaces], default=str)


def test_wireless_detection_uses_sysfs_markers(tmp_path, sysfs_root):
    assert is_wireless(sysfs_root, "wlp2s0")
    assert not is_wireless(sysfs_root, "enp1s0")
    assert not is_wireless(tmp_path, "wlp2s0")


def test_wireless_names_from_iw_are_used(sysfs_root, redactor):
    interfaces = parse_addr_payload(IP_ADDR_JSON, redactor, sysfs_root.parent, {"enp1s0"})
    assert interfaces[1].is_wireless  # name supplied by iw
    assert not interfaces[2].is_wireless


def test_routes_are_parsed_and_redacted(redactor):
    routes = parse_routes(IP_ROUTE_JSON, redactor)
    defaults = [route for route in routes if route.destination == "default"]
    assert len(defaults) == 2
    assert defaults[0].device == "wlp2s0"
    assert defaults[0].gateway == "[REDACTED_IPV4]"
    assert defaults[0].metric == 600
    assert TEST_IP not in str(routes)


def test_missing_ip_command_is_graceful(sysfs_root):
    runner = FakeRunner(available=set())
    interfaces, routes, issues, utilities = collect_network(
        runner, make_redactor(), sysfs_root
    )
    assert interfaces == [] and routes == []
    assert utilities["ip"] is False
    assert issues[0].error == "not_found"
    assert runner.calls == []


def test_failed_command_produces_issue(sysfs_root):
    runner = FakeRunner(
        {("ip", "-j", "addr", "show"): result(("ip",), ok=False, exit_code=2, error="nonzero_exit")},
        available={"ip"},
    )
    interfaces, _, issues, _ = collect_network(runner, make_redactor(), sysfs_root)
    assert interfaces == []
    assert issues[0].command == "ip -j addr show"
    assert issues[0].exit_code == 2


def test_invalid_json_is_graceful(sysfs_root):
    runner = FakeRunner({("ip", "-j", "addr", "show"): result(("ip",), "garbage")})
    interfaces, _, issues, _ = collect_network(runner, make_redactor(), sysfs_root)
    assert interfaces == []
    assert issues[0].error == "invalid_json"


def test_unexpected_payload_shape_does_not_crash(sysfs_root):
    assert parse_addr_payload({"not": "a list"}, make_redactor(), sysfs_root) == []
    assert parse_routes("nonsense", make_redactor()) == []
    assert parse_addr_payload([1, None, {}, {"ifname": ""}], make_redactor(), sysfs_root) == []
