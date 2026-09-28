"""Sentry engine contract: parsing, classification, and the anomaly diff.

These tests never touch the live system — they feed captured command text to the
pure parsers and hand-built snapshots to the pure diff. Run with:

    pytest agents/sentry/tests -v
"""

from __future__ import annotations

import pytest

from sentry import collectors, engine
from sentry.baseline import BaselineStore
from sentry.models import Connection, Device, Listener, Snapshot

ARP_SAMPLE = """\
console.gl-inet.com (192.168.10.1) at 94:83:c4:a8:81:19 on en0 ifscope [ethernet]
mac.lan (192.168.10.105) at 2e:d0:e8:aa:a0:5 on en0 ifscope [ethernet]
iphone.lan (192.168.10.155) at 0:5b:94:2:e6:14 on en0 ifscope [ethernet]
? (192.168.10.66) at (incomplete) on en0 ifscope [ethernet]
? (192.168.10.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
mdns.mcast.net (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""

ROUTE_SAMPLE = """\
   route to: default
destination: default
    gateway: 192.168.10.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
"""

LISTEN_SAMPLE = """\
COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
rapportd    977   as   12u  IPv4 0xac9dbfba11240ff3      0t0  TCP *:56355 (LISTEN)
ControlCe  1347   as   11u  IPv4 0x6b1d5b7d05ea1add      0t0  TCP *:5000 (LISTEN)
postgres    880   as    7u  IPv4 0xdeadbeef0000      0t0  TCP 127.0.0.1:5432 (LISTEN)
"""

ESTABLISHED_SAMPLE = """\
COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
firefox    2201   as   40u  IPv4 0xaaaa      0t0  TCP 192.168.10.105:52012->140.82.112.3:443 (ESTABLISHED)
rapportd    977   as   17u  IPv6 0x50a6      0t0  TCP [fe80:b::454]:56355->[fe80:b::4f7]:55328 (ESTABLISHED)
"""


# ── parsers ───────────────────────────────────────────────────────────────

def test_parse_arp_keeps_physical_hosts_only():
    devices = collectors.parse_arp(ARP_SAMPLE)
    ips = {d.ip for d in devices}
    assert ips == {"192.168.10.1", "192.168.10.105", "192.168.10.155"}
    # incomplete, broadcast and multicast rows are dropped
    assert "192.168.10.66" not in ips
    assert "192.168.10.255" not in ips
    assert "224.0.0.251" not in ips


def test_mac_normalisation_pads_octets():
    # "0:5b:94:2:e6:14" and "00:5b:94:02:e6:14" are the same NIC.
    assert collectors.normalize_mac("0:5b:94:2:e6:14") == "00:5b:94:02:e6:14"
    device = [d for d in collectors.parse_arp(ARP_SAMPLE) if d.ip == "192.168.10.155"][0]
    assert device.mac == "00:5b:94:02:e6:14"


NDP_SAMPLE = """\
Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%lo0                             (incomplete)         lo0 permanent R
fe80::454:59b0:1c69:1b01%en0            aa:29:ec:7b:9e:5d    en0 permanent R
fe80::46f:4b20:2df5:7ea6%en0            0:5b:94:2:e6:14      en0 23h56m36s S
"""


def test_parse_ndp_strips_scope_and_skips_loopback_and_incomplete():
    devices = collectors.parse_ndp(NDP_SAMPLE)
    ips = {d.ip for d in devices}
    assert ips == {"fe80::454:59b0:1c69:1b01", "fe80::46f:4b20:2df5:7ea6"}
    padded = [d for d in devices if d.ip == "fe80::46f:4b20:2df5:7ea6"][0]
    assert padded.mac == "00:5b:94:02:e6:14"  # normalised
    assert padded.interface == "en0"


def test_parse_default_route():
    assert collectors.parse_default_route(ROUTE_SAMPLE) == ("192.168.10.1", "en0")


def test_parse_listeners_reads_protocol_addr_port():
    listeners = collectors.parse_lsof_listeners(LISTEN_SAMPLE)
    keys = {l.key() for l in listeners}
    assert "tcp:*:5000" in keys
    assert "tcp:127.0.0.1:5432" in keys
    pg = [l for l in listeners if l.port == 5432][0]
    assert pg.process == "postgres" and pg.pid == 880


def test_parse_connections_extracts_remote_endpoint():
    conns = collectors.parse_lsof_connections(ESTABLISHED_SAMPLE)
    ff = [c for c in conns if c.process == "firefox"][0]
    assert ff.remote_address == "140.82.112.3" and ff.remote_port == 443


def test_classify_address_buckets():
    assert collectors.classify_address("140.82.112.3") == "public"
    assert collectors.classify_address("192.168.1.5") == "private"
    assert collectors.classify_address("127.0.0.1") == "loopback"
    assert collectors.classify_address("fe80::1") == "link-local"
    assert collectors.classify_address("*") == "wildcard"


# ── diff ────────────────────────────────────────────────────────────────────

def _baseline():
    gw = Device(ip="192.168.10.1", mac="94:83:c4:a8:81:19", interface="en0")
    return Snapshot(
        gateway_ip="192.168.10.1",
        gateway_mac="94:83:c4:a8:81:19",
        devices=[gw, Device(ip="192.168.10.105", mac="aa:bb:cc:dd:ee:01", interface="en0")],
        listeners=[Listener(protocol="tcp", address="127.0.0.1", port=5432, process="postgres")],
        connections=[],
    )


def test_new_device_is_a_notice():
    baseline = _baseline()
    current = Snapshot(
        gateway_ip="192.168.10.1", gateway_mac="94:83:c4:a8:81:19",
        devices=baseline.devices + [Device(ip="192.168.10.200", mac="de:ad:be:ef:00:99", interface="en0")],
    )
    findings = engine.diff(baseline, current)
    kinds = {f.kind for f in findings}
    assert "new_device" in kinds
    dev = [f for f in findings if f.kind == "new_device"][0]
    assert dev.severity == "notice"
    assert dev.evidence["mac"] == "de:ad:be:ef:00:99"


def test_gateway_impersonation_is_an_alert():
    baseline = _baseline()
    # Two MACs now answer for the gateway IP -> ARP spoof, on the gateway.
    current = Snapshot(
        gateway_ip="192.168.10.1", gateway_mac="94:83:c4:a8:81:19",
        devices=[
            Device(ip="192.168.10.1", mac="94:83:c4:a8:81:19", interface="en0"),
            Device(ip="192.168.10.1", mac="66:66:66:66:66:66", interface="en0"),
        ],
    )
    findings = engine.diff(baseline, current)
    spoof = [f for f in findings if f.kind == "arp_spoof"]
    assert spoof and spoof[0].severity == "alert"
    # strongest finding sorts first
    assert findings[0].severity == "alert"


def test_gateway_mac_change_is_an_alert():
    baseline = _baseline()
    current = Snapshot(
        gateway_ip="192.168.10.1", gateway_mac="00:11:22:33:44:55",
        devices=[Device(ip="192.168.10.1", mac="00:11:22:33:44:55", interface="en0")],
    )
    findings = engine.diff(baseline, current)
    change = [f for f in findings if f.kind == "gateway_mac_change"]
    assert change and change[0].severity == "alert"
    assert change[0].evidence["was"] == "94:83:c4:a8:81:19"


def test_new_exposed_listener_is_a_warning_loopback_is_not():
    baseline = _baseline()
    current = Snapshot(
        gateway_ip="192.168.10.1", gateway_mac="94:83:c4:a8:81:19",
        devices=baseline.devices,
        listeners=baseline.listeners + [
            Listener(protocol="tcp", address="*", port=8080, process="python"),
            Listener(protocol="tcp", address="127.0.0.1", port=6000, process="devtool"),
        ],
    )
    findings = {f.evidence.get("port"): f for f in engine.diff(baseline, current) if f.kind == "new_listener"}
    assert findings[8080].severity == "warning"
    assert findings[6000].severity == "notice"


def test_new_public_connection_reported_local_chatter_ignored():
    baseline = _baseline()
    current = Snapshot(
        gateway_ip="192.168.10.1", gateway_mac="94:83:c4:a8:81:19",
        devices=baseline.devices,
        connections=[
            Connection(protocol="tcp", remote_address="140.82.112.3", remote_port=443, process="firefox"),
            Connection(protocol="tcp", remote_address="fe80::4f7", remote_port=55328, process="rapportd"),
        ],
    )
    findings = [f for f in engine.diff(baseline, current) if f.kind == "new_connection"]
    assert len(findings) == 1
    assert findings[0].evidence["remote_address"] == "140.82.112.3"


def test_identical_snapshot_yields_nothing():
    baseline = _baseline()
    same = Snapshot(
        gateway_ip=baseline.gateway_ip, gateway_mac=baseline.gateway_mac,
        devices=list(baseline.devices), listeners=list(baseline.listeners),
        connections=list(baseline.connections),
    )
    assert engine.diff(baseline, same) == []


# ── persistence / run_watch ─────────────────────────────────────────────────

def test_first_run_establishes_baseline_without_findings(tmp_path):
    store = BaselineStore(tmp_path)
    snap = Snapshot(
        gateway_ip="192.168.10.1", gateway_mac="94:83:c4:a8:81:19",
        devices=[Device(ip="192.168.10.1", mac="94:83:c4:a8:81:19", interface="en0")],
    )
    result = engine.run_watch(store, snapshot=snap)
    assert result["baseline_established"] is True
    assert result["findings"] == []
    assert store.has_baseline()


def test_second_run_reports_then_folds_into_baseline(tmp_path):
    store = BaselineStore(tmp_path)
    first = Snapshot(
        gateway_ip="192.168.10.1", gateway_mac="94:83:c4:a8:81:19",
        devices=[Device(ip="192.168.10.1", mac="94:83:c4:a8:81:19", interface="en0")],
    )
    engine.run_watch(store, snapshot=first)

    second = Snapshot(
        gateway_ip="192.168.10.1", gateway_mac="94:83:c4:a8:81:19",
        devices=first.devices + [Device(ip="192.168.10.50", mac="12:34:56:78:9a:bc", interface="en0")],
    )
    result = engine.run_watch(store, snapshot=second)
    assert any(f["kind"] == "new_device" for f in result["findings"])
    assert store.load_findings()  # appended to the log

    # A third identical pass must not re-report the now-known device.
    third = engine.run_watch(store, snapshot=second)
    assert third["findings"] == []
