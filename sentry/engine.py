"""Turn observations into findings, and drive one watch pass.

``diff`` is the heart of Sentry and is a pure function: given a trusted baseline
and a fresh snapshot, it returns the findings without touching disk, the clock,
or the system. Everything above it (collecting a live snapshot, persisting the
baseline, appending to the log) is thin orchestration around that function.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from . import collectors
from .baseline import BaselineStore
from .models import (
    Connection,
    Device,
    Finding,
    Listener,
    Snapshot,
    severity_rank,
)


def collect_snapshot() -> Snapshot:
    """Observe the live system, read-only, and return a timestamped snapshot."""
    devices = collectors.collect_devices()
    gateway_ip, _iface = collectors.collect_default_route()
    return Snapshot(
        gateway_ip=gateway_ip,
        gateway_mac=collectors.gateway_mac(gateway_ip, devices),
        devices=devices,
        listeners=collectors.collect_listeners(),
        connections=collectors.collect_connections(),
        taken_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


def _device_findings(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    known_macs = {d.key() for d in baseline.devices}

    # New host on the segment.
    for device in current.devices:
        if device.key() not in known_macs:
            findings.append(Finding(
                severity="notice",
                kind="new_device",
                title=f"New device on the network: {device.ip} ({device.mac})",
                detail=(
                    "A host not seen on earlier trusted passes appeared on "
                    f"interface {device.interface or '?'}. Confirm it is yours "
                    "or expected before trusting the segment."
                ),
                evidence={"ip": device.ip, "mac": device.mac, "interface": device.interface},
            ))

    # ARP anomaly: one IP claimed by several MACs is the classic spoof / MITM
    # tell. (One MAC holding several IPs is ordinary — dual-stack hosts, routers,
    # VLANs — so it is deliberately not treated as a signal.)
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    for device in current.devices:
        ip_to_macs[device.ip].add(device.mac)
    baseline_ip_to_macs: dict[str, set[str]] = defaultdict(set)
    for device in baseline.devices:
        baseline_ip_to_macs[device.ip].add(device.mac)
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            # Report only when a MAC newly claims this IP. merge_into_baseline
            # unions devices, so once a conflict is folded in, an unchanged
            # duplicate mapping is not re-reported on every pass (which would
            # otherwise flood the log and evict real history); a genuinely new
            # conflicting MAC still is.
            if macs <= baseline_ip_to_macs.get(ip, set()):
                continue
            severity = "alert" if ip == current.gateway_ip else "warning"
            findings.append(Finding(
                severity=severity,
                kind="arp_spoof",
                title=f"Address conflict: {ip} is claimed by {len(macs)} MACs",
                detail=(
                    "Multiple hardware addresses answering for one IP is a "
                    "signature of ARP spoofing / a man-in-the-middle. "
                    + ("This is the default gateway — treat the network as "
                       "untrusted until resolved." if ip == current.gateway_ip
                       else "Verify which host legitimately owns this address.")
                ),
                evidence={"ip": ip, "macs": sorted(macs)},
            ))

    # Gateway hardware changed since the trusted baseline.
    if (baseline.gateway_ip and baseline.gateway_ip == current.gateway_ip
            and baseline.gateway_mac and current.gateway_mac
            and baseline.gateway_mac != current.gateway_mac):
        findings.append(Finding(
            severity="alert",
            kind="gateway_mac_change",
            title="Default gateway hardware address changed",
            detail=(
                f"The gateway {current.gateway_ip} now answers from "
                f"{current.gateway_mac}, previously {baseline.gateway_mac}. "
                "This can be a router swap — or a device impersonating your "
                "gateway to intercept traffic."
            ),
            evidence={
                "gateway": current.gateway_ip,
                "was": baseline.gateway_mac,
                "now": current.gateway_mac,
            },
        ))
    return findings


def _listener_findings(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    known = {l.key() for l in baseline.listeners}
    for listener in current.listeners:
        if listener.key() in known:
            continue
        exposure = collectors.classify_address(listener.address)
        externally_reachable = exposure in ("wildcard", "public", "private")
        findings.append(Finding(
            severity="warning" if externally_reachable else "notice",
            kind="new_listener",
            title=(
                f"New listening service: {listener.process or '?'} on "
                f"{listener.protocol}/{listener.port}"
            ),
            detail=(
                f"A process began accepting connections on {listener.address}:"
                f"{listener.port}. "
                + ("It is bound to an externally reachable address — confirm it "
                   "should be exposed." if externally_reachable
                   else "It is bound to loopback only.")
            ),
            evidence={
                "process": listener.process, "pid": listener.pid,
                "protocol": listener.protocol, "address": listener.address,
                "port": listener.port, "exposure": exposure,
            },
        ))
    return findings


def _connection_findings(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    known = {c.key() for c in baseline.connections}
    for conn in current.connections:
        if conn.key() in known:
            continue
        reach = collectors.classify_address(conn.remote_address)
        if reach in ("loopback", "link-local", "multicast"):
            continue  # local chatter (AirDrop, mDNS, Handoff) — not worth a card
        findings.append(Finding(
            severity="notice" if reach == "public" else "info",
            kind="new_connection",
            title=(
                f"New outbound connection: {conn.process or '?'} → "
                f"{conn.remote_address}:{conn.remote_port}"
            ),
            detail=(
                f"{conn.process or 'A process'} opened a {reach} connection to "
                f"{conn.remote_address}:{conn.remote_port} not seen on earlier "
                "passes."
            ),
            evidence={
                "process": conn.process, "pid": conn.pid,
                "remote_address": conn.remote_address,
                "remote_port": conn.remote_port, "reach": reach,
            },
        ))
    return findings


def diff(baseline: Snapshot, current: Snapshot) -> list[Finding]:
    """Compare a trusted baseline with a fresh snapshot; return findings.

    Pure: no I/O, no clock, no system access. Findings come back strongest-first.
    """
    findings: list[Finding] = []
    findings += _device_findings(baseline, current)
    findings += _listener_findings(baseline, current)
    findings += _connection_findings(baseline, current)
    findings.sort(key=lambda f: severity_rank(f.severity), reverse=True)
    return findings


# Outbound endpoints accumulate forever across passes, so the connections
# baseline is capped: without a bound it grows unbounded and is fully
# re-serialised every pass. The cap is generous enough that eviction (which can
# re-report a long-idle endpoint once) is rare in practice.
MAX_BASELINE_CONNECTIONS = 4096


def merge_into_baseline(baseline: Snapshot, current: Snapshot) -> Snapshot:
    """Fold a snapshot into the baseline so seen items are not re-reported.

    The gateway is taken from the current pass (so a legitimate router change
    settles after being reported once); devices, listeners and connections are
    the union of both, keyed by identity.
    """
    def _union(existing, incoming, cap=None):
        merged = {item.key(): item for item in existing}
        for item in incoming:
            merged.setdefault(item.key(), item)
        values = list(merged.values())
        # Keep the most recent when capped: incoming items were setdefault-ed
        # after the existing ones, so the tail holds the newest endpoints.
        return values[-cap:] if cap is not None else values

    return Snapshot(
        gateway_ip=current.gateway_ip or baseline.gateway_ip,
        gateway_mac=current.gateway_mac or baseline.gateway_mac,
        devices=_union(baseline.devices, current.devices),
        listeners=_union(baseline.listeners, current.listeners),
        connections=_union(baseline.connections, current.connections,
                           cap=MAX_BASELINE_CONNECTIONS),
        taken_at=current.taken_at,
    )


def run_watch(store: BaselineStore | None = None, *, snapshot: Snapshot | None = None) -> dict:
    """One watch pass: snapshot → diff → persist. Returns a summary dict.

    On the very first run there is no baseline, so the snapshot is adopted as the
    baseline and no findings are raised (everything is "new" only relative to
    nothing). Callers get ``{"baseline_established": True}`` so the UI can say so.
    """
    store = store or BaselineStore()
    current = snapshot if snapshot is not None else collect_snapshot()

    baseline = store.load_baseline()
    if baseline is None:
        store.save_baseline(current)
        return {
            "baseline_established": True,
            "findings": [],
            "device_count": len(current.devices),
            "listener_count": len(current.listeners),
            "connection_count": len(current.connections),
            "taken_at": current.taken_at,
        }

    findings = diff(baseline, current)
    store.append_findings(findings)
    store.save_baseline(merge_into_baseline(baseline, current))

    top = findings[0].severity if findings else "info"
    return {
        "baseline_established": False,
        "findings": [f.as_dict() for f in findings],
        "top_severity": top,
        "device_count": len(current.devices),
        "listener_count": len(current.listeners),
        "connection_count": len(current.connections),
        "taken_at": current.taken_at,
    }
