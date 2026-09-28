"""Typed records for Sentry's read-only network observation.

Everything here is a plain dataclass so a snapshot can be serialised to JSON for
the baseline store and compared field-by-field in tests without touching the
live system. Severity is a small closed vocabulary the panel maps to colour.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Ordered weakest -> strongest so callers can sort or threshold on the index.
SEVERITY_ORDER = ("info", "notice", "warning", "alert")


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


@dataclass(frozen=True)
class Device:
    """A host seen on the local segment via the ARP/NDP neighbour table."""

    ip: str
    mac: str
    interface: str = ""

    def key(self) -> str:
        # MAC is the stable identity; a device keeps its identity across a DHCP
        # lease change, and an IP that hops between MACs is exactly the spoof
        # signal we want to keep visible rather than collapse away.
        return self.mac.lower()


@dataclass(frozen=True)
class Listener:
    """A socket this host is accepting connections on."""

    protocol: str  # "tcp" / "udp"
    address: str   # bound local address, e.g. "*" or "127.0.0.1"
    port: int
    process: str = ""
    pid: int | None = None

    def key(self) -> str:
        return f"{self.protocol}:{self.address}:{self.port}"


@dataclass(frozen=True)
class Connection:
    """An established outbound connection from this host."""

    protocol: str
    remote_address: str
    remote_port: int
    process: str = ""
    pid: int | None = None

    def key(self) -> str:
        # Deliberately not keyed on the ephemeral local port: the same app
        # talking to the same endpoint should read as one relationship, not a
        # new one every time the kernel picks a fresh source port.
        return f"{self.protocol}:{self.remote_address}:{self.remote_port}"


@dataclass(frozen=True)
class Finding:
    """One thing worth a human's attention, produced by diffing snapshots."""

    severity: str          # one of SEVERITY_ORDER
    kind: str              # machine tag, e.g. "new_device", "arp_spoof"
    title: str             # one-line human summary
    detail: str = ""       # longer explanation / recommendation
    evidence: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Snapshot:
    """Everything one observation pass saw. Serialises straight to the store."""

    gateway_ip: str = ""
    gateway_mac: str = ""
    devices: list[Device] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    taken_at: str = ""  # ISO 8601 UTC; empty on an in-memory-only snapshot

    def as_dict(self) -> dict:
        return {
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "devices": [asdict(d) for d in self.devices],
            "listeners": [asdict(l) for l in self.listeners],
            "connections": [asdict(c) for c in self.connections],
            "taken_at": self.taken_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        data = data or {}
        return cls(
            gateway_ip=data.get("gateway_ip", ""),
            gateway_mac=data.get("gateway_mac", ""),
            devices=[Device(**d) for d in data.get("devices", [])],
            listeners=[Listener(**l) for l in data.get("listeners", [])],
            connections=[Connection(**c) for c in data.get("connections", [])],
            taken_at=data.get("taken_at", ""),
        )
