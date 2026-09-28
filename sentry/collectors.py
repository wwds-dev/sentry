"""Read-only observation of the local network and this host.

Every function here either shells out to a macOS command that needs no
privileges (``arp``, ``route``, ``lsof``) or parses that command's text. The
parsers are deliberately split from the subprocess wrappers so the interesting
logic is testable against captured fixtures with no live system involved.

Nothing in this module sends a packet, opens a socket, changes an interface, or
touches a remote host. It reads the neighbour table the OS already has and the
sockets this machine already owns.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess

from .models import Connection, Device, Listener

# name (ip) at mac on iface ...   — mac may be "(incomplete)"
_ARP_RE = re.compile(
    r"^(?P<name>\S+)\s+\((?P<ip>[0-9.]+)\)\s+at\s+"
    r"(?P<mac>[0-9a-fA-F:]+|\(incomplete\))\s+on\s+(?P<iface>\S+)"
)
# lsof NAME field for a listener: "*:5000", "127.0.0.1:5000", "[::1]:5000"
_LISTEN_RE = re.compile(r"^(?P<addr>.*?):(?P<port>\d+)$")
# lsof NAME field for an established conn: "local:port->remote:port"
_CONN_RE = re.compile(r"^(?P<local>.+?)->(?P<remote>.+)$")


def normalize_mac(mac: str) -> str:
    """Zero-pad each octet and lowercase, so ``0:5b:94:2`` == ``00:5b:94:02``.

    macOS ``arp`` prints octets without leading zeros; left as-is, the same NIC
    would look like two different MACs across runs and every device would read
    as "new". Anything that is not a clean 6-octet MAC is returned lowercased
    and untouched.
    """
    parts = mac.strip().lower().split(":")
    if len(parts) != 6:
        return mac.strip().lower()
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return mac.strip().lower()


def is_physical_mac(mac: str) -> bool:
    """False for broadcast and IPv4/IPv6 multicast MACs (ARP table noise)."""
    mac = normalize_mac(mac)
    if mac in ("ff:ff:ff:ff:ff:ff", ""):
        return False
    if mac.startswith("01:00:5e") or mac.startswith("33:33"):
        return False
    return bool(re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", mac))


def classify_address(address: str) -> str:
    """Bucket an address as loopback / link-local / private / multicast / public.

    Used to weight findings: a brand-new connection to a *public* endpoint is
    worth more attention than yet another link-local AirDrop chat.
    """
    addr = address.strip().strip("[]")
    if not addr or addr == "*":
        return "wildcard"
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "hostname"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    return "public"


# ── Pure parsers ────────────────────────────────────────────────────────────

def parse_arp(text: str) -> list[Device]:
    """Parse ``arp -a`` output into physical neighbour devices."""
    devices: list[Device] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        match = _ARP_RE.match(line.strip())
        if not match:
            continue
        raw_mac = match.group("mac")
        if raw_mac == "(incomplete)":
            continue
        mac = normalize_mac(raw_mac)
        if not is_physical_mac(mac):
            continue
        ip = match.group("ip")
        if (mac, ip) in seen:
            continue
        seen.add((mac, ip))
        devices.append(Device(ip=ip, mac=mac, interface=match.group("iface")))
    return devices


def parse_ndp(text: str) -> list[Device]:
    """Parse ``ndp -an`` (IPv6 neighbour table) into physical neighbour devices.

    Columns are ``Neighbor Linklayer Netif Expire St Flgs``. The neighbour
    address carries a ``%scope`` suffix (``fe80::1%en0``) which we strip. Merging
    this with ARP means an IPv6-only neighbour is still visible, and it keeps the
    device list populated on hosts where the IPv4 ARP cache reads empty.
    """
    devices: list[Device] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 3 or cols[0] == "Neighbor":
            continue
        raw_mac = cols[1]
        if raw_mac == "(incomplete)":
            continue
        mac = normalize_mac(raw_mac)
        if not is_physical_mac(mac):
            continue
        ip = cols[0].split("%", 1)[0]
        interface = cols[2]
        if interface == "lo0":
            continue
        if (mac, ip) in seen:
            continue
        seen.add((mac, ip))
        devices.append(Device(ip=ip, mac=mac, interface=interface))
    return devices


def parse_default_route(text: str) -> tuple[str, str]:
    """Return (gateway_ip, interface) from ``route -n get default``."""
    gateway = ""
    interface = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("gateway:"):
            gateway = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("interface:"):
            interface = stripped.split(":", 1)[1].strip()
    return gateway, interface


def _split_lsof_name(name: str) -> tuple[str, int] | None:
    match = _LISTEN_RE.match(name.strip())
    if not match:
        return None
    try:
        return match.group("addr"), int(match.group("port"))
    except ValueError:
        return None


def parse_lsof_listeners(text: str) -> list[Listener]:
    """Parse ``lsof -nP -iTCP -sTCP:LISTEN`` (and the UDP variant) output."""
    listeners: list[Listener] = []
    seen: set[str] = set()
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 9 or cols[0] == "COMMAND":
            continue
        protocol = cols[7].lower()
        if protocol not in ("tcp", "udp"):
            continue
        name = cols[8]
        parsed = _split_lsof_name(name)
        if not parsed:
            continue
        addr, port = parsed
        try:
            pid = int(cols[1])
        except ValueError:
            pid = None
        listener = Listener(
            protocol=protocol, address=addr.strip("[]"), port=port,
            process=cols[0], pid=pid,
        )
        if listener.key() in seen:
            continue
        seen.add(listener.key())
        listeners.append(listener)
    return listeners


def parse_lsof_connections(text: str) -> list[Connection]:
    """Parse ``lsof -nP -iTCP -sTCP:ESTABLISHED`` output into outbound conns."""
    connections: list[Connection] = []
    seen: set[str] = set()
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 9 or cols[0] == "COMMAND":
            continue
        protocol = cols[7].lower()
        if protocol not in ("tcp", "udp"):
            continue
        name = cols[8]
        conn_match = _CONN_RE.match(name.strip())
        if not conn_match:
            continue
        remote = _split_lsof_name(conn_match.group("remote"))
        if not remote:
            continue
        raddr, rport = remote
        try:
            pid = int(cols[1])
        except ValueError:
            pid = None
        conn = Connection(
            protocol=protocol, remote_address=raddr.strip("[]"), remote_port=rport,
            process=cols[0], pid=pid,
        )
        if conn.key() in seen:
            continue
        seen.add(conn.key())
        connections.append(conn)
    return connections


# ── Subprocess wrappers (thin; the parsing above is what carries the logic) ──

def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout or ""


def collect_devices() -> list[Device]:
    """Neighbour table from both stacks: IPv4 ARP and IPv6 NDP, merged."""
    merged: dict[tuple[str, str], Device] = {}
    for device in parse_arp(_run(["arp", "-an"])) + parse_ndp(_run(["ndp", "-an"])):
        merged.setdefault((device.mac, device.ip), device)
    return list(merged.values())


def collect_default_route() -> tuple[str, str]:
    return parse_default_route(_run(["route", "-n", "get", "default"]))


def collect_listeners() -> list[Listener]:
    tcp = parse_lsof_listeners(_run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]))
    udp = parse_lsof_listeners(_run(["lsof", "-nP", "-iUDP"]))
    merged: dict[str, Listener] = {l.key(): l for l in tcp}
    for listener in udp:
        merged.setdefault(listener.key(), listener)
    return list(merged.values())


def collect_connections() -> list[Connection]:
    return parse_lsof_connections(_run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"]))


def gateway_mac(gateway_ip: str, devices: list[Device]) -> str:
    for device in devices:
        if device.ip == gateway_ip:
            return device.mac
    return ""
