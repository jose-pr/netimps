"""Concurrent port and host scanning (internal).

Sweeping a port range or a subnet is trivially parallel and painfully slow
serially: 1024 ports at a 1s timeout is 17 minutes sequentially and a couple of
seconds with a thread pool. Both scanners here are thin, honest wrappers over
:func:`netimps.tcp_check`.

Re-exported from :mod:`netimps`.

Scope
-----
This is a **reachability** sweep, not a security scanner. It performs ordinary
full TCP connects -- no SYN/stealth scanning, no service fingerprinting, no OS
detection -- which means connections are logged by the target like any other.
Use it on hosts you are responsible for.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor as _ThreadPool
from typing import List, Optional, Sequence, Tuple

__all__ = ["scan_ports", "scan_hosts", "PORT_RANGES"]

#: Handy port sets for the common cases, so callers need not spell them out.
PORT_RANGES = {
    #: The IANA well-known range. ~1s with the default concurrency.
    "well-known": tuple(range(1, 1024)),
    #: Ports actually worth checking on a typical host -- two orders of
    #: magnitude faster than a full sweep and finds nearly as much.
    "common": (
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        123,
        135,
        139,
        143,
        389,
        443,
        445,
        465,
        587,
        631,
        636,
        993,
        995,
        1080,
        1433,
        1521,
        3000,
        3306,
        3389,
        5000,
        5432,
        5900,
        6379,
        8000,
        8080,
        8443,
        9000,
        9200,
        27017,
    ),
    #: Everything. Slow: prefer a narrower set unless you truly need it.
    "all": tuple(range(1, 65536)),
}

#: Default worker count. Chosen because these tasks are entirely I/O-bound --
#: threads sit in connect() -- so the useful ceiling is far above the CPU count.
#: Above ~200 the OS starts refusing sockets on some platforms.
_DEFAULT_WORKERS = 100


def _resolve_ports(ports) -> "Sequence[int]":
    """Normalise a port specification to a tuple of port numbers.

    Accepts a :data:`PORT_RANGES` name, a **scheme name** (``"https"`` ->
    443, via :func:`netimps.get_default_port`), a single int, a numeric string,
    or any iterable mixing those::

        _resolve_ports("common")            # the named set
        _resolve_ports("https")             # (443,)
        _resolve_ports(["ssh", 8080])       # (22, 8080)

    Range names win over scheme names where they collide, since a caller
    writing ``"common"`` means the set.
    """
    from . import get_default_port

    if isinstance(ports, str):
        if ports in PORT_RANGES:
            return PORT_RANGES[ports]
        resolved = _port_number(ports, get_default_port)
        if resolved is not None:
            return (resolved,)
        raise ValueError(
            "unknown port range or scheme %r (ranges: %s)"
            % (ports, ", ".join(sorted(PORT_RANGES)))
        )
    if isinstance(ports, int):
        return (ports,)

    out = []
    for entry in ports:
        if isinstance(entry, int):
            out.append(entry)
            continue
        resolved = _port_number(entry, get_default_port)
        if resolved is None:
            raise ValueError("cannot resolve %r to a port number" % (entry,))
        out.append(resolved)
    return tuple(out)


def _port_number(value, get_default_port) -> "Optional[int]":
    """A single port spec to a number: ``"443"``, ``"https"``, or ``None``."""
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    return get_default_port(text)


def scan_ports(
    host: str,
    ports="common",
    timeout: float = 1.0,
    workers: int = _DEFAULT_WORKERS,
) -> "List[int]":
    """Return the sorted open TCP ports on ``host``.

    ::

        scan_ports("192.168.1.1")                    # the 'common' set
        scan_ports("localhost", "well-known")        # ports 1-1023
        scan_ports("10.0.0.5", range(8000, 8100))
        scan_ports("10.0.0.5", [22, 80, 443])
        scan_ports("10.0.0.5", "https")              # scheme name -> 443
        scan_ports("10.0.0.5", ["ssh", "https"])     # -> 22, 443

    :param ports: a :data:`PORT_RANGES` name (``"common"``, ``"well-known"``,
        ``"all"``), a scheme name resolved via :func:`get_default_port`, a port
        number, or any iterable mixing those. A range name wins over a scheme
        name where the two collide.
    :param timeout: per-port connect timeout. This bounds the whole scan
        (``timeout`` x rounds), so keep it small on a large range -- but not so
        small that a slow host reads as closed.
    :param workers: concurrent connections. These tasks are I/O-bound, so the
        useful number is far above the CPU count; very high values can exhaust
        file descriptors or trip rate limiting.

    Open means "the TCP handshake completed" -- not that the service is
    healthy, and not that a filtered port is distinguishable from a closed one
    (both simply fail to connect).
    """
    from . import tcp_check

    targets = _resolve_ports(ports)
    if not targets:
        return []

    open_ports = []
    with _ThreadPool(max_workers=min(workers, len(targets))) as pool:
        results = pool.map(lambda p: (p, tcp_check(host, p, timeout)), targets)
        open_ports = [port for port, is_open in results if is_open]
    return sorted(open_ports)


def scan_hosts(
    network,
    port: "Optional[int]" = None,
    ports=None,
    timeout: float = 1.0,
    workers: int = _DEFAULT_WORKERS,
) -> "List[Tuple[object, List[int]]]":
    """Find responsive hosts on ``network``, with the ports each answers on.

    ::

        scan_hosts("192.168.1.0/24", port=22)        # who has SSH open
        scan_hosts("10.0.0.0/28", ports=[80, 443])
        scan_hosts("192.168.1.0/24")                 # the 'common' set each
        scan_hosts("192.168.1.0/24", port="https")   # scheme name works too

    :param network: anything :func:`netimps.parse` accepts as a network. Only
        usable host addresses are probed -- the network and broadcast addresses
        are skipped.
    :param port: shorthand for ``ports=[port]``. Accepts a scheme name too, so
        ``port="ssh"`` is ``port=22``.
    :param ports: ports to probe per host; defaults to the ``"common"`` set.
        Same forms as :func:`scan_ports`.
    :param timeout: per-connection timeout.
    :param workers: total concurrent connections across all hosts.

    Returns ``[(address, [open_ports]), ...]`` sorted by address, including
    only hosts with at least one open port.

    .. note::
       This is a **TCP** sweep, so a host that is up but answers on none of the
       probed ports does not appear. That is the honest result for the question
       asked -- it is not an ARP or ICMP discovery scan, and a firewalled host
       is indistinguishable from an absent one. Widen ``ports`` if you need
       better coverage.

    Refuses networks larger than /16 (or IPv6 /112): a /8 sweep is 16 million
    hosts, which is a mistake rather than an intention.
    """
    from . import IPNetwork, parse, tcp_check

    net = parse(network, IPNetwork)
    if net.version == 4 and net.prefixlen < 16:
        raise ValueError(
            "%s has %d addresses; scan a /16 or smaller" % (net, net.num_addresses)
        )
    if net.version == 6 and net.prefixlen < 112:
        raise ValueError("%s is too large to sweep; scan a /112 or smaller" % (net,))

    if port is not None and ports is not None:
        raise ValueError("pass either port or ports, not both")
    targets = _resolve_ports([port] if port is not None else (ports or "common"))
    if not targets:
        return []

    # A /31 or /32 has no separate network/broadcast address, and .hosts()
    # already accounts for that.
    addresses = list(net.hosts()) or [net.network_address]
    work = [(address, probe) for address in addresses for probe in targets]

    found = {}
    with _ThreadPool(max_workers=min(workers, len(work))) as pool:
        results = pool.map(
            lambda item: (item[0], item[1], tcp_check(str(item[0]), item[1], timeout)),
            work,
        )
        for address, probe, is_open in results:
            if is_open:
                found.setdefault(address, []).append(probe)

    return [(address, sorted(found[address])) for address in sorted(found)]
