"""Concurrent port and host scanning (internal).

Sweeping a port range or a subnet is trivially parallel and painfully slow
serially: 1024 ports at a 1s timeout is 17 minutes sequentially and a couple of
seconds with a thread pool. Both scanners here are thin, honest wrappers over
:func:`netimps.tcp_check`, with one addition: the destination is resolved
**once** for the whole scan rather than once per probe, because ``tcp_check``
resolves on every call and a failing lookup is indistinguishable from a closed
port in its answer.

Re-exported from :mod:`netimps`.

Scope
-----
This is a **reachability** sweep, not a security scanner. It performs ordinary
full TCP connects -- no SYN/stealth scanning, no service fingerprinting, no OS
detection -- which means connections are logged by the target like any other.
Use it on hosts you are responsible for.
"""

from __future__ import annotations

import socket as _socket
from concurrent.futures import ThreadPoolExecutor as _ThreadPool
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from ._ip import AddressLike, IPAddress, IPNetworkLike, _dst_argument
from ._scheme import coerce_port

__all__ = ["scan_ports", "scan_hosts", "PORT_RANGES"]

#: A :data:`PORT_RANGES` name, a scheme name (:func:`get_default_port`), a
#: port number, a numeric string, or any iterable mixing those.
PortsLike = Union[str, int, Iterable[Union[str, int]]]

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

#: The smallest timeout a probe is allowed to run with. ``settimeout(0)`` puts
#: a socket in **non-blocking** mode rather than meaning "do not wait", so a
#: zero timeout reports every port -- open or not -- as closed. 1ms is the
#: smallest value that still blocks, and is far below any real connect.
_MIN_TIMEOUT = 0.001


def _floor_timeout(timeout: float) -> float:
    """Clamp a probe timeout away from zero.

    A caller passing ``timeout=0`` means "be quick", which is a reasonable
    request; what ``socket.settimeout(0)`` delivers is a non-blocking socket
    whose ``connect`` raises ``BlockingIOError`` immediately, so every port
    reads as closed -- a full scan's worth of confidently wrong answers.
    :func:`netimps.ping` already rounds a sub-second POSIX timeout **up** so
    it never becomes 0; this is the same precedent for the socket path.

    A negative timeout has no such reading -- ``settimeout`` rejects it -- so
    it raises :class:`ValueError` rather than being silently floored.
    """
    value = float(timeout)
    if value < 0:
        raise ValueError("timeout must not be negative: %r" % (timeout,))
    return max(value, _MIN_TIMEOUT)


def _probe_addresses(host: "AddressLike") -> "List[str]":
    """Resolve ``host`` to address literals **once**, for a whole scan.

    :func:`netimps.tcp_check` resolves its destination on every call, and a
    scan dispatches one call per port -- so scanning a *name* issued one
    lookup per port, 65,535 of them for a full sweep. The cost is not only
    latency: a rate-limited or flaky resolver starts failing those lookups
    partway through, ``tcp_check`` reads a failed lookup as unreachable, and
    the affected ports are reported **closed** by the function whose entire
    output is the list of open ones.

    An address literal is returned untouched, without consulting the resolver
    at all. A name that resolves to several addresses keeps all of them, in
    the order the system prefers: probing each in turn is what
    ``socket.create_connection`` was already doing inside every single probe,
    so a dual-stack name still reports a port open on either family. A name
    that does not resolve yields an empty list -- the scan then finds nothing,
    which is what it found before, after one lookup instead of thousands.
    """
    from . import try_parse

    dst = _dst_argument(host)
    if try_parse(dst, IPAddress) is not None:
        return [dst]
    try:
        infos = _socket.getaddrinfo(dst, None, 0, _socket.SOCK_STREAM)
    except OSError:
        return []

    addresses: "List[str]" = []
    for info in infos:
        # Only the INET/INET6 sockaddrs carry a textual address in slot 0, and
        # a SOCK_STREAM lookup returns nothing else -- the guard is for the
        # type checker, which types the union of every sockaddr shape.
        address = info[4][0]
        if isinstance(address, str) and address not in addresses:
            addresses.append(address)
    return addresses


def _probe(addresses: "Sequence[str]", port: int, timeout: float) -> bool:
    """True if any of ``addresses`` accepts a TCP connection on ``port``.

    The scan worker. Takes already-resolved literals so no probe touches the
    resolver -- see :func:`_probe_addresses`.
    """
    from . import tcp_check

    return any(tcp_check(address, port, timeout) for address in addresses)


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

    Every resulting number is validated by :func:`netimps._scheme.coerce_port`,
    so an out-of-range port raises here rather than reaching the socket layer,
    which would mask it to 16 bits and scan a different port. An empty
    iterable stays empty -- it means "nothing to scan", never "the default
    set".
    """
    from . import get_default_port

    if isinstance(ports, str):
        if ports in PORT_RANGES:
            return PORT_RANGES[ports]
        resolved = _port_number(ports, get_default_port)
        if resolved is not None:
            return (coerce_port(resolved),)
        raise ValueError(
            "unknown port range or scheme %r (ranges: %s)"
            % (ports, ", ".join(sorted(PORT_RANGES)))
        )
    if isinstance(ports, int):
        return (coerce_port(ports),)

    out = []
    for entry in ports:
        if isinstance(entry, int):
            out.append(coerce_port(entry))
            continue
        resolved = _port_number(entry, get_default_port)
        if resolved is None:
            raise ValueError("cannot resolve %r to a port number" % (entry,))
        out.append(coerce_port(resolved))
    return tuple(out)


def _port_number(value, get_default_port) -> "Optional[int]":
    """A single port spec to a number: ``"443"``, ``"https"``, or ``None``.

    The numeric test is ``int()`` itself, not :meth:`str.isdigit`: that
    answers ``True`` for characters ``int()`` then rejects -- superscripts and
    other Unicode digits -- so the intended fall-through to the scheme table
    became a :class:`ValueError` from inside the conversion instead.
    """
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text)
    except ValueError:
        return get_default_port(text)


def scan_ports(
    host: "AddressLike",
    ports: "PortsLike" = "common",
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

    ``host`` also accepts an address object or an :class:`IPv4Interface`/
    :class:`IPv6Interface` (its ``.ip`` is used), same as :func:`tcp_check`.

    :param ports: a :data:`PORT_RANGES` name (``"common"``, ``"well-known"``,
        ``"all"``), a scheme name resolved via :func:`get_default_port`, a port
        number, or any iterable mixing those. A range name wins over a scheme
        name where the two collide. Each port must be in ``0-65535``; an empty
        iterable means "nothing to scan" and returns ``[]``.
    :param timeout: per-port connect timeout. This bounds the whole scan
        (``timeout`` x rounds), so keep it small on a large range -- but not so
        small that a slow host reads as closed. Floored to 1ms, since
        ``settimeout(0)`` means *non-blocking* and would report every port
        closed; a negative value raises.
    :param workers: concurrent connections. These tasks are I/O-bound, so the
        useful number is far above the CPU count; very high values can exhaust
        file descriptors or trip rate limiting.

    ``host`` is resolved **once** for the whole scan rather than once per port
    -- see :func:`_probe_addresses` for why that is a correctness fix and not
    only a speed one. A name that does not resolve returns ``[]``.

    Open means "the TCP handshake completed" -- not that the service is
    healthy, and not that a filtered port is distinguishable from a closed one
    (both simply fail to connect).

    Raises :class:`ValueError` for a port outside ``0-65535``, an unknown
    scheme or range name, or a negative ``timeout``.
    """
    targets = _resolve_ports(ports)
    if not targets:
        return []
    timeout = _floor_timeout(timeout)

    addresses = _probe_addresses(host)
    if not addresses:
        return []

    with _ThreadPool(max_workers=min(workers, len(targets))) as pool:
        results = pool.map(lambda p: (p, _probe(addresses, p, timeout)), targets)
        open_ports = [port for port, is_open in results if is_open]
    return sorted(open_ports)


def scan_hosts(
    network: "IPNetworkLike",
    port: "Optional[Union[int, str]]" = None,
    ports: "Optional[PortsLike]" = None,
    timeout: float = 1.0,
    workers: int = _DEFAULT_WORKERS,
) -> "List[Tuple[IPAddress, List[int]]]":
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
    :param ports: ports to probe per host; defaults to the ``"common"`` set
        when **omitted**. Same forms as :func:`scan_ports`. An explicitly
        empty ``ports`` means "nothing to scan" and returns ``[]`` -- it does
        not fall back to the default set, which would sweep 36 ports across
        the network a caller just said to probe on none.
    :param timeout: per-connection timeout, floored to 1ms as in
        :func:`scan_ports`; a negative value raises.
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
    from . import IPNetwork, parse

    net = parse(network, IPNetwork)
    if net.version == 4 and net.prefixlen < 16:
        raise ValueError(
            "%s has %d addresses; scan a /16 or smaller" % (net, net.num_addresses)
        )
    if net.version == 6 and net.prefixlen < 112:
        raise ValueError("%s is too large to sweep; scan a /112 or smaller" % (net,))

    if port is not None and ports is not None:
        raise ValueError("pass either port or ports, not both")
    # `ports or "common"` would read an explicitly empty list as "unset" and
    # sweep the default 36 ports instead of none, so test for omission.
    if port is not None:
        spec: "PortsLike" = [port]
    elif ports is not None:
        spec = ports
    else:
        spec = "common"
    targets = _resolve_ports(spec)
    if not targets:
        return []
    timeout = _floor_timeout(timeout)

    # A /31 or /32 has no separate network/broadcast address, and .hosts()
    # already accounts for that.
    addresses = list(net.hosts()) or [net.network_address]
    work = [(address, probe) for address in addresses for probe in targets]

    found: "Dict[IPAddress, List[int]]" = {}
    with _ThreadPool(max_workers=min(workers, len(work))) as pool:
        results = pool.map(
            # Every address here is already a literal from the network, so the
            # workers never consult the resolver -- same property scan_ports
            # gets from _probe_addresses.
            lambda item: (item[0], item[1], _probe([str(item[0])], item[1], timeout)),
            work,
        )
        for address, probe, is_open in results:
            if is_open:
                found.setdefault(address, []).append(probe)

    return [(address, sorted(found[address])) for address in sorted(found)]
