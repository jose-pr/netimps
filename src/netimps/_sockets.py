"""Socket-level helpers and route/MTU queries (internal).

The small functions every network tool ends up rewriting: which local address
would be used to reach a host, an unused port for a test server, an honest TCP
reachability check, and waiting for a service to come up. Plus the routing and
MTU queries that need per-platform work.

Re-exported from :mod:`netimps`; do not import this module path directly.

Privilege boundary
------------------
Everything here works unprivileged **except** :func:`hop_count`, which needs to
read ICMP TTL-exceeded replies and therefore a raw socket (root/Administrator).
It raises :class:`PermissionError` rather than silently returning nonsense.
:func:`get_route` deliberately stops at the first hop, which *is* available
unprivileged on every supported platform.
"""

from __future__ import annotations

import socket as _socket
import struct as _struct
from subprocess import TimeoutExpired as _SubprocessTimeout
from subprocess import run as _subprocess_run
import sys as _sys
import time as _time

from ._iface_spec import interface_address as _interface_address
from typing import Optional, Tuple

__all__ = [
    "bind",
    "bind_error_hint",
    "interface_for",
    "get_source_ip",
    "free_port",
    "tcp_check",
    "wait_for_port",
    "get_route",
    "Route",
    "hop_count",
    "path_mtu",
    "discover_mtu",
]

_IS_WINDOWS = _sys.platform == "win32"

#: Probe destination for "which way does traffic go by default?". A
#: public address forces the default route; it is never contacted (see
#: get_source_ip).
_DEFAULT_PROBE = "8.8.8.8"


def bind(
    address: str = "",
    port: int = 0,
    *,
    family: int = _socket.AF_INET,
    kind: int = _socket.SOCK_DGRAM,
    reuse_address: bool = True,
    reuse_port: bool = False,
    broadcast: bool = False,
    interface=None,
    options=(),
    listen: "Optional[int]" = None,
):
    """Create, configure and bind a socket in one call.

    The setup every server repeats, with the options that are easy to get
    wrong handled once::

        sock = bind("", 67, broadcast=True)               # DHCP-style listener
        sock = bind("127.0.0.1", 0, kind=SOCK_STREAM, listen=5)
        sock = bind(port=5353, interface="eth0")          # pin to one adapter

    :param address: local address to bind. ``""`` (the default) is the
        wildcard, which is what a server almost always wants.
    :param port: local port; ``0`` lets the OS choose.
    :param interface: bind to this adapter's address instead of ``address``.
        Accepts an :class:`Interface`, a MAC, an adapter name or an address --
        the same union as ``ping(source=)``. Raises :class:`ValueError` if it
        cannot be resolved, rather than silently binding the wildcard.
    :param reuse_port: sets ``SO_REUSEPORT``. **A no-op where the option does
        not exist** (Windows) rather than an error, so the same call works
        everywhere.
    :param options: extra ``(level, name, value)`` triples for anything not
        covered by the named arguments.
    :param listen: call ``listen(backlog)`` after binding. Ignored for
        datagram sockets, where it is meaningless.

    Raises :class:`OSError` if the bind fails -- see :func:`bind_error_hint`
    for turning that into something a user can act on. The socket is closed
    before the exception propagates, so a failed call leaks nothing.
    """
    if interface is not None:
        resolved = _interface_address(interface, want_ipv6=(family == _socket.AF_INET6))
        if resolved is None:
            raise ValueError("cannot resolve interface %r to an address" % (interface,))
        address = str(resolved)

    sock = _socket.socket(family, kind)
    try:
        if reuse_address:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        if reuse_port:
            # Absent on Windows; setting it unconditionally would raise there.
            option = getattr(_socket, "SO_REUSEPORT", None)
            if option is not None:
                try:
                    sock.setsockopt(_socket.SOL_SOCKET, option, 1)
                except OSError:
                    pass  # present but refused by this kernel -- not fatal
        if broadcast:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        for level, name, value in options:
            sock.setsockopt(level, name, value)

        sock.bind((address, port))
        if listen is not None and kind == _socket.SOCK_STREAM:
            sock.listen(listen)
    except BaseException:
        sock.close()
        raise
    return sock


def bind_error_hint(
    exc: BaseException, port: "Optional[int]" = None
) -> "Optional[str]":
    """Turn a bind failure into a sentence a user can act on, or ``None``.

    The raw ``OSError`` from a failed bind is famously unhelpful, and the errno
    differs per platform -- Windows reports ``WinError 10013``/``10048`` where
    POSIX reports ``EACCES``/``EADDRINUSE``::

        try:
            sock = bind("", 67)
        except OSError as exc:
            raise OSError(bind_error_hint(exc, 67) or str(exc)) from exc

    Returns ``None`` for anything unrecognised, so the caller keeps the
    original error rather than a worse paraphrase. This **does not raise** --
    deciding what to do with a failure belongs to the caller.
    """
    import errno as _errno

    if not isinstance(exc, OSError):
        return None

    winerror = getattr(exc, "winerror", None)
    where = "port %d" % port if port is not None else "that port"

    if (
        isinstance(exc, PermissionError)
        or exc.errno == _errno.EACCES
        or winerror == 10013
    ):
        hint = "permission denied binding %s" % where
        if port is not None and port < 1024:
            hint += "; ports below 1024 need root/Administrator"
        return hint

    if exc.errno == _errno.EADDRINUSE or winerror == 10048:
        return "%s is already in use" % where.capitalize()

    if exc.errno == _errno.EADDRNOTAVAIL or winerror == 10049:
        return (
            "that address is not available on this host; "
            "it must belong to a local interface"
        )

    return None


def interface_for(address, strict: bool = True):
    """Return the :class:`Interface` holding ``address``, or ``None``.

    The reverse of interface enumeration -- "a socket is bound here, which
    adapter is that?"::

        interface_for(sock.getsockname()[0])

    :param strict: when True (the default), an address held by no local
        interface returns ``None``. When False, a synthetic single-address
        ``Interface`` is returned instead, so a caller that only needs
        *something* to attribute traffic to does not have to special-case it.

    The synthetic interface is named ``"<unknown>"`` and carries a host route
    (``/32`` or ``/128``), matching how degraded enumeration reports itself.
    """
    from . import try_parse
    from ._ifaddrs import Interface, get_interfaces

    wanted = try_parse(address)
    if wanted is None:
        return None

    for iface in get_interfaces():
        for entry in iface.ips:
            if entry.ip == wanted:
                return iface

    if strict:
        return None

    built = _make_host_route(wanted)
    return Interface(name="<unknown>", ips=[built] if built else [])


def _make_host_route(address):
    import ipaddress as _ipaddress

    try:
        return _ipaddress.ip_interface("%s/%d" % (address, address.max_prefixlen))
    except ValueError:
        return None


def get_source_ip(dest: str = _DEFAULT_PROBE, port: int = 80):
    """Return the local address the kernel would use to reach ``dest``.

    Answers "which of my addresses is the *real* one for this destination?" --
    the question a hostname lookup gets wrong on any host with VMs, containers
    or a VPN::

        get_source_ip()                  # IPv4Address('192.0.2.10')
        get_source_ip("192.168.1.1")     # the LAN-facing address
        get_source_ip("2001:4860::8888") # an IPv6 source address

    **No packets are sent.** ``connect()`` on a UDP socket only fixes the
    socket's local endpoint by consulting the routing table, so this is
    immediate and invisible to ``dest``.

    The answer depends on ``dest``: with a VPN up, a public probe returns the
    tunnel address while a LAN probe returns the physical one. Pass the address
    you actually intend to talk to rather than trusting the default.

    Returns ``None`` if no route exists (e.g. IPv6 probe on an IPv4-only host).
    """
    from . import parse

    try:
        family = _socket.AF_INET6 if ":" in dest else _socket.AF_INET
        sock = _socket.socket(family, _socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        sock.connect((dest, port))
        return parse(sock.getsockname()[0].split("%")[0])
    except (OSError, ValueError):
        return None
    finally:
        sock.close()


def free_port(host: str = "127.0.0.1", family: int = _socket.AF_INET) -> int:
    """Return a port number that was free a moment ago.

    Binds port 0, reads back what the OS assigned, and closes::

        port = free_port()
        server = start_my_server(port=port)

    .. warning::
       **Inherently racy.** The port is released the instant this returns, so
       another process can take it before you bind. There is no way around that
       with a returned port number -- if you can, bind port 0 in the server
       itself and read back ``getsockname()`` instead of calling this.

    ``SO_REUSEADDR`` is deliberately **not** set: it would let the OS hand back
    a port still in ``TIME_WAIT``, which then fails or steals traffic when the
    caller binds it for real.
    """
    sock = _socket.socket(family, _socket.SOCK_STREAM)
    try:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def tcp_check(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP connection to ``host``:``port`` is accepted.

    The honest reachability test, and what you almost always want instead of
    :func:`netimps.ping`: it proves the *service* answers, not merely that the
    host replies to ICMP echo (which most cloud firewalls drop anyway)::

        tcp_check("example.com", 443)
        tcp_check("db.internal", 5432, timeout=1.0)

    Never raises: refused, timed out, unresolvable and unreachable all yield
    ``False``. Only TCP handshake completion is checked -- not that the service
    behind the port is healthy.
    """
    try:
        sock = _socket.create_connection((host, port), timeout=timeout)
    except (OSError, ValueError, OverflowError):
        return False
    sock.close()
    return True


def wait_for_port(
    host: str,
    port: int,
    timeout: float = 30.0,
    interval: float = 0.1,
    connect_timeout: Optional[float] = None,
) -> bool:
    """Poll until ``host``:``port`` accepts a connection, or ``timeout`` elapses.

    The "wait for the service to come up" loop every deploy and container
    script contains::

        if not wait_for_port("localhost", 5432, timeout=60):
            raise RuntimeError("database never started")

    :param interval: delay between attempts. Backs off up to 1s so a long wait
        does not spin.
    :param connect_timeout: per-attempt connect timeout; defaults to
        ``interval`` bounded to at least 1s.

    Returns ``True`` as soon as the port answers, ``False`` on timeout. The
    deadline is honoured overall, so this cannot overrun by more than one
    attempt regardless of how long individual connects block.
    """
    deadline = _time.monotonic() + timeout
    per_try = connect_timeout if connect_timeout is not None else max(interval, 1.0)
    delay = interval

    while True:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            return False
        if tcp_check(host, port, timeout=min(per_try, remaining)):
            return True
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            return False
        _time.sleep(min(delay, remaining))
        delay = min(delay * 1.5, 1.0)  # gentle backoff, capped


class Route:
    """How traffic to a destination leaves this host.

    Attributes:
        dest: the destination this route was computed for.
        source: local address the kernel would use (see :func:`get_source_ip`).
        gateway: next-hop router, or ``None`` when the destination is *on-link*
            (same subnet, or loopback) and no router is involved.
        interface_index: index of the outgoing interface, ``0`` if unknown.
        on_link: True when no gateway is needed.
    """

    __slots__ = ("dest", "source", "gateway", "interface_index")

    def __init__(self, dest, source=None, gateway=None, interface_index=0):
        self.dest = dest
        self.source = source
        self.gateway = gateway
        self.interface_index = interface_index

    @property
    def on_link(self) -> bool:
        """True when the destination is reachable without a router."""
        return self.gateway is None

    def __repr__(self) -> str:
        return "Route(dest=%r, source=%r, gateway=%r, on_link=%r)" % (
            None if self.dest is None else str(self.dest),
            None if self.source is None else str(self.source),
            None if self.gateway is None else str(self.gateway),
            self.on_link,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Route):
            return NotImplemented
        return (
            self.dest == other.dest
            and self.source == other.source
            and self.gateway == other.gateway
            and self.interface_index == other.interface_index
        )


def _windows_next_hop(dest_v4: str) -> "Tuple[Optional[str], int]":
    """(next_hop, if_index) from ``GetBestRoute``. IPv4 only."""
    import ctypes
    from ctypes import wintypes

    class _MIB_IPFORWARDROW(ctypes.Structure):
        _fields_ = [
            ("dwForwardDest", wintypes.DWORD),
            ("dwForwardMask", wintypes.DWORD),
            ("dwForwardPolicy", wintypes.DWORD),
            ("dwForwardNextHop", wintypes.DWORD),
            ("dwForwardIfIndex", wintypes.DWORD),
            ("dwForwardType", wintypes.DWORD),
            ("dwForwardProto", wintypes.DWORD),
            ("dwForwardAge", wintypes.DWORD),
            ("dwForwardNextHopAS", wintypes.DWORD),
            ("dwForwardMetric1", wintypes.DWORD),
            ("dwForwardMetric2", wintypes.DWORD),
            ("dwForwardMetric3", wintypes.DWORD),
            ("dwForwardMetric4", wintypes.DWORD),
            ("dwForwardMetric5", wintypes.DWORD),
        ]

    iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    row = _MIB_IPFORWARDROW()
    packed = _struct.unpack("<I", _socket.inet_aton(dest_v4))[0]
    if iphlpapi.GetBestRoute(packed, 0, ctypes.byref(row)) != 0:
        return None, 0
    next_hop = _socket.inet_ntoa(_struct.pack("<I", row.dwForwardNextHop))
    # 0.0.0.0 means "on-link" -- no router in the path.
    return (None if next_hop == "0.0.0.0" else next_hop), int(row.dwForwardIfIndex)


def _posix_next_hop(dest: str) -> "Tuple[Optional[str], int]":
    """(next_hop, if_index) by reading the kernel routing table.

    Linux exposes it as ``/proc/net/route``; elsewhere there is no portable
    unprivileged interface, so the gateway is reported as unknown and only the
    on-link determination (made by the caller from the source address) stands.
    """
    try:
        with open("/proc/net/route") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None, 0

    # /proc/net/route omits loopback entirely on many kernels, so a lookup for
    # 127.0.0.1 would fall through to the default route (mask 0) and report the
    # LAN gateway. Loopback is on-link by definition; answer it directly.
    from . import LOOPBACK_V4, try_parse

    parsed_dest = try_parse(dest)
    if parsed_dest is not None and parsed_dest in LOOPBACK_V4:
        return None, _if_index("lo")

    best = None
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            destination = int(parts[1], 16)
            gateway = int(parts[2], 16)
            mask = int(parts[7], 16)
        except ValueError:
            continue
        packed = _struct.unpack("<I", _socket.inet_aton(dest))[0]
        if (packed & mask) == destination:
            # Longest prefix wins, so prefer the most specific match.
            ones = bin(mask).count("1")
            if best is None or ones > best[0]:
                best = (ones, gateway, parts[0])

    if best is None:
        return None, 0
    _, gateway, name = best
    if gateway == 0:
        return None, _if_index(name)
    return _socket.inet_ntoa(_struct.pack("<I", gateway)), _if_index(name)


def _if_index(name: str) -> int:
    try:
        return _socket.if_nametoindex(name)
    except (OSError, AttributeError, ValueError):
        return 0


def get_route(dest: str = _DEFAULT_PROBE) -> Route:
    """Return how traffic to ``dest`` leaves this host.

    Reports the source address and the **first hop** -- the gateway a packet is
    handed to, or ``None`` when the destination is on-link::

        r = get_route("8.8.8.8")
        r.source        # IPv4Address('192.0.2.10')
        r.gateway       # IPv4Address('192.0.2.1')
        r.on_link       # False

        get_route("127.0.0.1").on_link      # True -- no router involved

    First hop only, deliberately: it is available **unprivileged** on every
    supported platform, whereas the full path requires raw sockets. See
    :func:`hop_count` for distance, which does not.

    Never raises: unknown pieces come back as ``None``/``0`` rather than an
    error. The gateway is only resolvable on Windows and Linux; elsewhere it
    stays ``None``, so use ``.gateway is None`` to mean "on-link" only when
    ``.source`` is also set.
    """
    from . import parse, try_parse

    source = get_source_ip(dest)
    resolved = dest
    if try_parse(dest) is None:
        try:
            resolved = _socket.gethostbyname(dest)
        except OSError:
            resolved = dest

    gateway_text = None
    index = 0
    parsed_dest = try_parse(resolved)
    if parsed_dest is not None and parsed_dest.version == 4:
        try:
            if _IS_WINDOWS:
                gateway_text, index = _windows_next_hop(resolved)
            else:
                gateway_text, index = _posix_next_hop(resolved)
        except (OSError, AttributeError, ValueError, _struct.error):
            gateway_text, index = None, 0

    return Route(
        dest=parsed_dest if parsed_dest is not None else dest,
        source=source,
        gateway=try_parse(gateway_text) if gateway_text else None,
        interface_index=index,
    )


#: ICMP types that answer a TTL-limited probe: 11 = time exceeded (a router on
#: the path), 3 = destination unreachable (the target's port is closed, which
#: means we arrived), 0 = echo reply.
_ICMP_REPLY_TYPES = frozenset((0, 3, 11))


def _is_icmp_reply(packet: bytes) -> bool:
    """True if ``packet`` is an ICMP message answering a probe.

    Raw IPv4 sockets deliver whole IP datagrams, so the ICMP type sits after
    the variable-length IP header (IHL, low nibble of byte 0, in 32-bit words).
    """
    if len(packet) < 20:
        return False
    header_len = (packet[0] & 0x0F) * 4
    if len(packet) < header_len + 1:
        return False
    return packet[header_len] in _ICMP_REPLY_TYPES


def _hop_count_traceroute(
    target: str, max_hops: int, timeout: float
) -> "Optional[int]":
    """Hop count by driving the system traceroute. Unprivileged.

    Parses only the **hop number** and the presence of ``target`` as a literal
    address -- never the prose, which is localised ("Request timed out." /
    "Expiration du delai d'attente"). Numeric output is forced (``-d``/``-n``)
    so the destination appears as an address rather than a reverse-DNS name.

    Returns None if the binary is missing, errors, or never reaches ``target``.
    """
    if _IS_WINDOWS:
        cmd = [
            "tracert",
            "-d",
            "-h",
            str(max_hops),
            "-w",
            str(int(timeout * 1000)),
            target,
        ]
    else:
        cmd = [
            "traceroute",
            "-n",
            "-m",
            str(max_hops),
            "-w",
            str(max(1, int(timeout))),
            target,
        ]

    # Bound the whole run: a traceroute to a black hole takes max_hops * probes
    # * timeout, which is minutes.
    budget = max(10.0, max_hops * timeout * 3 + 10)
    try:
        result = _subprocess_run(cmd, capture_output=True, text=True, timeout=budget)
    except (OSError, ValueError, _SubprocessTimeout):
        return None

    for line in (result.stdout or "").splitlines():
        fields = line.split()
        if not fields or not fields[0].isdigit():
            continue
        # The destination answering this hop is the answer, whatever the
        # latency columns look like.
        if any(field.strip("[]") == target for field in fields[1:]):
            return int(fields[0])
    return None


def hop_count(
    dest: str,
    max_hops: int = 30,
    timeout: float = 1.0,
    allow_traceroute: bool = True,
) -> Optional[int]:
    """Return the number of hops to ``dest``, or ``None`` if it never answers.

    Sends TTL-limited probes and counts the routers that reply, the same
    technique ``traceroute`` uses::

        hop_count("8.8.8.8")     # 12

    Uses raw-socket probes when available (root/Administrator), and otherwise
    falls back to driving the system ``traceroute``/``tracert``, so this works
    unprivileged on a normal desktop. Pass ``allow_traceroute=False`` to require
    the in-process path, which then raises :class:`PermissionError` instead of
    shelling out.

    The fallback is slower (seconds) because it runs a whole trace. Only the
    hop number and the destination address are read from its output, never the
    localised prose, so it is not locale-dependent.

    Returns ``None`` when the destination never responds within ``max_hops``.
    That is common and usually **not** a missing route: host firewalls (Windows
    Firewall in particular) routinely drop inbound ICMP even for an elevated
    process, so ``None`` here means "no answer", never "unreachable". Treat it
    as unknown rather than as a negative result.
    """
    try:
        target = _socket.gethostbyname(dest)
    except OSError:
        return None

    try:
        icmp = _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_ICMP)
    except (OSError, AttributeError) as exc:
        if allow_traceroute:
            return _hop_count_traceroute(target, max_hops, timeout)
        raise PermissionError(
            "hop_count needs a raw socket (root/Administrator); "
            "pass allow_traceroute=True, or use get_route() for the first hop"
        ) from exc

    try:
        icmp.settimeout(timeout)
        # Windows will not deliver ICMP to a raw socket bound to INADDR_ANY --
        # it must be bound to a real local address, and put into promiscuous
        # mode with SIO_RCVALL. On POSIX, binding to "" is both sufficient and
        # correct.
        bind_to = ""
        if _IS_WINDOWS:
            source = get_source_ip(target)
            bind_to = str(source) if source is not None else ""
        try:
            icmp.bind((bind_to, 0))
        except OSError:
            pass
        if _IS_WINDOWS:
            try:
                icmp.ioctl(_socket.SIO_RCVALL, _socket.RCVALL_ON)
            except (OSError, AttributeError):
                pass
        for ttl in range(1, max_hops + 1):
            probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            try:
                probe.setsockopt(_socket.IPPROTO_IP, _socket.IP_TTL, ttl)
                probe.sendto(b"", (target, 33434 + ttl))
            except OSError:
                continue
            finally:
                probe.close()

            # With SIO_RCVALL the socket sees unrelated traffic too, so keep
            # reading (within this hop's budget) until an ICMP packet that is
            # actually a reply shows up, rather than trusting the first one.
            deadline = _time.monotonic() + timeout
            while _time.monotonic() < deadline:
                try:
                    icmp.settimeout(max(0.01, deadline - _time.monotonic()))
                    packet, addr = icmp.recvfrom(1024)
                except (_socket.timeout, OSError):
                    break
                if not _is_icmp_reply(packet):
                    continue
                if addr[0] == target:
                    return ttl  # destination itself answered: distance found
                break  # a router replied: this hop is done, try the next TTL

        # Raw probes got no answer -- commonly a host firewall dropping inbound
        # ICMP even for an elevated process. Try the system tool before giving
        # up, since it often succeeds where the raw socket does not.
        return (
            _hop_count_traceroute(target, max_hops, timeout)
            if allow_traceroute
            else None
        )
    finally:
        icmp.close()


def path_mtu(dest: str, port: int = 80) -> Optional[int]:
    """Return the path MTU to ``dest`` in bytes, or ``None`` if undiscoverable.

    Asks the kernel for the MTU it has learned for this destination::

        path_mtu("example.com")     # 1500, or 1420 through a VPN

    **Linux only in practice.** It reads ``IP_MTU``, which the kernel fills in
    after path-MTU discovery on a connected socket. ``IP_MTU``,
    ``IP_MTU_DISCOVER`` and ``IP_DONTFRAG`` do not exist on Windows, and reading
    the ICMP *fragmentation needed* replies that would let us probe manually
    requires a raw socket -- so this returns ``None`` there rather than
    guessing.

    For the local link MTU, which *is* available everywhere, use
    ``Interface.mtu`` from :func:`netimps.get_interfaces` instead. That is the
    number you want unless you specifically care about a bottleneck somewhere
    along the path.
    """
    ip_mtu = getattr(_socket, "IP_MTU", None)
    if ip_mtu is None:
        return None

    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        # PMTU is only maintained for connected sockets.
        discover = getattr(_socket, "IP_MTU_DISCOVER", None)
        do_want = getattr(_socket, "IP_PMTUDISC_DO", None)
        if discover is not None and do_want is not None:
            try:
                sock.setsockopt(_socket.IPPROTO_IP, discover, do_want)
            except OSError:
                pass
        sock.connect((dest, port))
        return int(sock.getsockopt(_socket.IPPROTO_IP, ip_mtu))
    except OSError:
        return None
    finally:
        sock.close()


def discover_mtu(
    dest: str,
    low: int = 576,
    high: int = 9000,
    timeout: float = 1.0,
    source=None,
) -> "Optional[int]":
    """Find the path MTU to ``dest`` by binary-searching DF-flagged pings.

    Sends echo requests with the *don't fragment* bit set, growing and
    shrinking the payload until the largest one that survives is found::

        discover_mtu("8.8.8.8")          # 1500
        discover_mtu("vpn.internal")     # 1420, say

    Unlike :func:`path_mtu` -- which asks the kernel and only works where
    ``IP_MTU`` exists -- this **works on every platform**, because it only
    needs the platform ``ping`` binary. The cost is that it is slow (a dozen
    or so pings) and needs the destination to answer ICMP at all.

    :param low: smallest MTU to consider. 576 is the IPv4 minimum every host
        must accept, so anything smaller means the host is simply unreachable.
    :param high: largest to consider. 9000 covers jumbo frames; the search
        starts by confirming the ceiling, so a generous value costs one probe.
    :param source: send from this interface -- same union as ``ping(source=)``.

    Returns the MTU in **bytes including headers** (payload + 28 for IPv4 +
    ICMP), so it is directly comparable with :attr:`Interface.mtu`. Returns
    ``None`` when the destination never answers, which is common: many hosts
    and most cloud firewalls drop echo entirely, and that is indistinguishable
    from "every size was too big".

    .. note::
       A *silent* black hole -- a router that drops oversized DF packets
       without sending "fragmentation needed" -- is exactly what this measures,
       and is why the result can be lower than any local ``Interface.mtu``.
    """
    from . import ping

    # ping's size= is the ICMP *payload* on both Windows (-l) and POSIX (-s) --
    # neither counts headers -- so the wire packet is 20 (IPv4) + 8 (ICMP)
    # bytes larger. Getting this backwards would skew every result by 28.
    overhead = 28

    def survives(mtu: int) -> bool:
        payload = mtu - overhead
        if payload < 0:
            return False
        return bool(
            ping(
                dest,
                size=payload,
                dont_fragment=True,
                timeout=timeout,
                source=source,
            )
        )

    # Establish that the host answers at all, at the smallest size worth
    # trying. Without this a firewalled host looks like a tiny MTU.
    if not survives(low):
        return None

    if survives(high):
        return high  # nothing between low and high to find

    # Invariant: `low` survives, `high` does not. Narrow until they meet.
    while high - low > 1:
        middle = (low + high) // 2
        if survives(middle):
            low = middle
        else:
            high = middle
    return low
