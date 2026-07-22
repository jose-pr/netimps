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
from typing import Any, Optional, Tuple

__all__ = [
    "bind",
    "bind_error_hint",
    "interface_for",
    "get_source_ip",
    "get_free_port",
    "tcp_check",
    "wait_for_port",
    "get_route",
    "Route",
    "hop_count",
    "get_pmtu",
    "discover_mtu",
    "get_tcp_mss",
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
) -> "_socket.socket":
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
        the same union as ``ping(src=)``. Raises :class:`ValueError` if it
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


def interface_for(address, strict: bool = True) -> "Optional[Any]":
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


def get_source_ip(dst: str = _DEFAULT_PROBE, port: int = 80) -> "Optional[Any]":
    """Return the local address the kernel would use to reach ``dst``.

    Answers "which of my addresses is the *real* one for this destination?" --
    the question a hostname lookup gets wrong on any host with VMs, containers
    or a VPN::

        get_source_ip()                  # IPv4Address('192.0.2.10')
        get_source_ip("192.168.1.1")     # the LAN-facing address
        get_source_ip("2001:4860::8888") # an IPv6 src address

    **No packets are sent.** ``connect()`` on a UDP socket only fixes the
    socket's local endpoint by consulting the routing table, so this is
    immediate and invisible to ``dst``.

    The answer depends on ``dst``: with a VPN up, a public probe returns the
    tunnel address while a LAN probe returns the physical one. Pass the address
    you actually intend to talk to rather than trusting the default.

    Returns ``None`` if no route exists (e.g. IPv6 probe on an IPv4-only host).
    """
    from . import parse

    try:
        family = _socket.AF_INET6 if ":" in dst else _socket.AF_INET
        sock = _socket.socket(family, _socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        sock.connect((dst, port))
        return parse(sock.getsockname()[0].split("%")[0])
    except (OSError, ValueError):
        return None
    finally:
        sock.close()


def get_free_port(src: str = "127.0.0.1", family: int = _socket.AF_INET) -> int:
    """Return a port number that was free a moment ago.

    Binds port 0, reads back whatever the OS assigned, and closes::

        port = get_free_port()
        server = start_my_server(port=port)

    A *getter*, despite "free" in the name -- it acquires a number, it does not
    release anything. The port is **not** held open for you.

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
        sock.bind((src, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def tcp_check(dst: str, port: int, timeout: float = 3.0) -> bool:
    """Return True if a TCP connection to ``dst``:``port`` is accepted.

    The honest reachability test, and what you almost always want instead of
    :func:`netimps.ping`: it proves the *service* answers, not merely that the
    host replies to ICMP echo (which most cloud firewalls drop anyway)::

        tcp_check("example.com", 443)
        tcp_check("db.internal", 5432, timeout=1.0)

    Never raises: refused, timed out, unresolvable and unreachable all yield
    ``False``. Only TCP handshake completion is checked -- not that the service
    behind the port is healthy.

    .. note::
       **Not the same question as** ``ping(dst, method="tcp", port=...)``. This
       asks "is the *service* up?", so a refused connection is ``False``. That
       asks "is the *host* up?", and counts a refusal as success -- the RST
       proves something answered. Same distinction as a service check versus an
       ICMP echo. :func:`wait_for_port` and the scanners build on this one,
       because they care about the service.
    """
    try:
        sock = _socket.create_connection((dst, port), timeout=timeout)
    except (OSError, ValueError, OverflowError):
        return False
    sock.close()
    return True


def wait_for_port(
    dst: str,
    port: int,
    timeout: float = 30.0,
    interval: float = 0.1,
    connect_timeout: Optional[float] = None,
) -> bool:
    """Poll until ``dst``:``port`` accepts a connection, or ``timeout`` elapses.

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
        if tcp_check(dst, port, timeout=min(per_try, remaining)):
            return True
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            return False
        _time.sleep(min(delay, remaining))
        delay = min(delay * 1.5, 1.0)  # gentle backoff, capped


class Route:
    """How traffic to a destination leaves this host.

    Attributes:
        dst: the destination this route was computed for.
        src: local address the kernel would use (see :func:`get_source_ip`).
        gateway: next-hop router, or ``None`` when the destination is *on-link*
            (same subnet, or loopback) and no router is involved.
        interface_index: index of the outgoing interface, ``0`` if unknown.
        on_link: True when no gateway is needed.
    """

    __slots__ = ("dst", "src", "gateway", "interface_index")

    def __init__(self, dst, src=None, gateway=None, interface_index=0):
        self.dst = dst
        self.src = src
        self.gateway = gateway
        self.interface_index = interface_index

    @property
    def on_link(self) -> bool:
        """True when the destination is reachable without a router."""
        return self.gateway is None

    def __repr__(self) -> str:
        return "Route(dst=%r, src=%r, gateway=%r, on_link=%r)" % (
            None if self.dst is None else str(self.dst),
            None if self.src is None else str(self.src),
            None if self.gateway is None else str(self.gateway),
            self.on_link,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Route):
            return NotImplemented
        return (
            self.dst == other.dst
            and self.src == other.src
            and self.gateway == other.gateway
            and self.interface_index == other.interface_index
        )


def _windows_next_hop(dest_v4: str) -> "Tuple[Optional[str], int]":
    """(next_hop, if_index) from ``GetBestRoute``. IPv4 only.

    ``GetBestRoute`` rather than ``GetIpForwardTable``: it asks Windows which
    route *it* would choose for a destination, so the kernel does the
    longest-prefix matching. Dumping the table and matching by hand -- which is
    what the POSIX side has to do, lacking an equivalent -- is more code and
    more ways to be wrong.
    """
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


def _posix_next_hop(dst: str) -> "Tuple[Optional[str], int]":
    """(next_hop, if_index) by reading the kernel routing table.

    Linux exposes it as ``/proc/net/route``; elsewhere there is no portable
    unprivileged interface, so the gateway is reported as unknown and only the
    on-link determination (made by the caller from the src address) stands.
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

    parsed_dest = try_parse(dst)
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
        packed = _struct.unpack("<I", _socket.inet_aton(dst))[0]
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


def get_route(dst: str = _DEFAULT_PROBE) -> Route:
    """Return how traffic to ``dst`` leaves this host.

    Reports the src address and the **first hop** -- the gateway a packet is
    handed to, or ``None`` when the destination is on-link::

        r = get_route("8.8.8.8")
        r.src        # IPv4Address('192.0.2.10')
        r.gateway       # IPv4Address('192.0.2.1')
        r.on_link       # False

        get_route("127.0.0.1").on_link      # True -- no router involved

    First hop only, deliberately: it is available **unprivileged** on every
    supported platform, whereas the full path requires raw sockets. See
    :func:`hop_count` for distance, which does not.

    Never raises: unknown pieces come back as ``None``/``0`` rather than an
    error. The gateway is only resolvable on Windows and Linux; elsewhere it
    stays ``None``, so use ``.gateway is None`` to mean "on-link" only when
    ``.src`` is also set.
    """
    from . import parse, try_parse

    src = get_source_ip(dst)
    resolved = dst
    if try_parse(dst) is None:
        try:
            resolved = _socket.gethostbyname(dst)
        except OSError:
            resolved = dst

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
        dst=parsed_dest if parsed_dest is not None else dst,
        src=src,
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
    dst: str,
    max_hops: int = 30,
    timeout: float = 1.0,
    allow_traceroute: bool = True,
) -> Optional[int]:
    """Return the number of hops to ``dst``, or ``None`` if it never answers.

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
        target = _socket.gethostbyname(dst)
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
            src = get_source_ip(target)
            bind_to = str(src) if src is not None else ""
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


def get_pmtu(dst: str, port: int = 80) -> "Optional[int]":
    """Return the path MTU the kernel has **already learned**, or ``None``.

    A lookup, not a measurement -- it reads ``IP_MTU`` on a connected socket
    and sends nothing::

        get_pmtu("example.com")      # 1420, or None if nothing is cached

    Instant and silent, but it answers a weaker question than
    :func:`discover_mtu`:

    * **``None`` is the common answer.** The kernel only knows a path MTU once
      its own discovery has learned one, which needs prior traffic that
      actually hit the limit. A fresh destination reports nothing.
    * **Windows has no ``IP_MTU``** (nor ``IP_MTU_DISCOVER`` / ``IP_DONTFRAG``),
      so this always returns ``None`` there. Nor is there another route: the
      ``dwForwardMtu`` field of ``MIB_IPFORWARDROW`` reads **0** (verified via
      ``GetBestRoute``; Microsoft lists it as unsupported), and the newer
      ``MIB_IPFORWARD_ROW2`` dropped the field entirely. Route MTU lives at the
      interface level on Windows, which is :attr:`Interface.mtu`. Probing with
      :func:`discover_mtu` is the only way to learn a *path* MTU there.
    * When the kernel *has* an answer it can still be the **local link** MTU
      rather than the path minimum, if nothing has yet forced it lower.

    Use it as a free first guess; use :func:`discover_mtu` when the answer has
    to be right.
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
        sock.connect((dst, port))
        value = int(sock.getsockopt(_socket.IPPROTO_IP, ip_mtu))
        return value if value > 0 else None
    except (OSError, OverflowError):
        return None
    finally:
        sock.close()


def discover_mtu(
    dst: str,
    low: int = 576,
    high: int = 9000,
    timeout: float = 1.0,
    src=None,
    port: int = 80,
    probe: bool = True,
    method: str = "icmp",
    **ping_kwargs,
) -> "Optional[int]":
    """Measure the path MTU to ``dst`` in bytes, or ``None`` if undiscoverable.

    Sends DF-flagged pings of growing size, binary-searching for the largest
    packet that survives the whole path unfragmented::

        discover_mtu("example.com")      # 1500, or 1420 through a VPN

    **This actually traverses the path**, which is the difference from
    :func:`get_pmtu`: that reports what the kernel already knows (often
    nothing), while this goes and finds out. Packets really reach ``dst`` and
    come back, so the answer reflects every hop in between -- including a
    router that silently drops oversized DF packets without sending
    "fragmentation needed", which nothing else will reveal.

    Measured on one host: the local link was 9000 and ``get_pmtu`` returned
    ``None``, while this reported the true 1500.

    The cost is a dozen or so probes and a destination willing to answer ICMP.

    :param low: smallest MTU to consider. 576 is the IPv4 minimum every host
        must accept, so anything smaller means the host is simply unreachable.
    :param high: largest to consider. 9000 covers jumbo frames; the search
        confirms the ceiling first, so a generous value costs one probe.
    :param src: send from this interface -- same union as ``ping(src=)``.
    :param port: destination port passed through to :func:`get_pmtu`.
    :param method: how to probe. ``"icmp"`` (default) uses DF-flagged echo;
        ``"udp"`` sends datagrams of growing size to ``port`` and needs
        something there that replies. Use ``"udp"`` when ICMP is filtered but a
        UDP service answers, or to measure what a **UDP application** can
        actually push -- a middlebox may cap that below the ICMP-derived MTU.

        ``"tcp"`` **does not probe** -- it cannot: TCP is a stream and the
        kernel segments it transparently, so a large ``send()`` silently
        becomes many packets. It instead reads the negotiated MSS
        (:func:`get_tcp_mss`) and adds the 40-byte IPv4+TCP header back, which
        is the closest true equivalent. That is what the two *kernels agreed*,
        not necessarily what a middlebox further along will pass -- use
        ``"icmp"`` or ``"udp"`` when the answer must be measured.
    :param probe: set ``False`` to skip probing entirely and just return
        :func:`get_pmtu` -- the kernel's cached answer, usually ``None``.
    :param ping_kwargs: passed straight to :func:`ping` for ``method="icmp"``,
        so anything it accepts works here -- ``ipv6=True`` to force the family,
        ``tries=3`` to tolerate a lossy path. ``size`` and ``dont_fragment``
        are set by the search itself and cannot be overridden.

    Returns the MTU **including headers** (payload + 28 for IPv4 + ICMP), so it
    is directly comparable with :attr:`Interface.mtu`. Returns ``None`` when
    the destination never answers -- common, since many hosts and most cloud
    firewalls drop echo entirely, and that is indistinguishable from "every
    size was too big".

    .. note::
       The result can be **lower than any local** ``Interface.mtu``, and that
       is the useful case: the bottleneck is somewhere along the path, not on
       this host.
    """
    if not probe:
        # Explicitly asked for the kernel's cached answer only.
        return get_pmtu(dst, port)

    method = (method or "icmp").lower()
    if method not in ("icmp", "udp", "tcp"):
        raise ValueError("method must be 'icmp', 'udp' or 'tcp', got %r" % (method,))

    if method == "tcp":
        # TCP cannot probe: the kernel segments the stream, so a large send()
        # silently becomes many packets and measures nothing. The negotiated
        # MSS is the closest true equivalent -- derive the MTU from it rather
        # than refusing to answer.
        mss = get_tcp_mss(dst, port, timeout)
        if mss is None:
            return None
        # Header size differs by family: IPv4 is 20 + 20 TCP, IPv6 is 40 + 20.
        # Using the v4 figure for a v6 path would under-report by 20 bytes.
        return mss + _tcp_header_overhead(dst)

    for owned in ("size", "dont_fragment"):
        if owned in ping_kwargs:
            raise TypeError(
                "discover_mtu sets %r itself -- it is what the search varies" % (owned,)
            )

    if method == "udp":
        return _discover_mtu_udp(dst, port, low, high, timeout)

    from . import ping

    # ping's size= is the ICMP *payload* on both Windows (-l) and POSIX (-s) --
    # neither counts headers -- so the wire packet is larger by the IP header
    # plus 8 (ICMP). IPv4 gives 28, IPv6 gives 48: applying the v4 figure to a
    # v6 path would under-report by 20 bytes.
    overhead = _ip_header_bytes(dst) + 8

    def survives(mtu: int) -> bool:
        payload = mtu - overhead
        if payload < 0:
            return False
        return bool(
            ping(
                dst,
                size=payload,
                dont_fragment=True,
                timeout=timeout,
                src=src,
                **ping_kwargs,
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


def _discover_mtu_udp(dst, port, low, high, timeout):
    """Binary-search the largest UDP datagram that survives to ``dst``:``port``.

    Needs something at the far end that replies (an echo service, a DNS
    resolver, anything). Silence is treated as "too big", so a filtered or
    absent listener makes every size fail and the result is ``None``.
    """
    overhead = _ip_header_bytes(dst) + 8  # IP header + 8 (UDP)

    def survives(mtu):
        payload = mtu - overhead
        if payload < 0:
            return False
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(bytes(payload), (dst, port))
            sock.recvfrom(65535)
            return True
        except (OSError, _socket.timeout):
            # ConnectionResetError (ICMP port unreachable) also lands here: it
            # proves the host is reachable but says nothing about whether this
            # size made it, so treat it as a failure rather than a success.
            return False
        finally:
            sock.close()

    if not survives(low):
        return None
    if survives(high):
        return high
    while high - low > 1:
        middle = (low + high) // 2
        if survives(middle):
            low = middle
        else:
            high = middle
    return low


def get_tcp_mss(dst: str, port: int, timeout: float = 3.0) -> "Optional[int]":
    """Return the TCP maximum segment size negotiated with ``dst``, or ``None``.

    The TCP counterpart to an MTU: the largest payload a single segment may
    carry, agreed during the handshake::

        get_tcp_mss("example.com", 443)     # 1460 on a 1500-MTU path

    This **opens a real connection** to read the value, then closes it.

    MSS is normally the path MTU minus 40 (20 IPv4 + 20 TCP), so a reduced
    value is a useful signal: a VPN or tunnel is shrinking the path. Measured
    on one host: 1412 over a VPN where the link MTU was 1500, and 32741 on
    loopback.

    Returns ``None`` where the platform does not expose ``TCP_MAXSEG`` or the
    connection fails. Note this is what the *kernels agreed*, not what a
    middlebox further along will actually pass -- for that, measure with
    :func:`discover_mtu`.
    """
    option = getattr(_socket, "TCP_MAXSEG", None)
    if option is None:
        return None

    # Let getaddrinfo pick the family so a v6-only destination works.
    try:
        infos = _socket.getaddrinfo(dst, int(port), 0, _socket.SOCK_STREAM)
    except (OSError, OverflowError, ValueError):
        return None

    for family, kind, proto, _canon, addr in infos:
        sock = _socket.socket(family, kind, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(addr)
            value = int(sock.getsockopt(_socket.IPPROTO_TCP, option))
            return value if value > 0 else None
        except (OSError, OverflowError, ValueError):
            continue
        finally:
            sock.close()
    return None


def _ip_header_bytes(dst) -> int:
    """Fixed IP header size for ``dst``'s address family: 20 (v4) or 40 (v6).

    Every "wire size = payload + overhead" sum in this module depends on it.
    Assuming IPv4 on a v6 path under-reports by 20 bytes, which is exactly the
    sort of quiet 20-byte error that makes an MTU figure untrustworthy.

    Falls back to 20 for an unresolvable name -- IPv4 is the safer guess, since
    over-reporting an MTU causes drops while under-reporting only wastes a
    little headroom.
    """
    from . import try_parse

    parsed = try_parse(dst)
    if parsed is None:
        # A hostname: ask the resolver which family it actually resolves to.
        try:
            infos = _socket.getaddrinfo(dst, None, 0, _socket.SOCK_STREAM)
        except OSError:
            return 20
        family = infos[0][0] if infos else _socket.AF_INET
        return 40 if family == _socket.AF_INET6 else 20
    return 40 if parsed.version == 6 else 20


def _tcp_header_overhead(dst) -> int:
    """IP + TCP header bytes for ``dst``: 40 (IPv4) or 60 (IPv6)."""
    return _ip_header_bytes(dst) + 20
