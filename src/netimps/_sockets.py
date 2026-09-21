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
from subprocess import DEVNULL as _DEVNULL
from subprocess import TimeoutExpired as _SubprocessTimeout
from subprocess import run as _subprocess_run
import sys as _sys
import time as _time

from ._iface_spec import InterfaceSpec, interface_address as _interface_address
from ._iface_spec import _without_zone
from ._ifaddrs import Interface
from ._ip import (
    AddressLike,
    IPAddress,
    IPAddressLike,
    IPInterface,
    IPNetwork,
    _dst_argument,
)
from ._mac import MACAddress
from ._scheme import coerce_port as _coerce_port
from typing import Any, Iterable, Iterator, List, Optional, Tuple, Union

_InterfaceQuery = Union[
    Interface,
    IPAddressLike,
    IPInterface,
    IPNetwork,
    MACAddress,
]

__all__ = [
    "bind",
    "bind_error_hint",
    "interface_for",
    "interfaces_for",
    "is_local_address",
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
_IS_LINUX = _sys.platform.startswith("linux")

#: Probe destination for "which way does traffic go by default?". A
#: public address forces the default route; it is never contacted (see
#: get_source_ip).
_DEFAULT_PROBE = "8.8.8.8"

#: Smallest timeout actually handed to ``settimeout``. ``settimeout(0)`` does
#: **not** mean "do not wait": it puts the socket in *non-blocking* mode, so
#: ``connect`` raises ``BlockingIOError`` at once and every open port reads as
#: closed. A caller passing ``0`` means "be quick", so the value is floored
#: rather than honoured literally -- the same round-up :func:`netimps.ping`
#: applies to its own sub-second timeouts, and for the same reason.
_MIN_TIMEOUT = 0.05

# Socket options CPython does not export, named here from the platform
# headers. ``getattr`` is still tried first at every use, so a future CPython
# that does export one wins; these are the fallback, and they are guarded --
# a wrong number surfaces as ``OSError`` from ``setsockopt``, which the
# callers read as "DF unavailable" rather than as a measurement.
#
# Measured 2026-09-20: ``socket.IP_MTU``, ``IP_MTU_DISCOVER`` and
# ``IP_PMTUDISC_DO`` are absent on **every** platform including Linux (3.13
# and 3.14), which is why ``get_pmtu``'s ``getattr`` guard made its whole body
# unreachable. ``IPV6_PATHMTU``/``IPV6_DONTFRAG`` *are* exported on Linux.
_LINUX_IP_MTU = 14  # <linux/in.h>
_LINUX_IP_MTU_DISCOVER = 10  # <linux/in.h>
_LINUX_IP_PMTUDISC_DO = 2  # <linux/in.h>
_LINUX_IPV6_MTU_DISCOVER = 23  # <linux/in6.h>
_LINUX_IPV6_PMTUDISC_DO = 2  # <linux/in6.h>
_WINDOWS_IP_DONTFRAGMENT = 14  # <ws2ipdef.h>
#: The BSDs do not agree with each other here, and using one number for all of
#: them is how this shipped broken: FreeBSD's `IP_DONTFRAG` is 67, Darwin's is
#: 28, and a `setsockopt` with the wrong one simply fails -- which, for a DF
#: option, means the MTU search silently loses its whole point. Caught by CI on
#: macOS, where `_set_dont_fragment` returned False with the FreeBSD value.
_DARWIN_IP_DONTFRAG = 28  # <netinet/in.h>, Darwin
_FREEBSD_IP_DONTFRAG = 67  # <netinet/in.h>, FreeBSD
_BSD_IP_DONTFRAG = (
    _DARWIN_IP_DONTFRAG if _sys.platform == "darwin" else _FREEBSD_IP_DONTFRAG
)
#: This one they do agree on: the RFC 3542 number, same on Darwin and FreeBSD.
_BSD_IPV6_DONTFRAG = 62  # <netinet6/in6.h>


def bind(
    address: str = "",
    port: int = 0,
    *,
    family: int = _socket.AF_INET,
    kind: int = _socket.SOCK_DGRAM,
    reuse_address: bool = True,
    allow_address_takeover: bool = False,
    reuse_port: bool = False,
    broadcast: bool = False,
    interface: "InterfaceSpec" = None,
    options: "Iterable[Tuple[int, int, Any]]" = (),
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
    :param reuse_address: ask for the conventional "restart without waiting
        out ``TIME_WAIT``" behaviour. **What that takes differs by platform**,
        so the flag is not a single socket option: POSIX gets
        ``SO_REUSEADDR``, Windows gets ``SO_EXCLUSIVEADDRUSE``. See below.
    :param allow_address_takeover: set ``SO_REUSEADDR`` on Windows too, where
        it means something else entirely. Default ``False``; on POSIX it adds
        nothing, since ``reuse_address`` already sets exactly that option.
    :param reuse_port: sets ``SO_REUSEPORT``. **A no-op where the option does
        not exist** (Windows) rather than an error, so the same call works
        everywhere.
    :param options: extra ``(level, name, value)`` triples for anything not
        covered by the named arguments.
    :param listen: call ``listen(backlog)`` after binding. Ignored for
        datagram sockets, where it is meaningless.

    .. warning::
       **``SO_REUSEADDR`` is not the same option on Windows.** On POSIX it
       only permits binding an address still in ``TIME_WAIT``; two live
       sockets still cannot hold one ``addr:port``. On Windows it lets **any
       process** bind an ``addr:port`` another socket is already listening on,
       and the later binder can win subsequent connections -- reproduced on
       Windows 11, where a plain second bind was refused with ``EACCES`` while
       one through this function succeeded. So ``reuse_address=True`` sets
       ``SO_EXCLUSIVEADDRUSE`` there instead, which is the safe request with
       the same intent, and the literal option is available only by asking for
       it by its consequence: ``allow_address_takeover=True``.

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
        if allow_address_takeover:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        elif reuse_address:
            exclusive = getattr(_socket, "SO_EXCLUSIVEADDRUSE", None)
            if exclusive is None:
                sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            else:
                # Windows. Not merely "SO_REUSEADDR spelled differently": this
                # is the option that *denies* the takeover SO_REUSEADDR would
                # permit, and it is what a plain stdlib bind gets by default.
                sock.setsockopt(_socket.SOL_SOCKET, exclusive, 1)
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


def _classify_interface_query(query: _InterfaceQuery) -> "Tuple[str, Any]":
    """Return the lookup kind and normalised value, or ``("invalid", None)``."""
    import ipaddress as _ipaddress

    from . import IPAddress, IPNetwork, MACAddress, try_parse
    from ._ifaddrs import Interface

    if isinstance(query, Interface):
        return "interface", query
    if isinstance(query, MACAddress):
        return "mac", query
    if isinstance(query, (_ipaddress.IPv4Interface, _ipaddress.IPv6Interface)):
        return "address", query.ip
    if isinstance(query, (_ipaddress.IPv4Network, _ipaddress.IPv6Network)):
        return "network", query

    address = try_parse(query, IPAddress)
    if address is not None:
        return "address", address

    if isinstance(query, str) and "/" in query:
        network = try_parse(query, IPNetwork)
        if network is not None:
            return "network", network

    # MAC text cannot collide with a valid IP literal, and packed MAC bytes
    # have length 6 while packed IP addresses have length 4 or 16. Integers
    # are genuinely ambiguous, so those remain IP addresses unless callers
    # wrap them in MACAddress explicitly.
    if isinstance(query, (str, bytes)):
        mac = try_parse(query, MACAddress)
        if mac is not None:
            return "mac", mac
    return "invalid", None


def _zone_names(iface: "Interface", zone: str) -> bool:
    """True if ``zone`` identifies ``iface``.

    Linux and Windows write an IPv6 zone as the numeric interface index, the
    BSDs as the adapter name; both spellings are accepted, as they are in
    :func:`netimps._iface_spec.interface_index`.
    """
    if zone.isdigit():
        return bool(iface.index) and iface.index == int(zone)
    return iface.name == zone


def _interfaces_for_query(kind: str, wanted: Any) -> "Iterator[Interface]":
    from ._ifaddrs import get_interfaces

    if kind == "interface":
        yield wanted
        return
    if kind == "invalid":
        return

    zone = getattr(wanted, "scope_id", None) if kind == "address" else None
    if zone:
        # ``ipaddress`` keeps the zone as part of the address, so a scoped
        # literal is equal to nothing enumeration reports. Compare on the bare
        # address and use the zone for what it actually is -- a name for the
        # adapter -- rather than letting it turn a local address into "not
        # mine".
        wanted = _without_zone(wanted)

    for iface in get_interfaces():
        if kind == "mac":
            matches = iface.mac == wanted
        elif kind == "address":
            matches = any(entry.ip == wanted for entry in iface.ips)
            if matches and zone:
                # A zone that contradicts the adapter holding the address is
                # not a match: the caller named a specific adapter.
                matches = _zone_names(iface, zone)
        else:
            matches = any(
                entry.version == wanted.version and entry.ip in wanted
                for entry in iface.ips
            )
        if matches:
            yield iface


def interfaces_for(query: _InterfaceQuery) -> "Iterator[Interface]":
    """Yield every local interface matching ``query``, in OS order.

    ``query`` may be an :class:`Interface` (yielded directly), an address, an
    ``IPInterface`` (matched by its exact ``.ip``), an ``IPNetwork`` (matched
    when it contains any assigned address), or a :class:`MACAddress`. Address-
    like strings, integers and packed bytes are accepted too; a slash-bearing
    string is interpreted as a network when it is not an address.

    MAC text and 6-byte packed values are recognised after IP parsing.
    Integer MACs must be wrapped in ``MACAddress`` because an integer is also
    a valid IP-address representation. Invalid queries and misses yield
    nothing. Each matching interface is yielded once even if several of its
    assigned addresses fall within a requested network.

    A ``%zone``-qualified IPv6 address (``fe80::1%15``, ``fe80::1%eth0``) is
    matched on its bare address and **filtered** by the zone, which names the
    adapter -- the index on Linux/Windows, the adapter name on BSD. That form
    is what ``getsockname()``, ``getaddrinfo`` and every OS tool emit, and it
    used to match nothing at all, so the library denied that an address it had
    just reported was local. A zone naming an adapter that does not hold the
    address yields nothing, which is the honest answer to a contradiction.
    """
    kind, wanted = _classify_interface_query(query)
    yield from _interfaces_for_query(kind, wanted)


def interface_for(query: _InterfaceQuery, strict: bool = True) -> "Optional[Interface]":
    """Return the first local interface matching ``query``, or ``None``.

    The reverse of interface enumeration -- "a socket is bound here, which
    adapter is that?"::

        interface_for(sock.getsockname()[0])

    Accepts the same query forms as :func:`interfaces_for`; singular lookup is
    exactly the first plural result. Since addresses can appear on more than
    one adapter (especially unscoped IPv6 link-local addresses), use the plural
    form when every match matters.

    :param strict: when True (the default), a miss returns ``None``. When
        False, an address or ``IPInterface`` miss produces a synthetic
        single-address ``Interface`` so legacy callers can still attribute
        traffic. Network and MAC misses cannot be synthesized honestly and
        remain ``None``.

    The synthetic interface is named ``"<unknown>"`` and carries a host route
    (``/32`` or ``/128``), matching how degraded enumeration reports itself.
    """
    from ._ifaddrs import Interface

    kind, wanted = _classify_interface_query(query)
    match = next(_interfaces_for_query(kind, wanted), None)
    if match is not None or strict or kind != "address":
        return match

    built = _make_host_route(_without_zone(wanted))
    return Interface(name="<unknown>", ips=[built] if built else [])


def is_local_address(address: "IPAddressLike") -> bool:
    """Return whether ``address`` is loopback or assigned on this host.

    This is deliberately narrower than private, link-local, on-link, routable
    or reachable: those properties do not mean an address belongs to this
    machine. Malformed input raises exactly as :func:`parse` does.

    A ``%zone`` suffix is honoured rather than rejected (see
    :func:`interfaces_for`), so the address ``getsockname()`` hands back can be
    passed straight in.
    """
    from . import IPAddress, parse

    wanted = parse(address, IPAddress)
    if wanted.is_loopback:
        return True
    return next(interfaces_for(wanted), None) is not None


def _resolve_targets(
    dst: str, port: int, ipv6: "Optional[bool]", socktype: int
) -> "List[Tuple[int, Any]]":
    """``(family, sockaddr)`` pairs for ``dst``, in resolver order.

    One shared spelling of "resolve, honouring ``ipv6=``", reusing
    :func:`netimps._ping._probe_targets` rather than growing a second copy --
    the IPv4-only ``gethostbyname`` this module used to call is exactly the
    defect that helper was written to fix, and it had survived here at three
    more call sites. The import is function-local only to keep the module
    import order free to change; ``_ping`` does not import this module.

    Returns ``[]`` when nothing resolves, which every caller reads as "no
    answer" rather than raising.
    """
    from ._ping import _probe_targets

    return _probe_targets(dst, port, ipv6, socktype)


def _make_host_route(address: "IPAddress") -> "Optional[IPInterface]":
    import ipaddress as _ipaddress

    try:
        return _ipaddress.ip_interface("%s/%d" % (address, address.max_prefixlen))
    except ValueError:
        return None


def get_source_ip(
    dst: "AddressLike" = _DEFAULT_PROBE,
    port: int = 80,
    ipv6: "Optional[bool]" = None,
) -> "Optional[IPAddress]":
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

    :param ipv6: which family to probe -- ``True`` for IPv6, ``False`` for
        IPv4, ``None`` (the default) for whatever ``dst`` resolves to. The
        family used to be guessed with ``":" in dst``, and **a hostname never
        contains a colon**, so every name was probed as IPv4 and a v6-only one
        answered ``None``.

    Returns ``None`` if no route exists (e.g. IPv6 probe on an IPv4-only host).
    The returned address carries no ``%zone``: the zone identifies the adapter
    rather than the address, and :func:`interface_for` is the way back to it.
    """
    from . import parse

    dst = _dst_argument(dst)
    for family, sockaddr in _resolve_targets(dst, port, ipv6, _socket.SOCK_DGRAM):
        try:
            sock = _socket.socket(family, _socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            sock.connect(sockaddr)
            return parse(sock.getsockname()[0].split("%")[0], IPAddress)
        except (OSError, ValueError):
            continue
        finally:
            sock.close()
    return None


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


def _connect_timeout(timeout: "Optional[float]") -> "Optional[float]":
    """Floor a caller's timeout to something ``settimeout`` can honour.

    ``None`` passes through as "no timeout" (block). Anything else becomes at
    least :data:`_MIN_TIMEOUT`, because ``settimeout(0)`` is *non-blocking*
    rather than "do not wait": it made every open port read as closed, and a
    ``scan_ports(timeout=0)`` report every port on every host as closed.
    """
    if timeout is None:
        return None
    return max(float(timeout), _MIN_TIMEOUT)


def tcp_check(dst: "AddressLike", port: int, timeout: "Optional[float]" = 3.0) -> bool:
    """Return True if a TCP connection to ``dst``:``port`` is accepted.

    The honest reachability test, and what you almost always want instead of
    :func:`netimps.ping`: it proves the *service* answers, not merely that the
    host replies to ICMP echo (which most cloud firewalls drop anyway)::

        tcp_check("example.com", 443)
        tcp_check("db.internal", 5432, timeout=1.0)

    ``dst`` also accepts an address object or an :class:`IPv4Interface`/
    :class:`IPv6Interface` (its ``.ip`` is used).

    Never raises for a reachability outcome: refused, timed out, unresolvable
    and unreachable all yield ``False``. Only TCP handshake completion is
    checked -- not that the service behind the port is healthy. Two argument
    bugs are still raised rather than answered, because answering them would
    be answering a different question: a network
    (:class:`IPv4Network`/:class:`IPv6Network`) as ``dst`` raises
    :class:`TypeError`, and a ``port`` outside ``0-65535`` raises
    :class:`ValueError` instead of being masked to 16 bits by the socket layer
    (``port + 65536`` silently answered about ``port``).

    :param timeout: bounds **the whole call**, across every address ``dst``
        resolves to. It used to be handed to ``socket.create_connection``,
        which applies it once *per resolved address* after an unbounded
        ``getaddrinfo``, so a name with N addresses could take N x ``timeout``.
        Resolution happens once here and the connects share one monotonic
        deadline. ``0`` is floored to a small positive value rather than taken
        literally -- ``settimeout(0)`` means non-blocking, which reported every
        open port as closed. ``None`` means no timeout at all.

    .. note::
       **Not the same question as** ``ping(dst, method="tcp", port=...)``. This
       asks "is the *service* up?", so a refused connection is ``False``. That
       asks "is the *host* up?", and counts a refusal as success -- the RST
       proves something answered. Same distinction as a service check versus an
       ICMP echo. :func:`wait_for_port` and the scanners build on this one,
       because they care about the service.
    """
    dst = _dst_argument(dst)
    port = _coerce_port(port)
    budget = _connect_timeout(timeout)
    deadline = None if budget is None else _time.monotonic() + budget

    # Resolve once. create_connection resolves per call and then re-applies
    # the full timeout to each address it got, which is the overrun above.
    try:
        infos = _socket.getaddrinfo(dst, port, 0, _socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError, OverflowError):
        return False

    for family, kind, proto, _canon, sockaddr in infos:
        remaining: "Optional[float]" = None
        if deadline is not None:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                return False
        try:
            sock = _socket.socket(family, kind, proto)
        except OSError:
            continue
        try:
            sock.settimeout(remaining)
            sock.connect(sockaddr)
            return True
        except (OSError, ValueError, OverflowError):
            continue
        finally:
            sock.close()
    return False


def wait_for_port(
    dst: "AddressLike",
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

    ``dst`` accepts the same forms as :func:`tcp_check` (address objects,
    ``IPv4Interface``/``IPv6Interface``).

    :param interval: delay between attempts. Backs off up to 1s so a long wait
        does not spin.
    :param connect_timeout: per-attempt connect timeout; defaults to
        ``interval`` bounded to at least 1s.

    Returns ``True`` as soon as the port answers, ``False`` on timeout. The
    deadline is honoured overall, so this cannot overrun by more than one
    attempt regardless of how long individual connects block -- which became
    true only when :func:`tcp_check` started bounding *itself* overall rather
    than per resolved address. A ``dst`` resolving to N addresses used to
    overrun by up to N attempts.

    An out-of-range ``port`` raises :class:`ValueError` (from
    :func:`tcp_check`) rather than being masked to 16 bits.
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
            (same subnet, or loopback) and no router is involved -- **or** when
            no next-hop lookup could be made. ``on_link`` tells the two apart.
        interface_index: index of the outgoing interface, ``0`` if unknown.
        on_link: ``True`` when no gateway is needed, ``False`` when one is, and
            ``None`` when the next hop could not be looked up at all.

    ``on_link`` is three-state deliberately. It used to be ``gateway is
    None``, which turned "we never looked" into a confident ``True``: on
    macOS, where the lookup has no source to read, ``get_route('1.1.1.1')``
    reported ``on_link=True`` from a ``192.168.64.3/24`` host. ``None`` is
    falsy, so ``if route.on_link:`` still takes the safe branch, but
    ``route.on_link is True`` can now be asked and answered.
    """

    __slots__ = ("dst", "src", "gateway", "interface_index", "_on_link")

    def __init__(
        self,
        dst: "Union[str, IPAddress]",
        src: "Optional[IPAddress]" = None,
        gateway: "Optional[IPAddress]" = None,
        interface_index: int = 0,
        on_link: "Optional[bool]" = None,
    ) -> None:
        self.dst = dst
        self.src = src
        self.gateway = gateway
        self.interface_index = interface_index
        self._on_link = on_link

    @property
    def on_link(self) -> "Optional[bool]":
        """``True`` without a router, ``False`` with one, ``None`` if unknown.

        A gateway is proof on its own, so it wins over whatever was recorded.
        Its absence proves nothing by itself, which is why the constructor
        takes the flag separately.
        """
        if self.gateway is not None:
            return False
        return self._on_link

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
            and self.on_link == other.on_link
        )

    def __hash__(self) -> int:
        """Hash over exactly the fields ``__eq__`` compares.

        Defining ``__eq__`` without this set ``__hash__`` to ``None``, so a
        ``Route`` could not go in a set or be a dict key at all.
        """
        return hash(
            (self.dst, self.src, self.gateway, self.interface_index, self.on_link)
        )


#: ``(gateway_or_None, interface_index)``. A ``None`` gateway means *on-link*;
#: a ``None`` in place of the whole tuple means the lookup could not be made,
#: which is a different answer and the one :attr:`Route.on_link` reports as
#: ``None`` rather than as ``True``.
_NextHop = Tuple[Optional[str], int]


def _windows_next_hop(dest: str, ipv6: bool = False) -> "Optional[_NextHop]":
    """Next hop from ``GetBestRoute2``. Both address families.

    ``GetBestRoute2`` rather than ``GetIpForwardTable``: it asks Windows which
    route *it* would choose for a destination, so the kernel does the
    longest-prefix matching. Dumping the table and matching by hand -- which is
    what the POSIX side has to do, lacking an equivalent -- is more code and
    more ways to be wrong. It supersedes ``GetBestRoute``, which takes a packed
    IPv4 address and therefore cannot answer for IPv6 at all; this one takes a
    ``SOCKADDR_INET`` and handles both.

    Returns ``None`` when Windows reports no route (``ERROR_NETWORK_UNREACHABLE``
    for a v6 destination on a v4-only host, for instance) -- not "on-link".
    """
    import ctypes
    from ctypes import wintypes

    class _SOCKADDR_IN(ctypes.Structure):
        _fields_ = [
            ("sin_family", ctypes.c_ushort),
            ("sin_port", ctypes.c_ushort),
            ("sin_addr", ctypes.c_ubyte * 4),
            ("sin_zero", ctypes.c_ubyte * 8),
        ]

    class _SOCKADDR_IN6(ctypes.Structure):
        _fields_ = [
            ("sin6_family", ctypes.c_ushort),
            ("sin6_port", ctypes.c_ushort),
            ("sin6_flowinfo", wintypes.ULONG),
            ("sin6_addr", ctypes.c_ubyte * 16),
            ("sin6_scope_id", wintypes.ULONG),
        ]

    class _SOCKADDR_INET(ctypes.Union):
        _fields_ = [
            ("Ipv4", _SOCKADDR_IN),
            ("Ipv6", _SOCKADDR_IN6),
            ("si_family", ctypes.c_ushort),
        ]

    class _IP_ADDRESS_PREFIX(ctypes.Structure):
        _fields_ = [("Prefix", _SOCKADDR_INET), ("PrefixLength", ctypes.c_ubyte)]

    class _MIB_IPFORWARD_ROW2(ctypes.Structure):
        _fields_ = [
            ("InterfaceLuid", ctypes.c_ulonglong),
            ("InterfaceIndex", wintypes.ULONG),
            ("DestinationPrefix", _IP_ADDRESS_PREFIX),
            ("NextHop", _SOCKADDR_INET),
            ("SitePrefixLength", ctypes.c_ubyte),
            ("ValidLifetime", wintypes.ULONG),
            ("PreferredLifetime", wintypes.ULONG),
            ("Metric", wintypes.ULONG),
            ("Protocol", ctypes.c_int),
            ("Loopback", ctypes.c_ubyte),
            ("AutoconfigureAddress", ctypes.c_ubyte),
            ("Publish", ctypes.c_ubyte),
            ("Immortal", ctypes.c_ubyte),
            ("Age", wintypes.ULONG),
            ("Origin", ctypes.c_int),
        ]

    family = _socket.AF_INET6 if ipv6 else _socket.AF_INET
    packed = _socket.inet_pton(family, dest)

    destination = _SOCKADDR_INET()
    if ipv6:
        destination.Ipv6.sin6_family = family
        ctypes.memmove(destination.Ipv6.sin6_addr, packed, 16)
    else:
        destination.Ipv4.sin_family = family
        ctypes.memmove(destination.Ipv4.sin_addr, packed, 4)

    iphlpapi = ctypes.WinDLL("iphlpapi.dll")  # type: ignore[attr-defined]  # Windows-only name; mypy checks this branch on every platform, and it is already guarded at runtime
    row = _MIB_IPFORWARD_ROW2()
    best_source = _SOCKADDR_INET()
    status = iphlpapi.GetBestRoute2(
        None,  # InterfaceLuid: let Windows choose
        0,  # InterfaceIndex
        None,  # SourceAddress
        ctypes.byref(destination),
        0,  # AddressSortOptions
        ctypes.byref(row),
        ctypes.byref(best_source),
    )
    if status != 0:
        return None

    hop = row.NextHop
    if hop.si_family == _socket.AF_INET6:
        text = _socket.inet_ntop(_socket.AF_INET6, bytes(hop.Ipv6.sin6_addr))
        unspecified = "::"
    elif hop.si_family == _socket.AF_INET:
        text = _socket.inet_ntop(_socket.AF_INET, bytes(hop.Ipv4.sin_addr))
        unspecified = "0.0.0.0"
    else:
        return None
    # The unspecified address means "on-link" -- no router in the path.
    return (None if text == unspecified else text), int(row.InterfaceIndex)


#: ``/proc/net/ipv6_route`` flag bits. ``RTF_UP`` is not decoration: the
#: unreachable ``::/0`` route the kernel keeps on ``lo`` has it **clear** and
#: ``RTF_REJECT`` set, and matching it would report every global IPv6
#: destination as on-link via loopback. Measured on WSL2.
_RTF_UP = 0x0001
_RTF_REJECT = 0x0200


def _posix_next_hop(dst: str, ipv6: bool = False) -> "Optional[_NextHop]":
    """Next hop by reading the kernel routing table. Linux only.

    ``/proc/net/route`` for IPv4 and ``/proc/net/ipv6_route`` for IPv6. The
    two formats share nothing but the idea: v4 is hex little-endian words
    behind a header line, v6 is big-endian hex nibbles with no header and an
    explicit prefix length.

    Returns ``None`` when neither file can be read (every non-Linux platform,
    which is what :func:`_bsd_next_hop` is for) or nothing matched, so the
    caller can report "unknown" instead of inventing "on-link".
    """
    if ipv6:
        return _posix_next_hop_v6(dst)

    try:
        with open("/proc/net/route") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None

    # /proc/net/route omits loopback entirely on many kernels, so a lookup for
    # 127.0.0.1 would fall through to the default route (mask 0) and report the
    # LAN gateway. Loopback is on-link by definition; answer it directly.
    from . import LOOPBACK_V4, try_parse

    parsed_dest = try_parse(dst)
    if parsed_dest is not None and parsed_dest in LOOPBACK_V4:
        return None, _if_index("lo")

    try:
        packed = _struct.unpack("<I", _socket.inet_aton(dst))[0]
    except (OSError, _struct.error):
        return None

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
        if (packed & mask) == destination:
            # Longest prefix wins, so prefer the most specific match.
            ones = bin(mask).count("1")
            if best is None or ones > best[0]:
                best = (ones, gateway, parts[0])

    if best is None:
        return None
    _, gateway, name = best
    if gateway == 0:
        return None, _if_index(name)
    return _socket.inet_ntoa(_struct.pack("<I", gateway)), _if_index(name)


def _parse_ipv6_route_table(text: str, dst: str) -> "Optional[_NextHop]":
    """Longest-prefix match ``dst`` against ``/proc/net/ipv6_route`` text.

    Split out from the file read so it is testable offline against a captured
    table -- the v4 parser's equivalent bug (loopback missing from the file)
    was only ever found on a real host.

    Columns, none of them labelled: destination, prefix length, source, source
    prefix length, next hop, metric, refcount, use, flags, device.
    """
    try:
        packed = int.from_bytes(_socket.inet_pton(_socket.AF_INET6, dst), "big")
    except OSError:
        return None

    best = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            destination = int(parts[0], 16)
            prefix_length = int(parts[1], 16)
            gateway = int(parts[4], 16)
            flags = int(parts[8], 16)
        except ValueError:
            continue
        if prefix_length > 128:
            continue
        if not flags & _RTF_UP or flags & _RTF_REJECT:
            continue
        shift = 128 - prefix_length
        if (packed >> shift) != (destination >> shift):
            continue
        if best is None or prefix_length > best[0]:
            best = (prefix_length, gateway, parts[9])

    if best is None:
        return None
    _, gateway, name = best
    if gateway == 0:
        return None, _if_index(name)
    text_hop = _socket.inet_ntop(_socket.AF_INET6, gateway.to_bytes(16, "big"))
    return text_hop, _if_index(name)


def _posix_next_hop_v6(dst: str) -> "Optional[_NextHop]":
    try:
        with open("/proc/net/ipv6_route") as handle:
            table = handle.read()
    except OSError:
        return None
    return _parse_ipv6_route_table(table, dst)


def _parse_route_get_output(text: str) -> "Optional[_NextHop]":
    """Read ``route -n get <dst>`` output (BSD/macOS). Both families.

    Only the ``gateway:`` and ``interface:`` lines are read, never the prose
    or the flags block::

           route to: 1.1.1.1
        destination: default
            gateway: 192.168.64.1
          interface: en0

    A ``gateway:`` that does not parse as an address is the BSD ``link#4``
    spelling, which *is* the on-link answer -- as is no ``gateway:`` line at
    all. Returns ``None`` only when there is no ``interface:`` either, i.e.
    when nothing was matched.
    """
    from . import try_parse

    gateway = None
    name = None
    for line in text.splitlines():
        label, sep, value = line.partition(":")
        if not sep:
            continue
        label = label.strip()
        value = value.strip()
        if label == "gateway" and try_parse(value) is not None:
            gateway = value
        elif label == "interface":
            name = value
    if gateway is None and name is None:
        return None
    return gateway, _if_index(name) if name else 0


def _bsd_next_hop(dst: str, ipv6: bool = False) -> "Optional[_NextHop]":
    """Next hop from ``route -n get``, the BSD unprivileged equivalent.

    macOS and the BSDs have no ``/proc``, so :func:`_posix_next_hop` finds
    nothing there and ``get_route`` used to report ``gateway=None`` -- which,
    before :attr:`Route.on_link` became three-state, read as a confident
    "on-link" for every destination. ``route -n get`` answers the same
    question the kernel answers, unprivileged.

    ``-n`` keeps the output numeric, so nothing here depends on reverse DNS,
    and ``stdin`` is ``DEVNULL`` because a library must never consume its
    caller's. Any failure is ``None``: unknown, not on-link.
    """
    from . import LOOPBACK_V4, LOOPBACK_V6, try_parse

    # Loopback is on-link by definition, so answer it without spawning
    # anything -- and without depending on how this platform's `route` chooses
    # to spell a host route, which is the one shape not measured here.
    parsed = try_parse(dst)
    if parsed is not None and parsed in (LOOPBACK_V6 if ipv6 else LOOPBACK_V4):
        return None, 0

    command = ["route", "-n", "get"]
    if ipv6:
        command.append("-inet6")
    command.append(dst)
    try:
        result = _subprocess_run(
            command,
            capture_output=True,
            text=True,
            timeout=5.0,
            stdin=_DEVNULL,
        )
    except (OSError, ValueError, _SubprocessTimeout):
        return None
    if result.returncode != 0:
        return None
    return _parse_route_get_output(result.stdout or "")


def _if_index(name: str) -> int:
    try:
        return _socket.if_nametoindex(name)
    except (OSError, AttributeError, ValueError):
        return 0


def get_route(
    dst: "AddressLike" = _DEFAULT_PROBE, ipv6: "Optional[bool]" = None
) -> Route:
    """Return how traffic to ``dst`` leaves this host.

    Reports the src address and the **first hop** -- the gateway a packet is
    handed to, or ``None`` when the destination is on-link::

        r = get_route("8.8.8.8")
        r.src        # IPv4Address('192.0.2.10')
        r.gateway       # IPv4Address('192.0.2.1')
        r.on_link       # False

        get_route("127.0.0.1").on_link      # True -- no router involved

    ``dst`` also accepts an address object or an :class:`IPv4Interface`/
    :class:`IPv6Interface` (its ``.ip`` is used). A hostname is resolved
    through ``getaddrinfo``, so ``ipv6=`` selects which of its records the
    route is computed for; the IPv4-only ``gethostbyname`` used here before
    meant an AAAA-only name reached no lookup at all.

    First hop only, deliberately: it is available **unprivileged** on every
    supported platform, whereas the full path requires raw sockets. See
    :func:`hop_count` for distance, which does not.

    Both address families are looked up, through ``GetBestRoute2`` on Windows,
    ``/proc/net/route`` and ``/proc/net/ipv6_route`` on Linux, and
    ``route -n get`` on macOS/BSD -- the one platform where this spawns a
    short-lived process, because there is no ``/proc`` to read and the
    ``PF_ROUTE`` socket is the only other option. Where the lookup cannot be
    made -- no route, no source to read, an unresolvable name -- ``gateway``
    is ``None`` **and so is** ``on_link``, which is how "we did not find out"
    is spelled. ``on_link is True`` means a real on-link determination.

    Never raises for an unknown route: unknown pieces come back as
    ``None``/``0`` rather than an error. A network passed as ``dst`` still
    raises :class:`TypeError`.
    """
    from . import get_ip, try_parse

    dst = _dst_argument(dst)
    parsed_dest = get_ip(dst, ipv6)

    gateway_text = None
    index = 0
    on_link = None
    if parsed_dest is not None:
        # The zone names the adapter, not the address, and neither the route
        # tables nor inet_pton accept it.
        resolved = str(_without_zone(parsed_dest))
        src = get_source_ip(resolved, ipv6=ipv6)
        wants_six = parsed_dest.version == 6
        try:
            if _IS_WINDOWS:
                answer = _windows_next_hop(resolved, wants_six)
            elif _IS_LINUX:
                answer = _posix_next_hop(resolved, wants_six)
            else:
                answer = _bsd_next_hop(resolved, wants_six)
        except (OSError, AttributeError, ValueError, _struct.error):
            answer = None
        if answer is not None:
            gateway_text, index = answer
            on_link = gateway_text is None
    else:
        src = get_source_ip(dst, ipv6=ipv6)

    return Route(
        dst=parsed_dest if parsed_dest is not None else dst,
        src=src,
        gateway=try_parse(gateway_text) if gateway_text else None,
        interface_index=index,
        on_link=on_link,
    )


#: ICMP types that answer a TTL-limited probe: 11 = time exceeded (a router on
#: the path), 3 = destination unreachable (the target's port is closed, which
#: means we arrived), 0 = echo reply.
_ICMP_REPLY_TYPES = frozenset((0, 3, 11))

#: The ICMPv6 equivalents, which share *no* numbers with the v4 set: 3 = time
#: exceeded (11 in v4), 1 = destination unreachable (3 in v4), 129 = echo
#: reply (0 in v4). Reading a v6 packet with the v4 table is therefore not a
#: near miss -- ``3`` means the opposite thing in each.
_ICMPV6_REPLY_TYPES = frozenset((1, 3, 129))


def _is_icmp_reply(packet: bytes, ipv6: bool = False) -> bool:
    """True if ``packet`` is an ICMP message answering a probe.

    Raw IPv4 sockets deliver whole IP datagrams, so the ICMP type sits after
    the variable-length IP header (IHL, low nibble of byte 0, in 32-bit words).
    **Raw IPv6 sockets do not**: the kernel strips the IPv6 header and hands
    over the ICMPv6 message itself, so the type is byte 0.
    """
    if ipv6:
        return bool(packet) and packet[0] in _ICMPV6_REPLY_TYPES
    if len(packet) < 20:
        return False
    header_len = (packet[0] & 0x0F) * 4
    if len(packet) < header_len + 1:
        return False
    return packet[header_len] in _ICMP_REPLY_TYPES


def _hop_count_traceroute(
    target: str, max_hops: int, timeout: float, ipv6: bool = False
) -> "Optional[int]":
    """Hop count by driving the system traceroute. Unprivileged.

    Parses only the **hop number** and the presence of ``target`` as a literal
    address -- never the prose, which is localised ("Request timed out." /
    "Expiration du delai d'attente"). Numeric output is forced (``-d``/``-n``)
    so the destination appears as an address rather than a reverse-DNS name.

    The v6 binary differs by platform: Windows' ``tracert`` reads the family
    from the destination, Linux's ``traceroute`` takes ``-6``, and the BSDs
    ship a separate ``traceroute6`` -- the same split ``ping``/``ping6`` has.

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
        cmd = ["traceroute6"] if (ipv6 and not _IS_LINUX) else ["traceroute"]
        if ipv6 and _IS_LINUX:
            cmd.append("-6")
        cmd += [
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
        # stdin=DEVNULL: a library must never consume its caller's stdin, and
        # a traceroute that inherits a pipe can swallow whatever is in it.
        result = _subprocess_run(
            cmd,
            capture_output=True,
            text=True,
            timeout=budget,
            stdin=_DEVNULL,
        )
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
    dst: "AddressLike",
    max_hops: int = 30,
    timeout: float = 1.0,
    allow_traceroute: bool = True,
    ipv6: "Optional[bool]" = None,
) -> Optional[int]:
    """Return the number of hops to ``dst``, or ``None`` if it never answers.

    Sends TTL-limited probes and counts the routers that reply, the same
    technique ``traceroute`` uses::

        hop_count("8.8.8.8")     # 12

    ``dst`` also accepts an address object or an :class:`IPv4Interface`/
    :class:`IPv6Interface` (its ``.ip`` is used).

    Uses raw-socket probes when available (root/Administrator), and otherwise
    falls back to driving the system ``traceroute``/``tracert``, so this works
    unprivileged on a normal desktop. Pass ``allow_traceroute=False`` to require
    the in-process path, which then raises :class:`PermissionError` instead of
    shelling out.

    The fallback is slower (seconds) because it runs a whole trace. Only the
    hop number and the destination address are read from its output, never the
    localised prose, so it is not locale-dependent.

    :param ipv6: which family to resolve ``dst`` to -- ``True`` v6, ``False``
        v4, ``None`` (the default) whichever the resolver answers with. The
        probes follow: ICMPv6 with ``IPV6_UNICAST_HOPS`` for a v6 target, and
        the platform's v6 traceroute. This used to go through the IPv4-only
        ``gethostbyname``, so a v6 destination returned ``None`` -- read as
        "never answered" rather than "never asked".

    Returns ``None`` when the destination never responds within ``max_hops``.
    That is common and usually **not** a missing route: host firewalls (Windows
    Firewall in particular) routinely drop inbound ICMP even for an elevated
    process, so ``None`` here means "no answer", never "unreachable". Treat it
    as unknown rather than as a negative result.
    """
    dst = _dst_argument(dst)
    targets = _resolve_targets(dst, 0, ipv6, _socket.SOCK_DGRAM)
    if not targets:
        return None
    family, sockaddr = targets[0]
    wants_six = family == _socket.AF_INET6
    target = str(sockaddr[0]).split("%")[0]

    proto = _socket.IPPROTO_ICMPV6 if wants_six else _socket.IPPROTO_ICMP
    try:
        icmp = _socket.socket(family, _socket.SOCK_RAW, proto)
    except (OSError, AttributeError) as exc:
        if allow_traceroute:
            return _hop_count_traceroute(target, max_hops, timeout, wants_six)
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
            src = get_source_ip(target, ipv6=wants_six)
            bind_to = str(src) if src is not None else ""
        try:
            icmp.bind((bind_to, 0))
        except OSError:
            pass
        if _IS_WINDOWS:
            try:
                icmp.ioctl(  # type: ignore[attr-defined]
                    _socket.SIO_RCVALL,  # type: ignore[attr-defined]
                    _socket.RCVALL_ON,  # type: ignore[attr-defined]
                )
            except (OSError, AttributeError):
                pass
        for ttl in range(1, max_hops + 1):
            probe = _socket.socket(family, _socket.SOCK_DGRAM)
            try:
                if wants_six:
                    # IPv6 has a hop limit, not a TTL, and it is a different
                    # option at a different level -- IP_TTL on an AF_INET6
                    # socket raises rather than limiting anything.
                    probe.setsockopt(
                        _socket.IPPROTO_IPV6, _socket.IPV6_UNICAST_HOPS, ttl
                    )
                    probe_addr = (target, 33434 + ttl) + tuple(sockaddr[2:])
                else:
                    probe.setsockopt(_socket.IPPROTO_IP, _socket.IP_TTL, ttl)
                    probe_addr = (target, 33434 + ttl)
                probe.sendto(b"", probe_addr)
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
                if not _is_icmp_reply(packet, wants_six):
                    continue
                if str(addr[0]).split("%")[0] == target:
                    return ttl  # destination itself answered: distance found
                break  # a router replied: this hop is done, try the next TTL

        # Raw probes got no answer -- commonly a host firewall dropping inbound
        # ICMP even for an elevated process. Try the system tool before giving
        # up, since it often succeeds where the raw socket does not.
        return (
            _hop_count_traceroute(target, max_hops, timeout, wants_six)
            if allow_traceroute
            else None
        )
    finally:
        icmp.close()


def _option(name: str, fallback: int) -> int:
    """``socket.<name>`` if CPython exports it, else the header literal.

    Written this way round on purpose: the literal is a fact about the
    platform's headers, not about CPython, so a future release that starts
    exporting the constant silently takes over.
    """
    value = getattr(_socket, name, None)
    return fallback if value is None else int(value)


def _dont_fragment_options(family: int) -> "List[Tuple[int, int, int]]":
    """``(level, option, value)`` triples that stop local fragmentation.

    Four spellings for one idea, and **none of them is portable**: Linux uses
    ``IP_MTU_DISCOVER = IP_PMTUDISC_DO`` (which also asks the kernel to *learn*
    the path MTU), the BSDs ``IP_DONTFRAG``, Windows ``IP_DONTFRAGMENT``, and
    each has an ``IPV6_`` counterpart at a different level. Setting none of
    them -- which is what ``_discover_mtu_udp`` did -- does not fail: the stack
    fragments the probe, the peer reassembles it and answers, every size
    "survives", and the binary search confidently returns its own ceiling.
    """
    if family == _socket.AF_INET6:
        level = _socket.IPPROTO_IPV6
        if _IS_LINUX:
            return [
                (
                    level,
                    _option("IPV6_MTU_DISCOVER", _LINUX_IPV6_MTU_DISCOVER),
                    _option("IPV6_PMTUDISC_DO", _LINUX_IPV6_PMTUDISC_DO),
                )
            ]
        return [(level, _option("IPV6_DONTFRAG", _BSD_IPV6_DONTFRAG), 1)]

    level = _socket.IPPROTO_IP
    if _IS_LINUX:
        return [
            (
                level,
                _option("IP_MTU_DISCOVER", _LINUX_IP_MTU_DISCOVER),
                _option("IP_PMTUDISC_DO", _LINUX_IP_PMTUDISC_DO),
            )
        ]
    if _IS_WINDOWS:
        return [(level, _option("IP_DONTFRAGMENT", _WINDOWS_IP_DONTFRAGMENT), 1)]
    return [(level, _option("IP_DONTFRAG", _BSD_IP_DONTFRAG), 1)]


def _set_dont_fragment(sock: "_socket.socket", family: int) -> bool:
    """Set DF on ``sock``; ``False`` if this platform will not take it.

    A ``False`` here is the caller's cue to answer ``None`` rather than a
    number: an MTU search without DF measures nothing.
    """
    try:
        for level, option, value in _dont_fragment_options(family):
            sock.setsockopt(level, option, value)
    except OSError:
        return False
    return True


#: ``struct ip6_mtuinfo``: a ``sockaddr_in6`` (28 bytes on every supported
#: platform) followed by the MTU as a native ``uint32``. ``IPV6_PATHMTU``
#: returns *this*, not the bare int the IPv4 ``IP_MTU`` gives back -- reading
#: it as an int would decode the address family as the MTU.
_IP6_MTUINFO_SIZE = 32
_IP6_MTUINFO_MTU_OFFSET = 28


def _pmtu_for(family: int, sockaddr: Any) -> "Optional[int]":
    """The kernel's cached path MTU for one resolved target, or ``None``."""
    if family == _socket.AF_INET6:
        level = _socket.IPPROTO_IPV6
        # Exported by CPython on Linux (61) but not on Windows, which has no
        # equivalent at all -- so no literal fallback here.
        option = getattr(_socket, "IPV6_PATHMTU", None)
    else:
        level = _socket.IPPROTO_IP
        option = getattr(_socket, "IP_MTU", None)
        if option is None and _IS_LINUX:
            option = _LINUX_IP_MTU
    if option is None:
        return None

    try:
        sock = _socket.socket(family, _socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        # PMTU is only maintained for connected sockets in DO mode.
        _set_dont_fragment(sock, family)
        sock.connect(sockaddr)
        if family == _socket.AF_INET6:
            raw = sock.getsockopt(level, option, _IP6_MTUINFO_SIZE)
            if len(raw) < _IP6_MTUINFO_SIZE:
                return None
            value = int(_struct.unpack_from("=I", raw, _IP6_MTUINFO_MTU_OFFSET)[0])
        else:
            value = int(sock.getsockopt(level, option))
        return value if value > 0 else None
    except (OSError, OverflowError, _struct.error):
        return None
    finally:
        sock.close()


def get_pmtu(
    dst: "AddressLike", port: int = 80, ipv6: "Optional[bool]" = None
) -> "Optional[int]":
    """Return the path MTU the kernel has **already learned**, or ``None``.

    A lookup, not a measurement -- it reads ``IP_MTU`` (or ``IPV6_PATHMTU``) on
    a connected socket and sends nothing::

        get_pmtu("example.com")      # 1420, or None if nothing is cached

    ``dst`` also accepts an address object or an :class:`IPv4Interface`/
    :class:`IPv6Interface` (its ``.ip`` is used); ``ipv6=`` picks which family
    a hostname is resolved to.

    Instant and silent, but it answers a weaker question than
    :func:`discover_mtu`:

    * **``None`` is a common answer.** The kernel only knows a path MTU once
      its own discovery has learned one, which needs prior traffic that
      actually hit the limit. A fresh destination may report nothing.
    * **Windows has no ``IP_MTU``** (nor ``IP_MTU_DISCOVER`` / ``IPV6_PATHMTU``),
      so this always returns ``None`` there. Nor is there another route: the
      ``dwForwardMtu`` field of ``MIB_IPFORWARDROW`` reads **0** (verified via
      ``GetBestRoute``; Microsoft lists it as unsupported), and the newer
      ``MIB_IPFORWARD_ROW2`` dropped the field entirely. Route MTU lives at the
      interface level on Windows, which is :attr:`Interface.mtu`. Probing with
      :func:`discover_mtu` is the only way to learn a *path* MTU there.
    * macOS/BSD expose no IPv4 equivalent either, so v4 there is ``None`` too.
    * When the kernel *has* an answer it can still be the **local link** MTU
      rather than the path minimum, if nothing has yet forced it lower.

    .. note::
       ``IP_MTU``, ``IP_MTU_DISCOVER`` and ``IP_PMTUDISC_DO`` are **not
       exported by CPython on any platform**, Linux included (measured on 3.13
       and 3.14). Guarding on ``getattr(socket, "IP_MTU", None)`` therefore
       made this function unreachable everywhere rather than on Windows only,
       which is what the "usually ``None``" story was hiding. The Linux
       numbers are named from ``<linux/in.h>`` instead.

    Use it as a free first guess; use :func:`discover_mtu` when the answer has
    to be right.
    """
    dst = _dst_argument(dst)
    port = _coerce_port(port)
    for family, sockaddr in _resolve_targets(dst, port, ipv6, _socket.SOCK_DGRAM):
        value = _pmtu_for(family, sockaddr)
        if value is not None:
            return value
    return None


def discover_mtu(
    dst: "AddressLike",
    low: int = 576,
    high: int = 9000,
    timeout: float = 1.0,
    src: "InterfaceSpec" = None,
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
    size was too big" -- **and also when the don't-fragment bit cannot be set**
    for this destination on this platform (BSD's ``ping6`` has no DF flag).
    That second ``None`` is deliberate: without DF the probe is fragmented and
    reassembled, every size survives, and the search would return ``high`` as
    though it had measured something.

    .. note::
       The result can be **lower than any local** ``Interface.mtu``, and that
       is the useful case: the bottleneck is somewhere along the path, not on
       this host.
    """
    dst = _dst_argument(dst)
    port = _coerce_port(port)
    if not probe:
        # Explicitly asked for the kernel's cached answer only.
        return get_pmtu(dst, port, ping_kwargs.get("ipv6"))

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
        return _discover_mtu_udp(dst, port, low, high, timeout, ping_kwargs.get("ipv6"))

    from . import ping
    from ._ping import supports_dont_fragment

    if not supports_dont_fragment(dst, ping_kwargs.get("ipv6")):
        # The binary search is only meaningful when the probe cannot be
        # fragmented. Where the platform's ping has no DF flag for this
        # family -- BSD's ping6 -- passing dont_fragment=True raises, and
        # dropping it would return `high` as if it had been measured.
        return None

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


def _discover_mtu_udp(
    dst: str,
    port: int,
    low: int,
    high: int,
    timeout: float,
    ipv6: "Optional[bool]" = None,
) -> "Optional[int]":
    """Binary-search the largest UDP datagram that survives to ``dst``:``port``.

    Needs something at the far end that replies (an echo service, a DNS
    resolver, anything). Silence is treated as "too big", so a filtered or
    absent listener makes every size fail and the result is ``None``.

    Two things this used to get wrong, both silently. The socket was
    ``AF_INET`` whatever the destination, so every IPv6 target failed inside
    ``sendto`` and read as "no reply"; and **no DF option was set on any
    platform**, so oversized datagrams were fragmented locally, reassembled by
    the peer and answered -- making every size survive and the search return
    ``high``. Where DF cannot be set, this now returns ``None`` rather than a
    number it cannot stand behind.
    """
    targets = _resolve_targets(dst, port, ipv6, _socket.SOCK_DGRAM)
    if not targets:
        return None
    family, sockaddr = targets[0]
    overhead = (40 if family == _socket.AF_INET6 else 20) + 8  # IP + UDP

    def survives(mtu):
        payload = mtu - overhead
        if payload < 0:
            return False
        sock = _socket.socket(family, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            if not _set_dont_fragment(sock, family):
                return False
            sock.sendto(bytes(payload), sockaddr)
            sock.recvfrom(65535)
            return True
        except (OSError, _socket.timeout):
            # ConnectionResetError (ICMP port unreachable) also lands here: it
            # proves the host is reachable but says nothing about whether this
            # size made it, so treat it as a failure rather than a success.
            return False
        finally:
            sock.close()

    scout = _socket.socket(family, _socket.SOCK_DGRAM)
    try:
        if not _set_dont_fragment(scout, family):
            # Without DF every probe survives and the search returns `high`.
            # A refusal to answer is the only honest result.
            return None
    finally:
        scout.close()

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


def get_tcp_mss(dst: "AddressLike", port: int, timeout: float = 3.0) -> "Optional[int]":
    """Return the TCP maximum segment size negotiated with ``dst``, or ``None``.

    The TCP counterpart to an MTU: the largest payload a single segment may
    carry, agreed during the handshake::

        get_tcp_mss("example.com", 443)     # 1460 on a 1500-MTU path

    ``dst`` also accepts an address object or an :class:`IPv4Interface`/
    :class:`IPv6Interface` (its ``.ip`` is used).

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
    dst = _dst_argument(dst)
    port = _coerce_port(port)
    option = getattr(_socket, "TCP_MAXSEG", None)
    if option is None:
        return None

    # Let getaddrinfo pick the family so a v6-only destination works.
    try:
        infos = _socket.getaddrinfo(dst, port, 0, _socket.SOCK_STREAM)
    except (OSError, OverflowError, ValueError):
        return None

    for family, kind, proto, _canon, addr in infos:
        sock = _socket.socket(family, kind, proto)
        sock.settimeout(_connect_timeout(timeout))
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
