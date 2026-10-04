"""``discover_mtu``: path MTU by probing, and the largest UDP payload an MTU holds."""

from __future__ import annotations

import re as _re
import socket as _socket
import sys as _sys
from typing import Any, Callable, Dict, Literal, Optional, Tuple, cast as _cast
from .. import _proc
from .._ifaddrs import (
    InterfaceLike,
    get_interface,
    get_interfaces,
    interface_address as _interface_address,
    is_local_address,
)
from .._ip import HostLike, IPAddress, _dst_argument
from .._parse import try_parse
from .._ping import ping, supports_dont_fragment
from .._scheme import coerce_port as _coerce_port
from ._connect import _resolve_targets, get_source_ip
from ._nexthop import _ROUTE_TIMEOUT_SECONDS
from ._pmtu import _set_dont_fragment, _tcp_mss, get_pmtu
from ._route import get_route

_IS_WINDOWS = _sys.platform == "win32"
_IS_LINUX = _sys.platform.startswith("linux")


#: Fixed IP header sizes. IPv4's is the *minimum* (options can extend it to 60);
#: IPv6's is exact, because its extension headers are counted as payload.
_IPV4_HEADER = 20
_IPV6_HEADER = 40
_UDP_HEADER = 8


def max_udp_payload(mtu: int, *, ipv6: bool = False) -> int:
    """The largest UDP payload that fits *mtu* without fragmenting.

    ``mtu - ip_header - 8``, where the IP header is 20 for v4 and 40 for v6::

        max_udp_payload(1500)              # 1472
        max_udp_payload(1500, ipv6=True)   # 1452

    Pair it with :attr:`netimps.Interface.mtu` to size a datagram to the
    interface it will leave by. Three things make this worth a function rather
    than arithmetic at the call site:

    - the v4 figure uses the **minimum** 20-byte header, so a packet carrying IP
      options can still fragment. Subtract more if you set any.
    - IPv6 counts its extension headers as payload, so 40 is exact only without
      them.
    - ``Interface.mtu`` is ``Optional[int]``, so a caller must handle ``None``
      rather than assume. That is why this takes an ``int`` and does not accept
      an ``Interface``: the ``None`` decision belongs to the caller, who knows
      whether to fall back to 1500 or to refuse.

      ``None`` means the platform genuinely could not read an MTU, and never
      "unbounded": the Windows loopback adapter reports ULONG max, which
      ``Interface.mtu`` clamps to 65535, and this returns the 65507 that was
      measured to actually arrive. A ``None`` there would send a caller falling
      back to 1500 to cap loopback at 1472.

    Returns 0 rather than a negative number for an MTU too small to carry any
    payload.

    :raises ValueError: for a negative *mtu*.
    """
    if mtu < 0:
        raise ValueError("mtu must not be negative, got %r" % (mtu,))
    overhead = (_IPV6_HEADER if ipv6 else _IPV4_HEADER) + _UDP_HEADER
    return max(0, mtu - overhead)


def discover_mtu(
    dst: "HostLike",
    *,
    low: int = 576,
    high: int = 9000,
    timeout: float = 1.0,
    src: "InterfaceLike" = None,
    port: int = 80,
    probe: bool = True,
    method: "Literal['icmp', 'tcp', 'udp']" = "icmp",
    tries: int = 1,
    ipv6: "Optional[bool]" = None,
    ttl: "Optional[int]" = None,
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
    :param high: the size the search tries first as its ceiling. The path
        cannot be wider than the link it leaves by, so a probe at ``high``
        that is answered does not end the search: it goes on up to that link's
        MTU, and the answer is a measurement. Only when the link's MTU cannot
        be read is ``high`` the ceiling, and a result equal to it then means
        "at least ``high``". A ``high`` above the link's MTU is lowered to it.
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
        (:func:`get_tcp_mss`) and adds the header of the family that
        connected back (40 bytes for IPv4, 60 for IPv6), which is the closest
        true equivalent. That is what the two *kernels agreed*,
        not necessarily what a middlebox further along will pass -- use
        ``"icmp"`` or ``"udp"`` when the answer must be measured.
    :param probe: set ``False`` to skip probing entirely and just return
        :func:`get_pmtu` -- the kernel's cached answer, usually ``None``.
    :param tries: probes per size, passed to :func:`ping` for ``method="icmp"``;
        ``tries=3`` tolerates a lossy path.
    :param ipv6: force the family; ``None`` takes whichever ``dst`` resolves to.
        Applies to every method; the name is resolved once and the header
        overhead is that of the address probed.
    :param ttl: initial hop limit of the ICMP probes.

    ``size`` and ``dont_fragment`` are what the search varies, so they are not
    parameters.

    Returns the MTU **including headers** (payload + 28 for IPv4 + ICMP), so it
    is directly comparable with :attr:`Interface.mtu`. The platform ``ping``
    has a largest probe of its own (a 65500-byte payload on Windows, the
    ``net.inet.raw.maxdgram`` sysctl on macOS and the BSDs: 8192 on macOS 15.7),
    and so has a UDP socket there (``net.inet.udp.maxdgram``: a 9216-byte payload).
    A destination on this host that the search takes that far is reported at
    the loopback interface's MTU, since no hop narrows the path; any other
    path that reaches it is retried with ``"udp"`` and is otherwise reported at
    that limit, meaning "at least". Returns ``None`` when
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
        return get_pmtu(dst, port, ipv6=ipv6)

    lowered = (method or "icmp").lower()
    if lowered not in ("icmp", "udp", "tcp"):
        raise ValueError("method must be 'icmp', 'udp' or 'tcp', got %r" % (lowered,))
    method = _cast("Literal['icmp', 'tcp', 'udp']", lowered)

    if method == "tcp":
        # TCP cannot probe: the kernel segments the stream, so a large send()
        # silently becomes many packets and measures nothing. The negotiated
        # MSS is the closest true equivalent -- derive the MTU from it rather
        # than refusing to answer.
        measured = _tcp_mss(dst, port, timeout, ipv6)
        if measured is None:
            return None
        mss, family = measured
        # IPv4 is 20 + 20 TCP, IPv6 is 40 + 20, so the family that connected
        # decides the header.
        return mss + (60 if family == _socket.AF_INET6 else 40)

    # One resolution decides the target, the family and the header overhead.
    targets = _resolve_targets(dst, port, ipv6, _socket.SOCK_DGRAM)
    if not targets:
        return None
    family, sockaddr = targets[0]
    address = sockaddr[0]
    wants_six = family == _socket.AF_INET6

    if method == "udp":
        return _discover_mtu_udp(
            address, port, low, high, timeout, wants_six, src=src, sockaddr=sockaddr
        )

    if not supports_dont_fragment(address, wants_six):
        # The binary search is only meaningful when the probe cannot be
        # fragmented. Where the platform's ping has no DF flag for this
        # family -- BSD's ping6 -- passing dont_fragment=True raises, and
        # dropping it would return `high` as if it had been measured.
        return None

    # ping's size= is the ICMP *payload* on both Windows (-l) and POSIX (-s) --
    # neither counts headers -- so the wire packet is larger by the IP header
    # plus 8 (ICMP): 28 for IPv4, 48 for IPv6.
    overhead = (40 if wants_six else 20) + 8

    # Only what the caller changed is forwarded, so ``ping`` keeps owning its
    # own defaults.
    forwarded: "Dict[str, Any]" = {}
    if tries != 1:
        forwarded["tries"] = tries
    if ipv6 is not None:
        forwarded["ipv6"] = ipv6
    if ttl is not None:
        forwarded["ttl"] = ttl

    def survives(mtu: int) -> bool:
        payload = mtu - overhead
        if payload < 0:
            return False
        return bool(
            ping(
                address,
                size=payload,
                dont_fragment=True,
                timeout=timeout,
                src=src,
                **forwarded,
            )
        )

    first_hop, local = _outgoing_path(address, wants_six, src)
    limit = _icmp_packet_limit(overhead)
    found, bound_by_tool = _search_mtu(survives, low, high, first_hop, limit, local)
    if bound_by_tool and found is not None:
        # The platform's ping cannot send a larger packet, and the path may
        # carry one. UDP has no such limit.
        wider = _discover_mtu_udp(
            address,
            port,
            found,
            first_hop or high,
            timeout,
            wants_six,
            src=src,
            sockaddr=sockaddr,
        )
        if wider is not None and wider > found:
            return wider
    return found


#: The largest IP packet there is. A probe cannot be bigger.
_IP_MAXIMUM = 65535

#: Largest ICMP echo payload the Windows ``ping`` sends: -l 65500 is answered
#: and -l 65501 is not (measured 2026-10-05, Windows 11).
_WINDOWS_PING_MAX_PAYLOAD = 65500


def _parse_sysctl_int(text: str) -> "Optional[int]":
    """The integer a ``sysctl -n`` run printed, or ``None``."""
    match = _re.search(r"(\d+)\s*$", text)
    return int(match.group(1)) if match else None


def _sysctl_int(name: str) -> "Optional[int]":
    """The integer value of the ``sysctl`` *name*, or ``None`` if it cannot be read."""
    try:
        result = _proc.run("sysctl", ["-n", name], timeout=_ROUTE_TIMEOUT_SECONDS)
    except (OSError, ValueError, TimeoutError):
        return None
    return _parse_sysctl_int(result.stdout) if result.returncode == 0 else None


def _icmp_packet_limit(overhead: int) -> int:
    """The largest packet, headers included, that the platform ``ping`` can send.

    Windows stops at a 65500-byte payload. On macOS and the BSDs the raw
    socket ``ping`` writes to refuses a datagram above ``net.inet.raw.maxdgram``
    (8192 on macOS 15.7: ``-s 8164`` is answered, ``-s 8184`` is not). Linux is
    bound by the IP maximum alone.
    """
    if _IS_WINDOWS:
        return min(_IP_MAXIMUM, _WINDOWS_PING_MAX_PAYLOAD + overhead)
    if _IS_LINUX:
        return _IP_MAXIMUM
    value = _sysctl_int("net.inet.raw.maxdgram")
    return min(_IP_MAXIMUM, value) if value else _IP_MAXIMUM


def _udp_packet_limit(overhead: int) -> int:
    """The largest packet, headers included, that a UDP socket here can send.

    macOS and the BSDs refuse a UDP payload above ``net.inet.udp.maxdgram``
    (9216 on macOS 15: a 9216-byte payload is echoed on loopback, whose MTU is
    16384, and nothing larger is). Windows and Linux are bound by the IP
    maximum alone.
    """
    if _IS_WINDOWS or _IS_LINUX:
        return _IP_MAXIMUM
    value = _sysctl_int("net.inet.udp.maxdgram")
    return min(_IP_MAXIMUM, value + overhead) if value else _IP_MAXIMUM


def _outgoing_path(
    address: str, wants_six: bool, src: "InterfaceLike" = None
) -> "Tuple[Optional[int], bool]":
    """``(mtu, local)``: the first hop's link MTU, and whether ``address`` is this host.

    A packet cannot be wider than the link it leaves by, so that MTU bounds a
    path search. A destination on this host leaves by the loopback interface
    whichever adapter holds the address. ``None`` is "could not tell".
    """
    try:
        parsed = try_parse(address, IPAddress)
        if parsed is None:
            return None, False
        interfaces = get_interfaces()
        loopback = next(
            (
                iface
                for iface in interfaces
                if iface.is_loopback
                and any(entry.version == parsed.version for entry in iface.ips)
            ),
            None,
        )
        if loopback is not None and is_local_address(parsed):
            return loopback.mtu, True
        chosen = None
        if src is not None:
            held = _interface_address(src, wants_six, strict=False)
            chosen = get_interface(held) if held is not None else None
        else:
            index = get_route(parsed).interface_index
            chosen = next((i for i in interfaces if index and i.index == index), None)
            if chosen is None:
                source = get_source_ip(parsed)
                chosen = get_interface(source) if source is not None else None
        return (chosen.mtu if chosen is not None else None), False
    except (OSError, ValueError, TypeError):
        return None, False


def _search_mtu(
    survives: "Callable[[int], bool]",
    low: int,
    high: int,
    first_hop: "Optional[int]",
    limit: int,
    local: bool,
) -> "Tuple[Optional[int], bool]":
    """Binary-search the largest surviving size: ``(size, bound_by_the_tool)``.

    The path cannot be wider than its first hop, so that MTU is the ceiling
    when it is known, and a probe at ``high`` that is answered does not end
    the search: it goes on to the ceiling. With no first hop known the ceiling
    is ``high``, and a result equal to it means "at least".

    ``limit`` is the largest probe the tool can send. A search that ends there
    below the first hop's MTU is *bound by the tool*: on a local destination
    nothing narrows the path, so the MTU is the first hop's; otherwise the
    caller is told and may try another way.
    """
    ceiling = limit if first_hop is None else min(first_hop, limit)
    start = min(high, ceiling)
    if first_hop is None:
        ceiling = start
    if not survives(low):
        return None, False
    if survives(start):
        found = start
        if start < ceiling:
            found = ceiling if survives(ceiling) else _narrow(survives, start, ceiling)
    else:
        found = _narrow(survives, low, start)
    if found == limit and first_hop is not None and first_hop > limit:
        return (first_hop, False) if local else (found, True)
    return found, False


def _narrow(survives: "Callable[[int], bool]", low: int, high: int) -> int:
    """The largest size in ``[low, high)`` that survives, given that ``low`` does."""
    while high - low > 1:
        middle = (low + high) // 2
        if survives(middle):
            low = middle
        else:
            high = middle
    return low


def _discover_mtu_udp(
    address: str,
    port: int,
    low: int,
    high: int,
    timeout: float,
    wants_six: bool = False,
    *,
    src: "InterfaceLike" = None,
    sockaddr: "Any" = None,
) -> "Optional[int]":
    """Binary-search the largest UDP datagram that survives to ``address``:``port``.

    Needs something at the far end that replies (an echo service, a DNS
    resolver, anything). Silence is treated as "too big", so a filtered or
    absent listener makes every size fail and the result is ``None``.

    The socket takes the destination's family, and the don't-fragment option
    is set on every platform that has one: without it oversized datagrams are
    fragmented locally, reassembled by the peer and answered, every size
    survives and the search returns ``high``. Where DF cannot be set this
    returns ``None`` rather than a number it cannot stand behind.
    """
    if sockaddr is None:
        targets = _resolve_targets(address, port, wants_six, _socket.SOCK_DGRAM)
        if not targets:
            return None
        sockaddr = targets[0][1]
    family = _socket.AF_INET6 if wants_six else _socket.AF_INET
    overhead = (40 if wants_six else 20) + 8  # IP + UDP

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

    first_hop, local = _outgoing_path(address, wants_six, src)
    limit = _udp_packet_limit(overhead)
    found, _ = _search_mtu(survives, low, high, first_hop, limit, local)
    return found
