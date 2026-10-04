"""Resolving a destination, and the TCP and UDP probes that stand in for ICMP."""

from __future__ import annotations

import socket as _socket
from typing import Any, List, Optional
from .. import _dns
from .._ip import IPAddress
from .._parse import try_parse as _try_parse

#: Smallest bound handed to a name lookup. A ``timeout`` of ``0`` means "be
#: quick", not "give the resolver no time at all".
_MIN_LOOKUP_SECONDS = 0.05


def _lookup(call: "Any", timeout: "Optional[float]") -> "Any":
    """``call()`` under ``timeout`` seconds: the resolver module's bounded
    lookup, so a name server that hangs costs ``timeout`` and not however long
    it takes to give up. :class:`ResolutionTimeoutError` is an ``OSError``,
    which every caller here already treats as "did not resolve"."""
    bound = None if timeout is None else max(timeout, _MIN_LOOKUP_SECONDS)
    return _dns._bounded_lookup(call, bound)


def _expected_addresses(
    dst: str, ipv6: "Optional[bool]", timeout: "Optional[float]" = None
) -> "List[IPAddress]":
    """Addresses a reply from ``dst`` may legitimately carry.

    An address literal is its own answer. A hostname has to be resolved, and
    **honouring ``ipv6``** while doing so is the whole point: the obvious
    ``gethostbyname`` is IPv4-only, so ``ping(host, ipv6=True)`` would compare
    a v6 reply against a v4 expectation and report a healthy ping as falsy.
    ``ipv6=None`` collects both families, since the platform binary is then
    free to pick either.

    Returns ``[]`` when nothing resolves, or the lookup outlasts ``timeout``,
    which callers read as "no expectation to verify against" rather than as a
    failure.
    """

    literal = _try_parse(dst)
    if literal is not None:
        return [literal]

    if ipv6 is True:
        family = _socket.AF_INET6
    elif ipv6 is False:
        family = _socket.AF_INET
    else:
        family = _socket.AF_UNSPEC

    try:
        infos = _lookup(
            lambda: _socket.getaddrinfo(dst, None, family, _socket.SOCK_STREAM),
            timeout,
        )
    except OSError:
        return []

    found: "List[IPAddress]" = []
    for info in infos:
        address = _try_parse(info[4][0])
        if address is not None and address not in found:
            found.append(address)
    return found


def _probe_targets(
    dst: str,
    port: int,
    ipv6: "Optional[bool]",
    socktype: int,
    timeout: "Optional[float]" = None,
):
    """``(family, sockaddr)`` pairs to probe ``dst`` on, in resolver order.

    The family is a property of the destination and of ``ipv6=``, not of the
    code: a socket of the other family fails inside ``connect``/``sendto`` and
    the ``OSError`` reads as "unreachable"/"no reply" -- a wrong *falsy answer*
    rather than an error, with ``ipv6=`` silently ignored.

    Returns ``[]`` when nothing resolves, or the lookup outlasts ``timeout``
    (``None``: no bound), which the callers treat as a failure to reach rather
    than raising.
    """
    if ipv6 is True:
        family = _socket.AF_INET6
    elif ipv6 is False:
        family = _socket.AF_INET
    else:
        family = _socket.AF_UNSPEC

    literal = _try_parse(dst)
    if literal is not None and ipv6 is not None and (literal.version == 6) != ipv6:
        # An address of the other family has no answer in the one asked for.
        # macOS would hand back the IPv4-mapped form of an IPv4 literal.
        return []

    try:
        infos = _lookup(
            lambda: _socket.getaddrinfo(dst, port, family, socktype), timeout
        )
    except OSError:
        return []
    return [(info[0], info[4]) for info in infos]


def _configure_probe(sock, family, source, ttl):
    """Apply ``src=``/``ttl=`` to a tcp/udp probe socket.

    Both apply to these two methods as they do to the ICMP path, so ``src``
    never silently reroutes on any of them.
    """
    if source is not None:
        # Port 0: pin the address, let the kernel pick the port.
        sock.bind((str(source), 0))
    if ttl is not None:
        if family == _socket.AF_INET6:
            sock.setsockopt(_socket.IPPROTO_IPV6, _socket.IPV6_UNICAST_HOPS, ttl)
        else:
            sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_TTL, ttl)


def _tcp_ping(dst, port, timeout, size=None, ipv6=None, source=None, ttl=None):
    """Time a TCP handshake. Returns (ok, rtt in seconds, error).

    A refused connection still counts as reachable: the RST proves the host
    answered. Only a timeout or an unroutable address is a failure.
    """
    import time as _time

    targets = _probe_targets(dst, port, ipv6, _socket.SOCK_STREAM, timeout)
    if not targets:
        return False, None, "unreachable"

    for family, sockaddr in targets:
        # Construction sits inside the try so an unsupported address family
        # cannot escape a function documented never to raise, and so a failure
        # on one resolved address still tries the next.
        try:
            sock = _socket.socket(family, _socket.SOCK_STREAM)
        except OSError:
            continue
        start = _time.perf_counter()
        try:
            sock.settimeout(timeout)
            _configure_probe(sock, family, source, ttl)
            sock.connect(sockaddr)
            return True, _time.perf_counter() - start, None
        except ConnectionRefusedError:
            # The host is alive and said "no" -- that is a measurement.
            return True, _time.perf_counter() - start, "refused"
        except (_socket.timeout, OSError):
            continue  # try the next resolved address before giving up
        finally:
            sock.close()
    return False, None, "unreachable"


def _udp_ping(dst, port, timeout, size=0, ipv6=None, source=None, ttl=None):
    """Send a UDP datagram and wait for either a reply or ICMP unreachable.

    Two distinct signals prove liveness: an application reply, or an ICMP
    port-unreachable meaning the host answered but nothing is listening.
    Silence is ambiguous -- UDP has no handshake, so a filtered port and an
    absent host look identical.

    The socket is **connected** before sending, which is load-bearing rather
    than tidiness: POSIX delivers asynchronous ICMP errors only to a
    connected UDP socket, so an unconnected probe never sees the
    port-unreachable at all and just times out. Windows reports it either
    way, which is why the unconnected version looked correct. The two
    platforms then spell the same event differently -- ``ECONNRESET`` on
    Windows, ``ECONNREFUSED`` on Linux -- so both count.
    """
    import time as _time

    targets = _probe_targets(dst, port, ipv6, _socket.SOCK_DGRAM, timeout)
    if not targets:
        return False, None, "no reply"

    for family, sockaddr in targets:
        try:
            sock = _socket.socket(family, _socket.SOCK_DGRAM)
        except OSError:
            continue
        start = _time.perf_counter()
        try:
            sock.settimeout(timeout)
            _configure_probe(sock, family, source, ttl)
            sock.connect(sockaddr)
            sock.send(bytes(max(0, size)))
            sock.recv(65535)
            return True, _time.perf_counter() - start, None
        except (ConnectionResetError, ConnectionRefusedError):
            # ICMP port unreachable -- the host is there.
            return True, _time.perf_counter() - start, "port-unreachable"
        except (_socket.timeout, OSError):
            continue
        finally:
            sock.close()
    return False, None, "no reply"
