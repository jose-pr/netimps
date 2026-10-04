"""Reaching a host: the source address, resolved targets, and TCP reachability."""

from __future__ import annotations

import socket as _socket
import time as _time
from typing import Any, List, Optional, Tuple
from .._ip import HostLike, IPAddress, _dst_argument
from .._parse import parse
from .._scheme import coerce_port as _coerce_port

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


def _resolve_targets(
    dst: str, port: int, ipv6: "Optional[bool]", socktype: int
) -> "List[Tuple[int, Any]]":
    """``(family, sockaddr)`` pairs for ``dst``, in resolver order.

    One shared spelling of "resolve, honouring ``ipv6=``", reusing
    :func:`netimps._ping._probe_targets` rather than a second copy:
    ``gethostbyname`` is IPv4-only, so the family comes from ``getaddrinfo``.
    The import is function-local only to keep the module import order free to
    change; ``_ping`` does not import this module.

    Returns ``[]`` when nothing resolves, which every caller reads as "no
    answer" rather than raising.
    """
    from .._ping import _probe_targets

    return _probe_targets(dst, port, ipv6, socktype)


def get_source_ip(
    dst: "HostLike" = _DEFAULT_PROBE,
    port: int = 80,
    *,
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
        family is not guessed from ``":" in dst``: **a hostname never contains
        a colon**, so that test would probe every name as IPv4 and a v6-only
        one would answer ``None``.

    Returns ``None`` if no route exists (e.g. IPv6 probe on an IPv4-only host).
    The returned address carries no ``%zone``: the zone identifies the adapter
    rather than the address, and :func:`get_interface` is the way back to it.
    """

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


def tcp_check(dst: "HostLike", port: int, *, timeout: "Optional[float]" = 3.0) -> bool:
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
        resolves to. ``socket.create_connection`` would apply it once *per
        resolved address* after an unbounded ``getaddrinfo``, so a name with N
        addresses could take N x ``timeout``; here resolution happens once and
        the connects share one monotonic deadline. ``0`` is floored to a small
        positive value rather than taken
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
    dst: "HostLike",
    port: int,
    *,
    deadline: float = 30.0,
    interval: float = 0.1,
    timeout: Optional[float] = None,
) -> bool:
    """Poll until ``dst``:``port`` accepts a connection, or ``deadline`` elapses.

    The "wait for the service to come up" loop every deploy and container
    script contains::

        if not wait_for_port("localhost", 5432, deadline=60):
            raise RuntimeError("database never started")

    ``dst`` accepts the same forms as :func:`tcp_check` (address objects,
    ``IPv4Interface``/``IPv6Interface``).

    :param interval: delay between attempts. Backs off, growing by half each
        round, up to the larger of 1s and ``interval`` so a long wait does not
        spin and an interval above a second is never shortened.
    :param deadline: seconds the whole wait may take.
    :param timeout: per-attempt connect timeout; defaults to ``interval``
        bounded to at least 1s.

    Returns ``True`` as soon as the port answers, ``False`` once ``deadline``
    has passed. The deadline is honoured overall, so this cannot overrun by
    more than one attempt regardless of how long individual connects block:
    :func:`tcp_check` bounds *itself* overall rather than per resolved address,
    so a ``dst`` resolving to N addresses does not stretch an attempt to N.

    An out-of-range ``port`` raises :class:`ValueError` (from
    :func:`tcp_check`) rather than being masked to 16 bits.
    """
    expires = _time.monotonic() + deadline
    per_try = timeout if timeout is not None else max(interval, 1.0)
    delay = interval

    while True:
        remaining = expires - _time.monotonic()
        if remaining <= 0:
            return False
        if tcp_check(dst, port, timeout=min(per_try, remaining)):
            return True
        remaining = expires - _time.monotonic()
        if remaining <= 0:
            return False
        _time.sleep(min(delay, remaining))
        # Backing off never shortens the interval the caller asked for.
        delay = min(delay * 1.5, max(interval, 1.0))
