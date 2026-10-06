"""``ping``: the entry point that picks a method, retries and builds the result."""

from __future__ import annotations

import sys as _sys
from typing import List, Literal, Optional, Union, cast as _cast
from .. import _proc
from .._ifaddrs import InterfaceLike, interface_address as _interface_address
from .._ip import HostLike, IPAddress, _dst_argument
from .._parse import try_parse as _try_parse
from ._result import PingResult
from ._probe import _expected_addresses, _tcp_ping, _udp_ping
from ._output import _parse_ping_output
from ._command import _ping_command, _wants_ipv6, supports_dont_fragment


def ping(
    dst: "HostLike",
    *,
    tries: int = 1,
    timeout: float = 1.0,
    ipv6: Optional[bool] = None,
    src: "InterfaceLike" = None,
    size: Optional[int] = None,
    ttl: Optional[int] = None,
    dont_fragment: bool = False,
    method: "Literal['icmp', 'tcp', 'udp']" = "icmp",
    port: "Optional[int]" = None,
    cache: "Union[bool, float]" = False,
) -> "PingResult":
    """Ping ``dst``; the result is truthy if it answered.

    Returns a :class:`PingResult` rather than a bare bool, so the reply details
    are available without re-running and re-parsing ``ping``::

        ping("8.8.8.8")                          # ICMP echo
        ping("8.8.8.8", method="tcp", port=53)   # time a TCP handshake
        ping("10.0.0.5", method="udp", port=53)  # datagram + reply or ICMP

        if ping("8.8.8.8"):                  # still reads as a boolean
            ...
        result = ping("8.8.8.8")
        result.rtt                           # 0.005 (seconds)
        result.ttl                           # 119

    Shells out to the platform ``ping`` binary, translating ``timeout`` into the
    right per-platform flags (Windows ``-n``/``-w`` in milliseconds; POSIX
    ``-c``/``-W`` in whole seconds), and returns on the first success::

        ping("10.0.0.1")                      # one attempt, 1s timeout
        ping("example.com", tries=3, timeout=2.5)
        ping("2001:db8::1", ipv6=True)        # force ping6 semantics
        ping(get_interfaces()[0].ipv4[0])     # an IPv4Interface -- pings its .ip
        ping(IPv4Address("10.0.0.1"))         # an address object directly

    :param dst: hostname, address string, :class:`IPv4Address`/
        :class:`IPv6Address`, or :class:`IPv4Interface`/:class:`IPv6Interface`
        (its ``.ip`` is pinged, not the ``/prefix``). A network
        (:class:`IPv4Network`/:class:`IPv6Network`) raises :class:`TypeError`
        -- it has no single address to ping.
    :param tries: attempts before giving up. Values below 1 are treated as 1.
    :param timeout: seconds to wait per attempt. Linux ``ping -W`` takes whole
        seconds, so sub-second values are rounded **up** to 1 -- never down to
        0, which some implementations read as "wait forever". Windows ``-w``
        and BSD/macOS ``-W`` take milliseconds (rounded up to 1 ms); BSD
        ``ping6`` has no wait flag and the subprocess deadline bounds it. The
        timeout also bounds the lookup of a hostname ``dst``, which happens
        once before the first attempt.
    :param ipv6: force the IPv6 or IPv4 family. Applies to **all three**
        ``method`` values: it selects the ``-6``/``-4`` flag for ICMP and the
        address family the ``tcp``/``udp`` probes resolve and connect with.
        ``None`` (default) lets the resolver decide, and accepts a reply from
        either family. An address-literal ``dst`` decides for itself.
    :param src: send from this local address, choosing which interface the
        echo leaves by. Accepts an :class:`Interface`, an address object, or a
        string::

            ping("8.8.8.8", src=get_source_ip())            # address object
            ping("8.8.8.8", src=get_interfaces()[0])        # Interface
            ping("8.8.8.8", src="192.0.2.10")               # literal
            ping("8.8.8.8", src=MACAddress("00:00:5e:00:53:01"))  # by MAC

        A **MAC address** (object or string) is resolved to the interface
        holding it -- convenient when the adapter is known by hardware address
        rather than by a possibly-changing IP. An unknown MAC yields a falsy
        result rather than falling back.

        An ``Interface`` contributes its first non-loopback IPv4 address (its
        IPv6 address when ``ipv6=True``), because Windows ``-S`` requires an
        *address* -- passing an adapter name there fails. POSIX ``-I`` would
        accept a name, but resolving it here keeps behaviour identical on both.
        An interface holding no usable address yields a falsy result rather
        than falling back to the default route.

        Likewise an address not held by any local interface makes ``ping``
        fail, so the result is falsy -- this never silently reroutes.
    :param cache: reuse a recent enumeration of the adapters while ``src`` is
        resolved, as :func:`get_interfaces` does (``True`` for
        :data:`INTERFACE_CACHE_TTL` seconds, or a number for that TTL).
        ``False`` (the default) enumerates on each call; ignored without ``src``.
    :param size: ICMP **payload** bytes -- Windows ``-l``, POSIX ``-s``. Both
        flags mean the same thing: neither counts headers, so the wire packet is
        28 bytes larger (20 IP + 8 ICMP). Payload 1472 is exactly 1500 on the
        wire, which is why that is the number a 1500-MTU link tops out at.
        Verified on Windows against the DF boundary (1472 passes, 1473 does
        not); ``ping(8)`` documents ``-s`` as "data bytes" identically.
    :param ttl: initial hop limit (``-i`` on Windows, ``-t`` on Linux, ``-m`` on
        macOS/BSD ``ping`` and ``-h`` on ``ping6`` -- the letters differ between
        platforms, a classic source of scripts that silently do the wrong
        thing).

        A ``ttl`` too small to reach the target yields ``False`` on every
        platform. That takes explicit work on Windows, whose ``ping`` exits
        ``0`` for "TTL expired in transit" -- counting a router's error as a
        received reply -- so the raw exit code would report success although
        the target was never reached. The reply address is verified instead
        (see below), which is locale-independent.
    :param method: how to probe -- ``"icmp"`` (default), ``"tcp"`` or
        ``"udp"``. ICMP is the classic echo; the other two reach a host through
        firewalls that drop echo but permit ordinary traffic.

        All three answer **"is the host up?"**. A TCP *refusal* therefore counts
        as success -- the RST proves something answered -- and so does an ICMP
        port-unreachable for UDP. Use :func:`netimps.tcp_check` when the
        question is "is the *service* up?", where a refusal is a failure.

        **On Windows a refusal takes about two seconds to arrive**: the SYN is
        retried before the RST is reported (measured 2.02 s against a closed
        loopback port; macOS answers in 0.9 ms). A ``timeout`` under two seconds
        therefore reports a refusing Windows host as down, so give ``method="tcp"``
        a ``timeout`` of at least 3 there.

        The UDP probe connects its socket before sending, so the ICMP
        port-unreachable is delivered on POSIX as well as Windows -- an
        unconnected socket never receives one on Linux/BSD, which would make
        this method under-report liveness there for exactly the case it exists
        for. Silence still means "no answer": UDP cannot tell a filtered
        port from an absent host.
    :param port: destination port for ``tcp``/``udp``. Required for those, and
        ignored for ICMP.
    :param dont_fragment: set the DF bit (Windows ``-f``, Linux ``-M do``,
        macOS/BSD ``ping`` ``-D``). Combined with ``size``, the standard manual
        MTU probe: the largest ``size`` that still succeeds is the path MTU
        minus 28. BSD ``ping6`` has no verified DF flag, so the combination
        raises :class:`ValueError` instead of sending fragmentable probes.

    An empty ``dst`` gives a falsy result. A missing ``ping`` binary or a
    non-zero exit also yield a falsy :class:`PingResult` -- *reachability*
    failures are never raised.

    **Caller mistakes are raised**, as they are elsewhere in this package, so a
    typo cannot masquerade as an unreachable host: :class:`ValueError` for an
    unknown ``method``, a negative ``size``, a ``ttl`` outside 1-255, a
    ``tcp``/``udp`` probe with no ``port``, ``dont_fragment`` on a method or
    platform that cannot set it, and a ``dst`` beginning with ``-``. That last
    one matters more than it looks: the binary reads such a destination as an
    option, and Windows ``ping -?`` prints usage and **exits 0**, which would
    be reported as a successful ping of a host that was never contacted.

    .. note::
       This measures whether *ICMP echo* is answered, which is not the same as
       whether a host is up -- plenty of hosts and most cloud firewalls drop
       echo requests while serving traffic normally. Prefer a TCP connect to
       the port you actually care about when you can.
    """
    text = _dst_argument(dst)
    if not text:
        return PingResult(False, dst, attempts=0)
    dst = text

    # A destination that begins with "-" is read by the binary as an option,
    # not a host. Windows `ping -?` then prints usage and exits 0, which would
    # come back as a *truthy* PingResult for a host that was never contacted --
    # a false positive, which is the worse direction for a liveness check.
    if dst.startswith("-"):
        raise ValueError(
            "dst %r starts with '-' and would be read as an option, not a host" % (dst,)
        )

    lowered = (method or "icmp").lower()
    if lowered not in ("icmp", "tcp", "udp"):
        raise ValueError("method must be 'icmp', 'tcp' or 'udp', got %r" % (lowered,))
    method = _cast("Literal['icmp', 'tcp', 'udp']", lowered)

    # Validate every argument the same way for every method, so one bad value
    # cannot raise for one method and be silently accepted by another.
    if size is not None and size < 0:
        raise ValueError("size must be non-negative, got %r" % (size,))
    if ttl is not None and not 1 <= ttl <= 255:
        raise ValueError("ttl must be 1-255, got %r" % (ttl,))

    resolved_source = None
    expected: "Optional[List[IPAddress]]" = None
    if src is not None:
        # The source has to be of the destination's family: a literal decides
        # for itself, and a name is resolved (once, bounded) to learn it.
        if ipv6 is None and _try_parse(dst) is None:
            expected = _expected_addresses(dst, ipv6, timeout)
        resolved_source = _interface_address(
            src,
            want_ipv6=_wants_ipv6(dst, ipv6, expected),
            strict=False,
            cache=cache,
        )
        if resolved_source is None:
            # An interface with no usable address cannot be a src.
            return PingResult(False, dst, attempts=0)

    if method != "icmp":
        if port is None:
            raise ValueError("method=%r needs a port" % (method,))
        if dont_fragment:
            # DF is a property of the probe packet, which only the ICMP path
            # builds. Silently ignoring it here is what let discover_mtu report
            # a confident wrong MTU; say so instead.
            raise ValueError(
                "dont_fragment applies to method='icmp' only, not %r" % (method,)
            )
        prober = _tcp_ping if method == "tcp" else _udp_ping
        probe_size = size or 0
        # `ipv6=`, `src=` and `ttl=` apply to these methods too, not just to the
        # ICMP binary.
        probe_src = _try_parse(dst)
        last = None
        for attempt in range(1, max(1, tries) + 1):
            ok, rtt, note = prober(
                dst, port, timeout, probe_size, ipv6, resolved_source, ttl
            )
            if ok:
                return PingResult(
                    True,
                    dst,
                    rtt=rtt,
                    src=probe_src,
                    attempts=attempt,
                )
            last = attempt
        return PingResult(False, dst, attempts=last or 1)

    tries = max(1, tries)

    # Resolve once, here, and let both decisions read the same answer. The
    # reply-address expectation and (on BSD) the choice of binary are two
    # questions about one lookup; asking twice costs an extra round trip and
    # lets them disagree about which host is being pinged.
    if expected is None:
        expected = _expected_addresses(dst, ipv6, timeout)

    if dont_fragment and not supports_dont_fragment(dst, ipv6, expected):
        raise ValueError(
            "dont_fragment cannot be set for this destination on %s "
            "(no verified DF flag for ping6 here); a probe without DF measures "
            "nothing, so this refuses rather than answering wrongly" % (_sys.platform,)
        )
    argv, used_ping6 = _ping_command(
        dst,
        ipv6,
        timeout,
        str(resolved_source) if resolved_source is not None else None,
        size,
        ttl,
        dont_fragment,
        expected,
    )
    # A hard cap on the subprocess itself: the per-reply flag bounds how long
    # ping waits for an answer, but not how long name resolution can hang
    # beforehand -- and BSD `ping6` has no wait flag at all, so this is the only
    # bound there.
    wall_timeout = max(timeout, 1.0) + 5.0

    for attempt in range(1, tries + 1):
        try:
            response = _proc.run(argv[0], argv[1:], timeout=wall_timeout)
        except OSError:
            # No ping binary, or it hung past the wall clock (TimeoutError).
            return PingResult(False, dst, attempts=attempt)
        if response.returncode != 0:
            continue

        text = response.stdout

        # A zero exit is not proof the *target* answered: Windows also exits 0
        # for "TTL expired in transit", where a router replied instead. Confirm
        # by address, which is locale-independent.
        rtt, reply_ttl, reply_src = _parse_ping_output(text, expected)
        if expected:
            if reply_src is None:
                continue  # zero exit, but nothing from the destination
        elif rtt is None and reply_ttl is None:
            # Nothing resolved, so there is no address to verify against. A bare
            # exit code is not enough on its own -- `ping -?` prints usage and
            # exits 0 -- so require some positive evidence of a reply instead.
            continue
        return PingResult(
            True,
            dst,
            rtt=rtt,
            ttl=reply_ttl,
            src=reply_src,
            attempts=attempt,
        )
    return PingResult(False, dst, attempts=tries)
