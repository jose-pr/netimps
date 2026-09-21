"""ICMP echo via the platform ``ping`` binary (internal).

Shelling out rather than using raw sockets, so this works unprivileged. The
cost is per-platform flag translation and output parsing, both of which are
kept strictly numeric/address-based so nothing here depends on the locale.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import math as _math
import os as _os
import re as _re
import socket as _socket
import sys as _sys
from subprocess import DEVNULL as _DEVNULL
from subprocess import TimeoutExpired as _SubprocessTimeout
from subprocess import run as _run
from typing import List, Optional, Tuple

from ._iface_spec import InterfaceSpec, interface_address as _interface_address
from ._ip import AddressLike, IPAddress, _dst_argument

__all__ = ["ping", "PingResult"]


class PingResult:
    """Outcome of a :func:`ping`, usable directly as a boolean.

    ``ping()`` has always answered "did it reply?", so this stays truthy on
    success and falsy on failure -- ``if ping(host):`` keeps working -- while
    carrying the details a caller would otherwise re-run ``ping`` to scrape.

    Attributes:
        ok: whether the destination replied.
        host: the destination as given.
        rtt_ms: round-trip time in milliseconds, or ``None`` if not reported.
            Sub-millisecond replies (``time<1ms``) are recorded as ``0.0``,
            which is falsy -- test ``is None`` rather than truthiness.
        ttl: TTL/hop-limit of the reply, or ``None``. Counts *down* from the
            sender's initial value, so a smaller number means more hops.
        src: address that answered, which on success is the destination.
        attempts: how many probes were sent before this outcome.
    """

    __slots__ = ("ok", "host", "rtt_ms", "ttl", "src", "attempts")

    def __init__(
        self,
        ok: bool,
        host: "AddressLike",
        rtt_ms: Optional[float] = None,
        ttl: Optional[int] = None,
        src: "Optional[IPAddress]" = None,
        attempts: int = 1,
    ) -> None:
        self.ok = ok
        self.host = host
        self.rtt_ms = rtt_ms
        self.ttl = ttl
        self.src = src
        self.attempts = attempts

    def __bool__(self) -> bool:
        return bool(self.ok)

    def __repr__(self) -> str:
        return "PingResult(ok=%r, host=%r, rtt_ms=%r, ttl=%r)" % (
            self.ok,
            self.host,
            self.rtt_ms,
            self.ttl,
        )

    def __eq__(self, other: object) -> bool:
        # Compares equal to a plain bool so existing `== True` assertions and
        # boolean-returning call sites keep behaving.
        if isinstance(other, bool):
            return bool(self) is other
        if isinstance(other, PingResult):
            return (
                self.ok == other.ok
                and self.host == other.host
                and self.rtt_ms == other.rtt_ms
                and self.ttl == other.ttl
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.ok, self.host, self.rtt_ms, self.ttl))


#: Which ``ping`` grammar this host speaks. **Three values, not two.**
#:
#: The old ``os.name == "nt"`` split treated every POSIX platform as Linux, and
#: they are not: of the six flags this module emits, *five* mean something
#: different or nothing at all on BSD. ``-W`` is milliseconds there rather than
#: seconds, ``-t`` is an overall deadline rather than the TTL (``-m`` is the
#: TTL, while Linux's ``-m`` is a firewall mark), ``-I`` is rejected for a
#: unicast destination (``-S`` is the source flag), DF is ``-D`` rather than
#: ``-M do``, and ``-4``/``-6`` do not exist at all -- IPv6 lives in a separate
#: ``ping6`` binary. Measured on macOS, not inferred.
#:
#: Anything that is neither Windows nor Linux is treated as BSD. That is the
#: safer default for Solaris/AIX than pretending they are GNU: a flag we fail
#: to emit is a missing feature, while a flag that means something else is a
#: wrong answer.
if _os.name == "nt":
    _PLATFORM = "windows"
elif _sys.platform.startswith("linux"):
    _PLATFORM = "linux"
else:
    _PLATFORM = "bsd"

#: ``time=5ms`` / ``time<1ms`` / ``time=0.043 ms`` across platforms. The
#: comparison operator is captured because it carries meaning: ``time<1ms`` is
#: Windows saying "under a millisecond", and reading the ``1`` as the
#: measurement over-reports a sub-millisecond reply by up to 100%.
_PING_RTT = _re.compile(r"time\s*([=<])\s*([0-9]+(?:\.[0-9]+)?)\s*ms", _re.IGNORECASE)
#: ``TTL=119`` (Windows) / ``ttl=54`` (Linux) / ``hlim=64`` (BSD ``ping6``).
#: IPv6 does not have a "time to live" -- it has a hop limit -- and BSD says so,
#: so a v6 reply there reports no TTL at all unless ``hlim`` is matched too.
_PING_TTL = _re.compile(r"(?:ttl|hlim)[=\s]\s*([0-9]+)", _re.IGNORECASE)


def _reply_needle(address: "IPAddress") -> "_re.Pattern":
    """Match ``address`` where a reply line names its sender.

    Anchored on the punctuation that follows the address, because that is the
    one thing every platform agrees on structurally while disagreeing on
    everything around it::

        Reply from 127.0.0.1: bytes=32 time<1ms TTL=128     (Windows)
        64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 ...      (Linux)
        16 bytes from ::1, icmp_seq=0 hlim=64 ...           (BSD ping6)

    BSD uses a **comma**, which the old colon-only needle could never match, so
    a healthy v6 reply there verified as falsy.

    The lookbehind stops an address matching inside a longer one -- ``::1`` must
    not be found inside ``2001:db8::1`` -- which matters because the whole point
    of this check is proving *which* host answered.
    """
    return _re.compile(r"(?<![0-9A-Fa-f:.])" + _re.escape(str(address)) + r"[:,]")


def _expected_addresses(dst: str, ipv6: "Optional[bool]") -> "List[IPAddress]":
    """Addresses a reply from ``dst`` may legitimately carry.

    An address literal is its own answer. A hostname has to be resolved, and
    **honouring ``ipv6``** while doing so is the whole point: the obvious
    ``gethostbyname`` is IPv4-only, so ``ping(host, ipv6=True)`` would compare
    a v6 reply against a v4 expectation and report a healthy ping as falsy.
    ``ipv6=None`` collects both families, since the platform binary is then
    free to pick either.

    Returns ``[]`` when nothing resolves, which callers read as "no
    expectation to verify against" rather than as a failure.
    """
    from . import try_parse as _try_parse

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
        infos = _socket.getaddrinfo(dst, None, family, _socket.SOCK_STREAM)
    except OSError:
        return []

    found: "List[IPAddress]" = []
    for info in infos:
        address = _try_parse(info[4][0])
        if address is not None and address not in found:
            found.append(address)
    return found


def _parse_ping_output(
    text: str, expected: "List[IPAddress]"
) -> "Tuple[Optional[float], Optional[int], Optional[IPAddress]]":
    """Pull (rtt_ms, ttl, src) out of ping's stdout.

    Reads only numeric tokens that are stable across platforms and locales;
    the surrounding prose is never matched.
    """
    needles = [(address, _reply_needle(address)) for address in expected]
    rtt = ttl = src = None
    for line in text.splitlines():
        lowered = line.lower()
        # Secondary, English-only guard. The address match below is the primary
        # and locale-independent one -- a router's error line names the *router*,
        # so it cannot satisfy a needle built from the destination. This stays
        # as belt-and-braces for the case where nothing resolved and there is no
        # address to match against.
        if "expired" in lowered or "unreachable" in lowered:
            continue
        found_rtt = _PING_RTT.search(line)
        found_ttl = _PING_TTL.search(line)
        if found_rtt is None and found_ttl is None:
            continue
        answered_by = next((a for a, needle in needles if needle.search(line)), None)
        if expected and answered_by is None:
            # A measurement, but not one the destination produced. Keep looking
            # rather than reporting somebody else's number as the answer.
            continue
        if found_rtt is not None and rtt is None:
            operator, value = found_rtt.group(1), found_rtt.group(2)
            try:
                # "time<1ms" is an upper bound, not a measurement: report 0.0,
                # which is what the documented contract has always promised.
                rtt = 0.0 if operator == "<" else float(value)
            except ValueError:
                pass
        if found_ttl is not None and ttl is None:
            try:
                ttl = int(found_ttl.group(1))
            except ValueError:
                pass
        if src is None:
            src = answered_by
        break
    return rtt, ttl, src


def _probe_targets(dst: str, port: int, ipv6: "Optional[bool]", socktype: int):
    """``(family, sockaddr)`` pairs to probe ``dst`` on, in resolver order.

    Both probe methods used to hardcode ``AF_INET``, so a v6 destination
    failed inside ``connect``/``sendto`` and the ``OSError`` was reported as
    "unreachable"/"no reply" -- a wrong *falsy answer* rather than an error,
    with ``ipv6=`` silently ignored. Resolving here keeps the family a
    property of the destination (and of ``ipv6=``) rather than of the code.

    Returns ``[]`` when nothing resolves, which the callers treat as a
    failure to reach rather than raising.
    """
    if ipv6 is True:
        family = _socket.AF_INET6
    elif ipv6 is False:
        family = _socket.AF_INET
    else:
        family = _socket.AF_UNSPEC

    try:
        infos = _socket.getaddrinfo(dst, port, family, socktype)
    except OSError:
        return []
    return [(info[0], info[4]) for info in infos]


def _configure_probe(sock, family, source, ttl):
    """Apply ``src=``/``ttl=`` to a tcp/udp probe socket.

    Both used to be accepted by :func:`ping` and then dropped for these two
    methods -- the docstring documented ``src`` as "this never silently
    reroutes", which was true only of the ICMP path.
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
    """Time a TCP handshake. Returns (ok, rtt_ms, error).

    A refused connection still counts as reachable: the RST proves the host
    answered. Only a timeout or an unroutable address is a failure.
    """
    import time as _time

    targets = _probe_targets(dst, port, ipv6, _socket.SOCK_STREAM)
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
            return True, (_time.perf_counter() - start) * 1000.0, None
        except ConnectionRefusedError:
            # The host is alive and said "no" -- that is a measurement.
            return True, (_time.perf_counter() - start) * 1000.0, "refused"
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

    targets = _probe_targets(dst, port, ipv6, _socket.SOCK_DGRAM)
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
            return True, (_time.perf_counter() - start) * 1000.0, None
        except (ConnectionResetError, ConnectionRefusedError):
            # ICMP port unreachable -- the host is there.
            return True, (_time.perf_counter() - start) * 1000.0, "port-unreachable"
        except (_socket.timeout, OSError):
            continue
        finally:
            sock.close()
    return False, None, "no reply"


def _wants_ipv6(
    dst: str,
    ipv6: "Optional[bool]",
    resolved: "Optional[List[IPAddress]]" = None,
) -> bool:
    """Whether this probe should go out over IPv6.

    On BSD the answer selects the **binary**, not a flag, so it has to be
    decided before argv exists. An explicit ``ipv6=`` wins and an address
    literal answers for itself, neither of which costs a lookup.

    For a name, ``resolved`` is the answer :func:`_expected_addresses` already
    got, reused rather than looked up again. Resolving twice is not just waste:
    the two calls can disagree, and then the binary and the reply-address
    expectation would be arguing about different hosts. ``getaddrinfo`` returns
    the resolver's preferred family first, which is the same choice an
    unqualified ``ping`` would make.
    """
    if ipv6 is not None:
        return bool(ipv6)

    from . import try_parse as _try_parse

    literal = _try_parse(dst)
    if literal is not None:
        return literal.version == 6
    if resolved:
        return resolved[0].version == 6
    return False


def supports_dont_fragment(
    dst: "AddressLike" = "",
    ipv6: "Optional[bool]" = None,
    resolved: "Optional[List[IPAddress]]" = None,
) -> bool:
    """Whether DF can actually be set for this destination on this host.

    Exists so :func:`netimps.discover_mtu` can decline to answer rather than
    return a number it cannot stand behind: without DF the local stack
    fragments an oversized probe, the peer reassembles it and replies, every
    size "survives", and the binary search returns its own ceiling.

    BSD's ``ping`` does have a DF flag -- ``-D`` -- despite a long-standing
    comment here claiming otherwise. Its ``ping6`` is the one case with no
    verified flag, so that is the combination this reports as unsupported.
    """
    if _PLATFORM != "bsd":
        return True
    return not _wants_ipv6(_dst_argument(dst) if dst else "", ipv6, resolved)


def _ping_command(
    dst: str,
    ipv6: "Optional[bool]",
    timeout: float,
    source: "Optional[str]",
    size: "Optional[int]",
    ttl: "Optional[int]",
    dont_fragment: bool,
    resolved: "Optional[List[IPAddress]]" = None,
) -> "Tuple[List[str], bool]":
    """Build ``(argv, used_ping6)`` for one ICMP probe.

    One function per platform grammar, because the flags genuinely do not
    correspond: see the ``_PLATFORM`` comment for what differs and where it was
    measured.
    """
    use_six = _PLATFORM == "bsd" and _wants_ipv6(dst, ipv6, resolved)

    if _PLATFORM == "windows":
        # Windows counts with -n and takes a timeout in milliseconds.
        options = ["-n", "1", "-w", str(max(1, int(timeout * 1000)))]
        if ipv6 is True:
            options.append("-6")
        elif ipv6 is False:
            options.append("-4")
        if source is not None:
            options.extend(["-S", source])
        if size is not None:
            options.extend(["-l", str(size)])
        if ttl is not None:
            options.extend(["-i", str(ttl)])
        if dont_fragment:
            options.append("-f")
        return ["ping", *options, dst], False

    if _PLATFORM == "linux":
        # iputils: -W is whole seconds, rounded up so a sub-second timeout never
        # becomes 0 (read as "wait forever" by some implementations).
        options = ["-c", "1", "-W", str(max(1, int(_math.ceil(timeout)))), "-n"]
        if ipv6 is True:
            options.append("-6")
        elif ipv6 is False:
            options.append("-4")
        if source is not None:
            options.extend(["-I", source])
        if size is not None:
            options.extend(["-s", str(size)])
        if ttl is not None:
            options.extend(["-t", str(ttl)])
        if dont_fragment:
            options.extend(["-M", "do"])
        return ["ping", *options, dst], False

    # BSD/macOS. No -4/-6 at all: `ping` is IPv4-only and cannot even take a v6
    # literal ("cannot resolve ::1: Unknown host"), so the family picks the
    # binary. The two binaries then disagree with each other as well as with
    # Linux, which is why they are spelled out separately rather than shared.
    if use_six:
        # ping6 has no -W waittime; the subprocess wall clock bounds it instead.
        options = ["-c", "1", "-n"]
        if ttl is not None:
            options.extend(["-h", str(ttl)])
        # No verified DF flag for ping6; ping(dont_fragment=True) rejects the
        # combination up front rather than silently sending fragmentable probes.
    else:
        # -W here is MILLISECONDS, not seconds. Passing the Linux value gave
        # macOS a 1ms deadline and made `timeout=` inert.
        options = ["-c", "1", "-W", str(max(1, int(_math.ceil(timeout * 1000)))), "-n"]
        if ttl is not None:
            options.extend(["-m", str(ttl)])
        if dont_fragment:
            options.append("-D")
    if source is not None:
        # -S on both. -I exists but is multicast-only and is *rejected* for a
        # unicast destination, which made every src= ping falsy here.
        options.extend(["-S", source])
    if size is not None:
        options.extend(["-s", str(size)])
    return ["ping6" if use_six else "ping", *options, dst], use_six


def ping(
    dst: "AddressLike",
    tries: int = 1,
    timeout: float = 1.0,
    ipv6: Optional[bool] = None,
    src: "InterfaceSpec" = None,
    size: Optional[int] = None,
    ttl: Optional[int] = None,
    dont_fragment: bool = False,
    method: str = "icmp",
    port: "Optional[int]" = None,
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
        result.rtt_ms                        # 5.0
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
    :param timeout: seconds to wait per attempt. POSIX ``ping`` only accepts a
        whole number of seconds, so sub-second values are rounded **up** to 1 --
        never down to 0, which some implementations read as "wait forever".
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
    :param size: ICMP **payload** bytes -- Windows ``-l``, POSIX ``-s``. Both
        flags mean the same thing: neither counts headers, so the wire packet is
        28 bytes larger (20 IP + 8 ICMP). Payload 1472 is exactly 1500 on the
        wire, which is why that is the number a 1500-MTU link tops out at.
        Verified on Windows against the DF boundary (1472 passes, 1473 does
        not); ``ping(8)`` documents ``-s`` as "data bytes" identically.
    :param ttl: initial hop limit (``-i`` on Windows, ``-t`` on POSIX -- the
        letters are **swapped** between platforms, a classic src of scripts
        that silently do the wrong thing).

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

        The UDP probe connects its socket before sending, so the ICMP
        port-unreachable is delivered on POSIX as well as Windows -- an
        unconnected socket never receives one on Linux/BSD, which made this
        method under-report liveness there for exactly the case it exists
        for. Silence still means "no answer": UDP cannot tell a filtered
        port from an absent host.
    :param port: destination port for ``tcp``/``udp``. Required for those, and
        ignored for ICMP.
    :param dont_fragment: set the DF bit (Windows ``-f``, Linux ``-M do``).
        Combined with ``size``, the standard manual MTU probe: the largest
        ``size`` that still succeeds is the path MTU minus 28. Unsupported on
        macOS/BSD ping, where it is ignored.

    An empty ``dst`` gives a falsy result. A missing ``ping`` binary or a
    non-zero exit also yield a falsy :class:`PingResult` -- *reachability*
    failures are never raised.

    **Caller mistakes are raised**, as they are elsewhere in this package, so a
    typo cannot masquerade as an unreachable host: :class:`ValueError` for an
    unknown ``method``, a negative ``size``, a ``ttl`` outside 1-255, a
    ``tcp``/``udp`` probe with no ``port``, ``dont_fragment`` on a method or
    platform that cannot set it, and a ``dst`` beginning with ``-``. That last
    one matters more than it looks: the binary reads such a destination as an
    option, and Windows ``ping -?`` prints usage and **exits 0**, which used to
    be reported as a successful ping of a host that was never contacted.

    .. note::
       This measures whether *ICMP echo* is answered, which is not the same as
       whether a host is up -- plenty of hosts and most cloud firewalls drop
       echo requests while serving traffic normally. Prefer a TCP connect to
       the port you actually care about when you can.
    """
    if not dst:
        return PingResult(False, dst, attempts=0)
    dst = _dst_argument(dst)

    from . import try_parse as _try_parse

    # A destination that begins with "-" is read by the binary as an option,
    # not a host. Windows `ping -?` then prints usage and exits 0, which used to
    # come back as a *truthy* PingResult for a host that was never contacted --
    # a false positive, which is the worse direction for a liveness check.
    if dst.startswith("-"):
        raise ValueError(
            "dst %r starts with '-' and would be read as an option, not a host" % (dst,)
        )

    method = (method or "icmp").lower()
    if method not in ("icmp", "tcp", "udp"):
        raise ValueError("method must be 'icmp', 'tcp' or 'udp', got %r" % (method,))

    # Validate every argument the same way for every method. These used to be
    # checked only on the ICMP path, so the same bad value raised for one method
    # and was silently accepted by another.
    if size is not None and size < 0:
        raise ValueError("size must be non-negative, got %r" % (size,))
    if ttl is not None and not 1 <= ttl <= 255:
        raise ValueError("ttl must be 1-255, got %r" % (ttl,))

    resolved_source = None
    if src is not None:
        resolved_source = _interface_address(src, want_ipv6=bool(ipv6), strict=False)
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
        # ICMP binary -- they used to be accepted and dropped on the floor.
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
                    rtt_ms=rtt,
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
    expected = _expected_addresses(dst, ipv6)

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
            response = _run(
                argv,
                capture_output=True,
                timeout=wall_timeout,
                # Never hand a subprocess the caller's stdin. `ping` does not
                # read it, but a library that leaks stdin to a child is one
                # implementation change away from mattering -- and the sibling
                # nslookup call proved exactly that.
                stdin=_DEVNULL,
            )
        except (OSError, _SubprocessTimeout):
            # No ping binary, or it hung past the wall clock.
            return PingResult(False, dst, attempts=attempt)
        if response.returncode != 0:
            continue

        text = (response.stdout or b"").decode("utf-8", "replace")

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
            rtt_ms=rtt,
            ttl=reply_ttl,
            src=reply_src,
            attempts=attempt,
        )
    return PingResult(False, dst, attempts=tries)
