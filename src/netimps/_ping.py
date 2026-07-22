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
from subprocess import TimeoutExpired as _SubprocessTimeout
from subprocess import run as _run
from typing import Optional

__all__ = ["ping", "PingResult"]


def _source_argument(source, want_ipv6: bool = False) -> Optional[str]:
    """Coerce a source spec to the address string ``ping`` needs.

    Accepts an :class:`Interface`, an address object, or a string. Interfaces
    are reduced to an address because Windows ``-S`` will not take an adapter
    name; ``None`` means "nothing usable here", which the caller must treat as
    a failure rather than silently omitting the flag.
    """
    # A MAC identifies an adapter, so look up which one carries it. Unknown
    # MACs are None ("no such interface"), never a silent fallback.
    from . import MACAddress, is_valid_mac
    from ._ifaddrs import Interface, get_interfaces

    if isinstance(source, MACAddress) or (
        isinstance(source, str) and is_valid_mac(source)
    ):
        wanted = MACAddress(source)
        source = next(
            (iface for iface in get_interfaces() if iface.mac == wanted), None
        )
        if source is None:
            return None

    if isinstance(source, Interface):
        candidates = source.ipv6 if want_ipv6 else source.ipv4
        for entry in candidates:
            if not entry.ip.is_loopback:
                return str(entry.ip)
        # Fall back to a loopback address if that is genuinely all it has.
        return str(candidates[0].ip) if candidates else None

    text = str(source).strip()
    return text or None


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
        source: address that answered, which on success is the destination.
        attempts: how many probes were sent before this outcome.
    """

    __slots__ = ("ok", "host", "rtt_ms", "ttl", "source", "attempts")

    def __init__(self, ok, host, rtt_ms=None, ttl=None, source=None, attempts=1):
        self.ok = ok
        self.host = host
        self.rtt_ms = rtt_ms
        self.ttl = ttl
        self.source = source
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


#: ``time=5ms`` / ``time<1ms`` / ``time=0.043 ms`` across platforms.
_PING_RTT = _re.compile(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", _re.IGNORECASE)
#: ``TTL=119`` (Windows) / ``ttl=54`` (POSIX).
_PING_TTL = _re.compile(r"ttl[=\s]\s*([0-9]+)", _re.IGNORECASE)


def _parse_ping_output(text: str, expect):
    """Pull (rtt_ms, ttl, source) out of ping's stdout.

    Reads only numeric tokens that are stable across platforms and locales;
    the surrounding prose is never matched.
    """
    rtt = ttl = source = None
    for line in text.splitlines():
        lowered = line.lower()
        if "expired" in lowered or "unreachable" in lowered:
            continue
        found_rtt = _PING_RTT.search(line)
        found_ttl = _PING_TTL.search(line)
        if found_rtt is None and found_ttl is None:
            continue
        if found_rtt is not None and rtt is None:
            try:
                rtt = float(found_rtt.group(1))
            except ValueError:
                pass
        if found_ttl is not None and ttl is None:
            try:
                ttl = int(found_ttl.group(1))
            except ValueError:
                pass
        if source is None and expect is not None and str(expect) in line:
            source = expect
        break
    return rtt, ttl, source


def ping(
    hostname: str,
    tries: int = 1,
    timeout: float = 1.0,
    ipv6: Optional[bool] = None,
    source: Optional[str] = None,
    size: Optional[int] = None,
    ttl: Optional[int] = None,
    dont_fragment: bool = False,
) -> "PingResult":
    """Ping ``hostname``; the result is truthy if it answered.

    Returns a :class:`PingResult` rather than a bare bool, so the reply details
    are available without re-running and re-parsing ``ping``::

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

    :param tries: attempts before giving up. Values below 1 are treated as 1.
    :param timeout: seconds to wait per attempt. POSIX ``ping`` only accepts a
        whole number of seconds, so sub-second values are rounded **up** to 1 --
        never down to 0, which some implementations read as "wait forever".
    :param ipv6: force the IPv6 (``-6``) or IPv4 (``-4``) binary. ``None``
        (default) lets the system resolver decide.
    :param source: send from this local address, choosing which interface the
        echo leaves by. Accepts an :class:`Interface`, an address object, or a
        string::

            ping("8.8.8.8", source=get_source_ip())            # address object
            ping("8.8.8.8", source=get_interfaces()[0])        # Interface
            ping("8.8.8.8", source="192.0.2.10")               # literal
            ping("8.8.8.8", source=MACAddress("00:00:5e:00:53:01"))  # by MAC

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
    :param size: ICMP payload bytes (Windows ``-l``, POSIX ``-s``). The wire
        packet is 28 bytes larger (20 IP + 8 ICMP header), which matters when
        sizing against an MTU: payload 1472 is exactly 1500 on the wire.
    :param ttl: initial hop limit (``-i`` on Windows, ``-t`` on POSIX -- the
        letters are **swapped** between platforms, a classic source of scripts
        that silently do the wrong thing).

        A ``ttl`` too small to reach the target yields ``False`` on every
        platform. That takes explicit work on Windows, whose ``ping`` exits
        ``0`` for "TTL expired in transit" -- counting a router's error as a
        received reply -- so the raw exit code would report success although
        the target was never reached. The reply address is verified instead
        (see below), which is locale-independent.
    :param dont_fragment: set the DF bit (Windows ``-f``, Linux ``-M do``).
        Combined with ``size``, the standard manual MTU probe: the largest
        ``size`` that still succeeds is the path MTU minus 28. Unsupported on
        macOS/BSD ping, where it is ignored.

    An empty ``hostname`` gives a falsy result. Never raises: a missing ``ping``
    binary or a non-zero exit both yield a falsy :class:`PingResult`.

    .. note::
       This measures whether *ICMP echo* is answered, which is not the same as
       whether a host is up -- plenty of hosts and most cloud firewalls drop
       echo requests while serving traffic normally. Prefer a TCP connect to
       the port you actually care about when you can.
    """
    if not hostname:
        return PingResult(False, hostname, attempts=0)

    tries = max(1, tries)
    if _os.name == "nt":
        # Windows takes milliseconds and counts with -n.
        options = ["-n", "1", "-w", str(max(1, int(timeout * 1000)))]
    else:
        # POSIX -W is whole seconds; round up so a sub-second timeout never
        # becomes 0 (read as "no timeout" by some implementations).
        options = ["-c", "1", "-W", str(max(1, int(_math.ceil(timeout)))), "-n"]

    if ipv6 is True:
        options.append("-6")
    elif ipv6 is False:
        options.append("-4")

    if source is not None:
        resolved_source = _source_argument(source, want_ipv6=bool(ipv6))
        if resolved_source is None:
            # An interface with no usable address cannot be a source.
            return PingResult(False, hostname, attempts=0)
        # Windows spells it -S <addr>; POSIX uses -I <addr-or-ifname>.
        options.extend(["-S" if _os.name == "nt" else "-I", resolved_source])

    if size is not None:
        if size < 0:
            raise ValueError("size must be non-negative, got %r" % (size,))
        options.extend(["-l" if _os.name == "nt" else "-s", str(size)])

    if ttl is not None:
        if not 1 <= ttl <= 255:
            raise ValueError("ttl must be 1-255, got %r" % (ttl,))
        # -i on Windows is TTL; on POSIX -i is the *interval* and -t is TTL.
        options.extend(["-i" if _os.name == "nt" else "-t", str(ttl)])

    if dont_fragment:
        if _os.name == "nt":
            options.append("-f")
        elif _sys.platform.startswith("linux"):
            options.extend(["-M", "do"])
        # macOS/BSD ping has no portable DF flag; silently omitted.

    # A hard cap on the subprocess itself: -W bounds how long ping waits for a
    # reply, but not how long name resolution can hang beforehand.
    wall_timeout = max(timeout, 1.0) + 5.0

    # Windows exits 0 for "TTL expired in transit", so a zero exit alone does
    # not mean the target answered. Confirm the reply came from the target
    # itself by matching its address in the output -- an address comparison,
    # never the localised prose around it.
    from . import try_parse as _try_parse

    expect_address = _try_parse(hostname)
    if expect_address is None:
        try:
            expect_address = _try_parse(_socket.gethostbyname(hostname))
        except OSError:
            expect_address = None

    for attempt in range(1, tries + 1):
        try:
            response = _run(
                ["ping", *options, hostname],
                capture_output=True,
                timeout=wall_timeout,
            )
        except (OSError, _SubprocessTimeout):
            # No ping binary, or it hung past the wall clock.
            return PingResult(False, hostname, attempts=attempt)
        if response.returncode != 0:
            continue

        text = (response.stdout or b"").decode("utf-8", "replace")

        # A zero exit is not proof the *target* answered: Windows also exits 0
        # for "TTL expired in transit", where a router replied instead. Confirm
        # by address, which is locale-independent -- but only when the target's
        # address is known, since a bare exit code is all we have otherwise.
        if expect_address is not None:
            needle = "%s:" % expect_address
            answered = False
            for line in text.splitlines():
                if needle not in line:
                    continue
                lowered = line.lower()
                if "expired" in lowered or "unreachable" in lowered:
                    continue  # a router's error, not the destination
                if "bytes=" in lowered or "time" in lowered or "ttl=" in lowered:
                    answered = True
                    break
            if not answered:
                continue

        rtt, reply_ttl, source = _parse_ping_output(text, expect_address)
        return PingResult(
            True,
            hostname,
            rtt_ms=rtt,
            ttl=reply_ttl,
            source=source if source is not None else expect_address,
            attempts=attempt,
        )
    return PingResult(False, hostname, attempts=tries)
