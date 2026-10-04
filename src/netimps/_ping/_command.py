"""The argv of one ICMP probe for each ping grammar (Windows, Linux, BSD), and what each can express."""

from __future__ import annotations

import math as _math
import os as _os
import sys as _sys
from typing import List, Optional, Tuple
from .._ip import HostLike, IPAddress, _dst_argument
from .._parse import try_parse as _try_parse

#: Which ``ping`` grammar this host speaks. **Three values, not two.**
#:
#: An ``os.name == "nt"`` split would treat every POSIX platform as Linux, and
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

    literal = _try_parse(dst)
    if literal is not None:
        return literal.version == 6
    if resolved:
        return resolved[0].version == 6
    return False


def supports_dont_fragment(
    dst: "HostLike" = "",
    ipv6: "Optional[bool]" = None,
    resolved: "Optional[List[IPAddress]]" = None,
) -> bool:
    """Whether DF can actually be set for this destination on this host.

    Exists so :func:`netimps.discover_mtu` can decline to answer rather than
    return a number it cannot stand behind: without DF the local stack
    fragments an oversized probe, the peer reassembles it and replies, every
    size "survives", and the binary search returns its own ceiling.

    BSD's ``ping`` has a DF flag, ``-D``. Its ``ping6`` is the one case with no
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
        # -W here is MILLISECONDS, not seconds: the Linux value would give
        # macOS a 1ms deadline and make `timeout=` inert.
        options = ["-c", "1", "-W", str(max(1, int(_math.ceil(timeout * 1000)))), "-n"]
        if ttl is not None:
            options.extend(["-m", str(ttl)])
        if dont_fragment:
            options.append("-D")
    if source is not None:
        # -S on both. -I exists but is multicast-only and is *rejected* for a
        # unicast destination, which would make every src= ping falsy here.
        options.extend(["-S", source])
    if size is not None:
        options.extend(["-s", str(size)])
    return ["ping6" if use_six else "ping", *options, dst], use_six
