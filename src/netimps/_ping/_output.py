"""Reading a ping reply: round-trip time, TTL and the address that answered."""

from __future__ import annotations

import re as _re
from typing import List, Optional, Tuple
from .._ip import IPAddress

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

    BSD uses a **comma**, which a colon-only needle never matches, so a healthy
    v6 reply there would verify as falsy.

    The lookbehind stops an address matching inside a longer one -- ``::1`` must
    not be found inside ``2001:db8::1`` -- which matters because the whole point
    of this check is proving *which* host answered.
    """
    return _re.compile(r"(?<![0-9A-Fa-f:.])" + _re.escape(str(address)) + r"[:,]")


def _parse_ping_output(
    text: str, expected: "List[IPAddress]"
) -> "Tuple[Optional[float], Optional[int], Optional[IPAddress]]":
    """Pull (rtt in seconds, ttl, src) out of ping's stdout.

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
                # "time<1ms" is an upper bound, not a measurement: report 0.0.
                # The binary prints milliseconds; this is the one conversion.
                rtt = 0.0 if operator == "<" else float(value) / 1000.0
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
