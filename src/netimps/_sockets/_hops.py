"""``count_hops``: raw ICMP where permitted, the system traceroute otherwise."""

from __future__ import annotations

import socket as _socket
import sys as _sys
import time as _time
from typing import Optional
from .. import _proc
from .._ip import HostLike, _dst_argument
from ._connect import _resolve_targets, get_source_ip

_IS_WINDOWS = _sys.platform == "win32"
_IS_LINUX = _sys.platform.startswith("linux")


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
        result = _proc.run(cmd[0], cmd[1:], timeout=budget)
    except (OSError, ValueError):
        return None
    if result.returncode != 0:
        # A usage error or a failure to start a trace: its output is not a trace.
        return None

    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields or not fields[0].isdigit():
            continue
        # The destination answering this hop is the answer, whatever the
        # latency columns look like.
        if any(field.strip("[]") == target for field in fields[1:]):
            return int(fields[0])
    return None


def count_hops(
    dst: "HostLike",
    *,
    max_hops: int = 30,
    timeout: float = 1.0,
    allow_traceroute: bool = True,
    ipv6: "Optional[bool]" = None,
) -> Optional[int]:
    """Return the number of hops to ``dst``, or ``None`` if it never answers.

    Sends TTL-limited probes and counts the routers that reply, the same
    technique ``traceroute`` uses::

        count_hops("8.8.8.8")     # 12

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
        the platform's v6 traceroute. ``gethostbyname`` is IPv4-only: through
        it a v6 destination would return ``None``, read as "never answered"
        rather than "never asked".

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
            "count_hops needs a raw socket (root/Administrator); "
            "leave allow_traceroute=True to use the system traceroute, or use "
            "get_route() for the first hop"
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
