"""``get_route`` and the ``Route`` it returns."""

from __future__ import annotations

from functools import partial as _partial
import struct as _struct
import sys as _sys
from typing import Any, Optional, Tuple, Union
from .._ifaddrs import _without_zone
from .._ip import Host, HostLike, IPAddress, _dst_argument, format_address
from .._parse import try_parse
from ._connect import _DEFAULT_PROBE, get_source_ip
from ._nexthop import _bsd_next_hop, _posix_next_hop, _windows_next_hop

_IS_WINDOWS = _sys.platform == "win32"
_IS_LINUX = _sys.platform.startswith("linux")


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

    ``on_link`` is three-state deliberately. ``gateway is None`` would turn "we
    never looked" into a confident ``True``: on macOS, where the lookup has no
    source to read, ``get_route('1.1.1.1')`` from a ``192.168.64.3/24`` host
    would report ``on_link=True``. ``None`` is falsy, so ``if route.on_link:``
    takes the safe branch, and ``route.on_link is True`` asks the exact
    question.
    """

    __slots__ = ("dst", "src", "gateway", "interface_index", "_on_link")

    dst: "Union[str, IPAddress]"
    src: "Optional[IPAddress]"
    gateway: "Optional[IPAddress]"
    interface_index: int
    _on_link: "Optional[bool]"

    def __init__(
        self,
        dst: "Union[str, IPAddress]",
        *,
        src: "Optional[IPAddress]" = None,
        gateway: "Optional[IPAddress]" = None,
        interface_index: int = 0,
        on_link: "Optional[bool]" = None,
    ) -> None:
        object.__setattr__(self, "dst", dst)
        object.__setattr__(self, "src", src)
        object.__setattr__(self, "gateway", gateway)
        object.__setattr__(self, "interface_index", interface_index)
        object.__setattr__(self, "_on_link", on_link)

    def __reduce__(self) -> "Tuple[Any, Tuple[Any, ...]]":
        """Pickle and copy through the constructor.

        ``__slots__`` plus a blocked ``__setattr__`` defeats the default
        restore, which assigns the slots back onto a blank instance.
        """
        return (
            _partial(
                Route,
                self.dst,
                src=self.src,
                gateway=self.gateway,
                interface_index=self.interface_index,
                on_link=self._on_link,
            ),
            (),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Route is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Route is immutable")

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
            None if self.dst is None else _dst_argument(self.dst),
            None if self.src is None else format_address(self.src),
            None if self.gateway is None else format_address(self.gateway),
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


def get_route(
    dst: "HostLike" = _DEFAULT_PROBE, *, ipv6: "Optional[bool]" = None
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
    :func:`count_hops` for distance, which does not.

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

    dst = _dst_argument(dst)
    parsed_dest = Host(dst).ip(ipv6=ipv6)

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
