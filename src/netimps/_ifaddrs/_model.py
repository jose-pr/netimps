"""``Interface``, the immutable record of one adapter, and the helpers every enumerator shares."""

from __future__ import annotations

from functools import partial as _partial
from types import MappingProxyType as _MappingProxyType
import ipaddress as _ipaddress
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union
from .._mac import MACAddress

_IPInterface = Union[_ipaddress.IPv4Interface, _ipaddress.IPv6Interface]


def _freeze(value: Any) -> Any:
    """``value`` with every list a tuple and every mapping read-only."""
    if isinstance(value, Mapping):
        return _MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    """The inverse of :func:`_freeze` for what pickle can carry: plain dicts."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    return value


def _check_optional(name: str, value: object, kind: type) -> None:
    """``TypeError`` unless ``value`` is ``None`` or exactly of ``kind``'s family.

    A ``bool`` is not accepted where an ``int`` is asked for.
    """
    if value is None:
        return
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise TypeError(
            "%s must be %s or None, not %r"
            % (name, kind.__name__, type(value).__name__)
        )


class Interface:
    """One network interface, normalised to be identical across platforms.

    Attributes:
        name: Human-usable adapter name (``"eth0"``, ``"en0"``, or the Windows
            *friendly* name -- never the raw GUID).
        index: :func:`socket.if_nametoindex` value, or ``0`` when unknown.
        mac: The hardware address, or ``None`` for interfaces without one
            (loopback, tunnels). An all-zero address is normalised to ``None``:
            Linux reports the loopback MAC as ``00:00:00:00:00:00`` where
            macOS and Windows report nothing at all, and ``mac is None`` should
            mean the same thing on every platform.
        ips: Every address bound to the interface, each as an
            ``IPv4Interface``/``IPv6Interface`` carrying its real prefix.
        mtu: Link MTU in bytes, or ``None`` when the platform genuinely could
            not read one. An **unbounded** MTU is not ``None``: the Windows
            loopback adapter reports ULONG max, meaning there is no link to
            constrain it, and that is reported as 65535 -- the largest datagram
            the 16-bit IP total-length field can describe, so a clamp to reality
            rather than an invented figure. Measured: that interface really does
            carry a 65507-octet UDP payload, which is what
            :func:`netimps.max_udp_payload` derives from it, and Linux reports its
            own ``lo`` as 65536 rather than as nothing. This is the **link** MTU;
            for a path see :func:`netimps.discover_mtu`.
        is_up: Whether the interface is usable: ``IFF_UP`` and ``IFF_RUNNING``
            on POSIX, the operational status (``IfOperStatusUp``) on Windows.
            ``None`` when the system did not say. POSIX keeps the addresses of
            an interface that is down, since they are configured and can be
            bound; on Windows an adapter that is down stays listed with its name,
            MAC, index and MTU, and an address the system marks tentative or
            duplicate is left out of ``ips``.
        is_multicast: Whether the interface can carry multicast: ``IFF_MULTICAST``
            on POSIX, and on Windows the absence of the adapter's
            ``IP_ADAPTER_NO_MULTICAST`` flag. The kernel's own answer, never the
            name. ``None`` when the system did not say (the degraded enumeration
            path, hand-built objects, a POSIX platform whose flag value has not
            been measured). Linux reports its loopback interface as not
            multicast-capable and Windows reports its own as capable, so the
            value is a fact about the interface, not about its kind.
        is_point_to_point: Whether the interface joins two endpoints with no
            broadcast domain (a tunnel, a PPP or VPN link): ``IFF_POINTOPOINT``
            on POSIX, a PPP, SLIP or tunnel ``IfType`` on Windows. ``None`` when
            the system did not say, as for ``is_multicast``.
        is_loopback: The kernel's own loopback flag (``IFF_LOOPBACK`` on POSIX,
            ``IF_TYPE_SOFTWARE_LOOPBACK`` on Windows) when the enumeration
            reported one; otherwise derived from the addresses. The constructor
            argument of the same name is ``None`` for "not reported" -- the
            degraded enumeration path, and objects built by hand.
        raw: ``None`` unless enumerated with ``get_interfaces(raw=True)``, in
            which case a **read-only** mapping of platform-specific leftovers,
            with a tuple wherever the system gave a list. **Not portable** and
            explicitly outside the stability guarantee.

    The constructor raises :class:`TypeError` for a field of the wrong type
    (``mac`` must be a :class:`MACAddress`, each of ``ips`` an
    ``IPv4Interface``/``IPv6Interface``).
    """

    __slots__ = (
        "name",
        "index",
        "mac",
        "ips",
        "mtu",
        "is_up",
        "is_multicast",
        "is_point_to_point",
        "_is_loopback",
        "raw",
    )

    name: str
    index: int
    mac: "Optional[MACAddress]"
    ips: "Tuple[_IPInterface, ...]"
    mtu: "Optional[int]"
    is_up: "Optional[bool]"
    is_multicast: "Optional[bool]"
    is_point_to_point: "Optional[bool]"
    _is_loopback: "Optional[bool]"
    raw: "Optional[Mapping[str, Any]]"

    def __init__(
        self,
        name: str,
        index: int = 0,
        *,
        mac: "Optional[MACAddress]" = None,
        ips: "Optional[Iterable[_IPInterface]]" = None,
        mtu: "Optional[int]" = None,
        raw: "Optional[Mapping[str, Any]]" = None,
        is_loopback: "Optional[bool]" = None,
        is_up: "Optional[bool]" = None,
        is_multicast: "Optional[bool]" = None,
        is_point_to_point: "Optional[bool]" = None,
    ) -> None:
        if not isinstance(name, str):
            raise TypeError("name must be str, not %r" % (type(name).__name__,))
        if not isinstance(index, int) or isinstance(index, bool):
            raise TypeError("index must be int, not %r" % (type(index).__name__,))
        _check_optional("mac", mac, MACAddress)
        _check_optional("mtu", mtu, int)
        _check_optional("is_loopback", is_loopback, bool)
        _check_optional("is_up", is_up, bool)
        _check_optional("is_multicast", is_multicast, bool)
        _check_optional("is_point_to_point", is_point_to_point, bool)
        if raw is not None and not isinstance(raw, Mapping):
            raise TypeError(
                "raw must be a mapping or None, not %r" % (type(raw).__name__,)
            )
        if isinstance(ips, (str, bytes)):
            raise TypeError("ips must be an iterable of IPv4Interface/IPv6Interface")
        entries = () if ips is None else tuple(ips)
        for entry in entries:
            if not isinstance(
                entry, (_ipaddress.IPv4Interface, _ipaddress.IPv6Interface)
            ):
                raise TypeError(
                    "ips must hold IPv4Interface/IPv6Interface, not %r"
                    % (type(entry).__name__,)
                )
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "index", index)
        object.__setattr__(self, "mac", mac)
        object.__setattr__(self, "ips", entries)
        object.__setattr__(self, "mtu", mtu)
        object.__setattr__(self, "is_up", is_up)
        object.__setattr__(self, "is_multicast", is_multicast)
        object.__setattr__(self, "is_point_to_point", is_point_to_point)
        object.__setattr__(self, "_is_loopback", is_loopback)
        object.__setattr__(self, "raw", None if raw is None else _freeze(raw))

    def __reduce__(self) -> "Tuple[Any, Tuple[Any, ...]]":
        """Pickle and copy through the constructor.

        ``__slots__`` plus a blocked ``__setattr__`` defeats the default
        restore, which assigns the slots back onto a blank instance.
        """
        return (
            _partial(
                Interface,
                self.name,
                self.index,
                mac=self.mac,
                ips=self.ips,
                mtu=self.mtu,
                raw=None if self.raw is None else _thaw(self.raw),
                is_loopback=self._is_loopback,
                is_up=self.is_up,
                is_multicast=self.is_multicast,
                is_point_to_point=self.is_point_to_point,
            ),
            (),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Interface is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Interface is immutable")

    @property
    def is_loopback(self) -> bool:
        """True when this is the loopback interface.

        The kernel's own answer when there is one: ``IFF_LOOPBACK`` on POSIX,
        ``IF_TYPE_SOFTWARE_LOOPBACK`` on Windows, captured during
        enumeration. Never the name -- ``lo`` (Linux),
        ``lo0`` (macOS) and ``Loopback Pseudo-Interface 1`` (Windows) share no
        common spelling.

        Falls back to the addresses only when the flag was not reported (the
        degraded enumeration path reports no flags, and neither do hand-built
        objects). That fallback requires *a* loopback address and **no routable
        one**, which is a guess rather than an answer: WSL2 binds a routable
        ``10.255.255.254/32`` to ``lo`` on every installation, and binding a
        service address to the loopback interface is the standard
        keepalived/anycast pattern -- on such a host the heuristic reports that
        there is no loopback interface at all. Link-local addresses are ignored
        by it, since macOS's ``lo0`` also carries ``fe80::1/64`` and a
        non-routable address cannot make an interface non-loopback.
        """
        if self._is_loopback is not None:
            return self._is_loopback
        if not self.ips:
            return False
        has_loopback = False
        for entry in self.ips:
            if entry.ip.is_loopback:
                has_loopback = True
            elif not entry.ip.is_link_local:
                return False  # a routable address: not the loopback interface
        return has_loopback

    def primary_ip(
        self, ipv6: bool = False, *, loopback_ok: bool = True
    ) -> "Optional[_IPInterface]":
        """Pick the one entry that best represents this interface, or ``None``.

        Answers "which of this adapter's addresses do I use?" -- the question
        ``IP_MULTICAST_IF``, a bind target and ``ping -S`` all ask::

            iface.primary_ip()               # IPv4Interface('10.0.0.5/24')
            iface.primary_ip().ip            # IPv4Address('10.0.0.5')
            iface.primary_ip(ipv6=True)      # its IPv6 entry instead

        **Ranked, not first-non-loopback: routable, then loopback, then
        link-local**, keeping the OS order within a rank. The rank matters
        because an interface commonly lists a link-local address *before* its
        routable one -- ``fe80::`` is configured first on Linux and macOS NICs
        -- and "the first entry that is not loopback" therefore picked an
        address that is useless as a bind target and unreachable off-link.

        **Loopback outranks link-local deliberately**, which is not the obvious
        order. The only interface that carries both is the loopback adapter, and
        there ``::1`` is the address every caller means; a real NIC has no
        loopback entry, so the rank never takes anything from it. A NIC holding
        *only* a link-local address -- before SLAAC completes, say -- still
        yields it, because there is nothing else to yield. With
        ``loopback_ok=False`` the loopback rank is skipped entirely, so such a
        caller still gets the link-local in preference to ``None``.

        Measured on a macOS loopback adapter, whose entries are
        ``127.0.0.1/8``, ``::1/128``, ``fe80::1/64``: taking the first IPv6
        entry returns ``fe80::1`` for ``ipv6=True`` where ``::1`` is wanted,
        and ``bind(interface=...)`` then fails with "Can't assign requested
        address". Likewise, on a NIC listing ``fe80::`` before a global
        address, first-entry order picks the link-local over the global one.

        Link-local covers ``fe80::/10`` and IPv4 ``169.254.0.0/16``
        (``LINK_LOCAL_V4``): the same problem in the other family, and an
        interface holding both a ``LINK_LOCAL_V4`` address and a DHCP lease
        should answer with the lease.

        Named *primary* rather than *ip* because this is a **selection**, not
        "the" address: an interface routinely has several, and the full lists
        remain on :attr:`ips` / :attr:`ipv4` / :attr:`ipv6`.

        :param ipv6: pick from :attr:`ipv6` rather than :attr:`ipv4`.
        :param loopback_ok: when False, an interface holding only loopback
            addresses yields ``None`` instead -- for callers that need a
            routable address specifically.

        Returns an ``IPv4Interface``/``IPv6Interface``, the **same element type
        as** :attr:`ips` -- one of them, not a different shape. Use ``.ip`` for
        the bare address that socket options take.
        """
        candidates = self.ipv6 if ipv6 else self.ipv4
        if not candidates:
            return None

        # Three ranks rather than a loopback test, and stable within each so the
        # OS order still decides between two equals.
        routable, link_local, loopback = [], [], []
        for entry in candidates:
            if entry.ip.is_loopback:
                loopback.append(entry)
            elif entry.ip.is_link_local:
                link_local.append(entry)
            else:
                routable.append(entry)

        if routable:
            return routable[0]
        if loopback and loopback_ok:
            # Before link-local: the only interface holding both is loopback
            # itself, where `::1` is what every caller means.
            return loopback[0]
        if link_local:
            return link_local[0]
        return None

    @property
    def ipv4(self) -> "Tuple[_ipaddress.IPv4Interface, ...]":
        """Just the IPv4 addresses, as a tuple like :attr:`ips`."""
        return tuple(ip for ip in self.ips if isinstance(ip, _ipaddress.IPv4Interface))

    @property
    def ipv6(self) -> "Tuple[_ipaddress.IPv6Interface, ...]":
        """Just the IPv6 addresses, as a tuple like :attr:`ips`."""
        return tuple(ip for ip in self.ips if isinstance(ip, _ipaddress.IPv6Interface))

    def __repr__(self) -> str:
        """A constructor call that rebuilds an equal value."""
        text = "Interface(name=%r, index=%r, mac=%r, ips=%r, mtu=%r" % (
            self.name,
            self.index,
            self.mac,
            self.ips,
            self.mtu,
        )
        if self.is_up is not None:
            text += ", is_up=%r" % (self.is_up,)
        if self.is_multicast is not None:
            text += ", is_multicast=%r" % (self.is_multicast,)
        if self.is_point_to_point is not None:
            text += ", is_point_to_point=%r" % (self.is_point_to_point,)
        return text + ")"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Interface):
            return NotImplemented
        return (
            self.name == other.name
            and self.index == other.index
            and self.mac == other.mac
            and self.ips == other.ips
            and self.mtu == other.mtu
            and self.is_up == other.is_up
            and self.is_multicast == other.is_multicast
            and self.is_point_to_point == other.is_point_to_point
        )

    def __hash__(self) -> int:
        """Hash the same fields :meth:`__eq__` compares, so equal hashes equal.

        Defining ``__eq__`` without this sets ``__hash__`` to ``None``, which
        made ``set(get_interfaces())`` -- de-duplicating adapters, the obvious
        operation on the package's flagship return value -- raise
        ``TypeError``. :attr:`raw` is left out of both.
        """
        return hash(
            (
                self.name,
                self.index,
                self.mac,
                self.ips,
                self.mtu,
                self.is_up,
                self.is_multicast,
                self.is_point_to_point,
            )
        )


class _Pending:
    """An interface still collecting addresses.

    ``getifaddrs`` reports one list node per address and one for the MAC, so
    the fields arrive piecemeal; an :class:`Interface` cannot change after
    construction, so they are gathered here and built once.
    """

    def __init__(
        self,
        name: str,
        index: int,
        mtu: "Optional[int]",
        is_loopback: bool,
        raw: "Optional[Dict[str, Any]]",
        is_up: "Optional[bool]" = None,
        is_multicast: "Optional[bool]" = None,
        is_point_to_point: "Optional[bool]" = None,
    ) -> None:
        self.name = name
        self.index = index
        self.mtu = mtu
        self.is_loopback = is_loopback
        self.is_up = is_up
        self.is_multicast = is_multicast
        self.is_point_to_point = is_point_to_point
        self.raw = raw
        self.mac: "Optional[MACAddress]" = None
        self.ips: "List[_IPInterface]" = []

    def build(self) -> Interface:
        return Interface(
            name=self.name,
            index=self.index,
            mac=self.mac,
            ips=self.ips,
            mtu=self.mtu,
            raw=self.raw,
            is_loopback=self.is_loopback,
            is_up=self.is_up,
            is_multicast=self.is_multicast,
            is_point_to_point=self.is_point_to_point,
        )


def _make_ip_interface(addr: str, prefix: int) -> "Optional[_IPInterface]":
    """Build an ip_interface, returning None for anything unparseable.

    A malformed entry from the OS must never abort the whole enumeration, so
    every failure mode collapses to ``None`` for the caller to skip.
    """
    try:
        return _ipaddress.ip_interface("%s/%d" % (addr, prefix))
    except ValueError:
        return None


def _mac(octets: bytes) -> "Optional[MACAddress]":
    """Build a MACAddress from raw octets.

    An **all-zero** address is normalised to ``None``: Linux reports the
    loopback MAC as ``00:00:00:00:00:00`` while macOS and Windows report no
    address at all, and ``iface.mac is None`` must mean "no hardware address"
    on every platform rather than growing a per-platform branch in caller code.
    ``MACAddress(b"\\x00" * 6)`` itself stays perfectly valid -- this is a
    normalisation of what the OS reported, not a change to the type.
    """

    if not any(octets):
        return None
    try:
        return MACAddress(octets)
    except (ValueError, TypeError):
        return None
