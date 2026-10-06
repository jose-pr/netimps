"""``Host``, a hostname or an address, and the loose host value every ``dst`` takes."""

from __future__ import annotations

import platform as _platform
import socket as _socket
from typing import Any, List, Literal, Optional, Tuple, Type, TypeVar, Union, overload
from .._exceptions import NetimpsValueError, ResolutionError
from .._fqdn import FQDN
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from ._types import IPAddress, ip_literal

_D = TypeVar("_D")


_H = TypeVar("_H", bound="Host")


def _dst_argument(value) -> str:
    """Coerce a destination-like value to the plain string a socket or
    subprocess call expects.

    An :class:`IPv4Interface`/:class:`IPv6Interface` unwraps to its
    ``.ip`` -- the ``/prefix`` means nothing to ``ping``/``getaddrinfo``, and
    stringifying the interface directly would pass ``"10.0.0.5/24"`` as the
    destination, which every caller of this (a subprocess argument, a
    socket call, a DNS query) reads as garbage rather than an address.

    An :class:`IPv4Network`/:class:`IPv6Network` has no single address, so it
    raises :class:`TypeError` rather than silently picking one (the network
    address? the first host address?) -- a caller who meant a specific
    address should say so.

    A string, an :class:`IPv4Address`/:class:`IPv6Address`, a :class:`Host` and
    an :class:`FQDN` stand for the text they hold. **Anything else raises
    :class:`TypeError`**, through the same allowlist as :func:`split_host`: a
    ``str()`` fallback read ``None`` as the host named ``"None"``, an answer
    that looks right and is not.
    """
    if isinstance(value, (IPv4Network, IPv6Network)):
        raise TypeError(
            "expected a single destination, not a network (%r) -- "
            "pass an address from it instead" % (value,)
        )
    if isinstance(value, (IPv4Interface, IPv6Interface)):
        return str(value.ip)
    if isinstance(value, (IPv4Address, IPv6Address)):
        return str(value)
    return _host_text(value)


def _host_text(text: object) -> str:
    """The string a loose host value stands for.

    :raises TypeError: for a network (it names no single host) and for a value
        that is not a host type at all.
    """
    if isinstance(text, str):
        return text
    if isinstance(text, (IPv4Network, IPv6Network)):
        _dst_argument(text)  # raises TypeError, with the reason
    if isinstance(text, (IPv4Address, IPv6Address, IPv4Interface, IPv6Interface)):
        return _dst_argument(text)
    if isinstance(text, (Host, FQDN)):
        # Both stringify to the text the caller means -- `Host` to its
        # original spelling, `FQDN` to the name with its trailing dot if it
        # has one.
        return str(text)
    # An **allowlist**, not a `str()` fallback: a fallback turns `None` into
    # the hostname "None", a plausible answer that is wrong and that a caller
    # cannot detect.
    raise TypeError(
        "host must be a string, an address, a Host or an FQDN, not %r"
        % (type(text).__name__,)
    )


class Host:
    """A host named by either an address or a hostname.

    Config files and URLs hold "the host" as a string that may be either, and
    the useful operations differ. This keeps the original text and resolves on
    demand::

        host = Host("db.internal")
        host.ip()                  # IPv4Address(...) once DNS answers
        str(host)                  # 'db.internal' -- always the original

        Host("10.0.0.5").is_address    # True, no DNS involved

    The point is that ``str(host)`` is **always what was given**, so a URL can
    still be rebuilt when resolution fails -- the case a bare lookup handles
    badly, since it returns ``None`` and loses the name.
    """

    __slots__ = ("value", "_resolved", "_attempted")

    value: str
    _resolved: "Optional[IPAddress]"
    _attempted: bool

    def __init__(self, value: "Optional[HostLike]") -> None:
        if isinstance(value, Host):
            value = value.value
        elif value is not None:
            # An interface is its address and a network is no host, as for
            # every `dst` parameter.
            value = _dst_argument(value)
        object.__setattr__(self, "value", "" if value is None else str(value).strip())
        object.__setattr__(self, "_resolved", None)
        object.__setattr__(self, "_attempted", False)

    def __reduce__(self) -> "Tuple[Any, Tuple[str]]":
        """Pickle and copy through the constructor; the memo is not carried.

        ``__slots__`` plus a blocked ``__setattr__`` defeats the default
        restore, which assigns the slots back onto a blank instance.
        """
        return (type(self), (self.value,))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Host is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Host is immutable")

    @classmethod
    def parse(cls: "Type[_H]", text: str) -> "_H":
        """Build a ``Host`` from text naming an address or a hostname.

        A ``Host`` keeps what it was given, so no spelling is rejected for its
        form; text with nothing in it is, since there is no host to name.
        The constructor is the lenient entry that takes ``None`` and ``""``.

        :raises NetimpsValueError: for empty or blank text. It is a
            ``ValueError``.
        :raises TypeError: for anything that is not ``str``.
        """
        if not isinstance(text, str):
            raise TypeError("Host.parse takes text, not %r" % (type(text).__name__,))
        if not text.strip():
            raise NetimpsValueError("a host cannot be empty")
        return cls(text)

    @overload
    @classmethod
    def try_parse(cls: "Type[_H]", text: str) -> "Optional[_H]": ...

    @overload
    @classmethod
    def try_parse(cls: "Type[_H]", text: str, default: _D) -> "Union[_H, _D]": ...

    @classmethod
    def try_parse(cls, text: str, default: Any = None) -> Any:
        """Return ``parse(text)``, or ``default`` for empty or blank text.

        :raises TypeError: for anything that is not ``str``; only bad *text*
            is answered with ``default``. :func:`netimps.try_parse` is the
            entry that answers ``default`` for any object.
        """
        if not isinstance(text, str):
            raise TypeError(
                "Host.try_parse takes text, not %r" % (type(text).__name__,)
            )
        if not text.strip():
            return default
        return cls(text)

    @property
    def is_address(self) -> bool:
        """True if the value is already an IP literal -- no DNS needed."""
        return ip_literal(self.value) is not None

    @overload
    def fqdn(
        self,
        *,
        check: Literal[True],
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "FQDN": ...

    @overload
    def fqdn(
        self,
        *,
        check: Literal[False] = False,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Optional[FQDN]": ...

    @overload
    def fqdn(
        self,
        *,
        check: bool,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Optional[FQDN]": ...

    def fqdn(
        self,
        *,
        check: bool = False,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Optional[FQDN]":
        """This host as an :class:`FQDN`: the name itself, or the name an address
        reverses to.

        **A name is returned as written, with no lookup**; an address costs a
        reverse (PTR) lookup, which can block::

            Host("www.example.com").fqdn().domain   # FQDN('example.com'), no I/O
            Host("10.0.0.5").fqdn()                 # FQDN('db.internal'), or None

        The bridge between the two types: :class:`Host` is "an address *or* a
        name", while :class:`FQDN` is a name algebra that refuses an address.
        The name is the one written, **not** the canonical name after
        search-list expansion, and a reverse answer comes back without its root
        dot.

        ``None`` is the answer when nothing was found, and also for text that is
        not a syntactically possible name (over-long, an empty inner label).
        With ``check=True`` the first raises :class:`ResolutionError` and the
        second :class:`NetimpsValueError`.

        The resolver options mean what they do for :meth:`ip`. There is no
        ``ipv6``: the address decides which reverse zone is asked. Nothing is
        memoised.
        """
        text = self.value
        if self.is_address:
            from .._dns import lookup_fqdn, resolver_keywords

            return lookup_fqdn(text, **resolver_keywords(locals()))
        return FQDN.parse(text) if check else FQDN.try_parse(text)

    @overload
    def ip(
        self,
        *,
        check: Literal[True],
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
        refresh: bool = False,
    ) -> "IPAddress": ...

    @overload
    def ip(
        self,
        *,
        check: Literal[False] = False,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
        refresh: bool = False,
    ) -> "Optional[IPAddress]": ...

    @overload
    def ip(
        self,
        *,
        check: bool,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
        refresh: bool = False,
    ) -> "Optional[IPAddress]": ...

    def ip(
        self,
        *,
        check: bool = False,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
        refresh: bool = False,
    ) -> "Optional[IPAddress]":
        """Resolve to an address, or ``None``.

        **A literal is returned as parsed, with no lookup**; a name is looked
        up, which can block.

        :param check: raise :class:`ResolutionError` instead of returning
            ``None`` when nothing was found -- an empty answer, an outage, or an
            empty host.
        :param ipv6: ``True`` asks for AAAA, ``False`` for A, ``None`` for either
            in one lookup, in the order the OS chose.
        :param ns: nameserver(s) to ask instead of the OS's.
        :param timeout: seconds per backend attempt; what it bounds differs by
            backend, see :func:`netimps.resolve`.
        :param deadline: seconds for the whole lookup, every backend and
            candidate included; ``None`` sets no overall limit.
        :param port: nameserver port.
        :param tcp: query over TCP.
        :param search: expand an unqualified name through a search list: the
            system's (``True``), none (``False``) or the list given.
        :param backends: which of ``"dnspython"``, ``"wire"``, ``"system"``,
            ``"nslookup"``, and in what order; see :func:`netimps.resolve`.
        :param source: the local address the query is sent from.
        :param cache: reuse a recent answer, a miss included, from the shared
            resolution cache: ``False`` (the default) never reads or writes it,
            ``True`` keeps an answer for :data:`RESOLUTION_CACHE_TTL` seconds, a
            number is that many. Unlike the memo below it is shared by every
            :class:`Host` and :class:`FQDN`, and is keyed on the name and every
            option; see :func:`netimps.resolve`.
        :param refresh: ask again, and replace the memo with the new answer --
            a name that failed once may resolve later.

        **With none of ``ns``, ``port``, ``tcp``, ``source`` or ``backends`` the
        OS resolver alone answers**, as the standard library's lookups do. A
        missed name then costs milliseconds, where the full chain behind
        :func:`netimps.resolve` costs seconds. Naming any of them hands the
        choice to that chain.

        **A call that passes no option memoises its answer, a miss included**,
        because the common use is several lookups in a row on the same object.
        A call that passes any option, ``cache=`` included, neither reads nor
        writes the memo.
        """
        text = self.value
        if not text:
            if check:
                raise ResolutionError("there is no host to resolve")
            return None

        literal = ip_literal(text)
        if literal is not None:
            return literal

        plain = not (
            check
            or ipv6 is not None
            or ns
            or timeout != 5.0
            or port != 53
            or tcp
            or search is not True
            or backends is not None
            or source
            or cache is not False
            or deadline is not None
        )
        if plain and self._attempted and not refresh:
            return self._resolved

        from .._dns import lookup_ip, resolver_keywords

        found = lookup_ip(text, **resolver_keywords(locals(), ipv6=True))
        if plain:
            object.__setattr__(self, "_attempted", True)
            object.__setattr__(self, "_resolved", found)
        return found

    @overload
    def resolve(
        self,
        *,
        check: Literal[True],
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Tuple[FQDN, IPAddress]": ...

    @overload
    def resolve(
        self,
        *,
        check: Literal[False] = False,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Tuple[Optional[FQDN], Optional[IPAddress]]": ...

    @overload
    def resolve(
        self,
        *,
        check: bool,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Tuple[Optional[FQDN], Optional[IPAddress]]": ...

    def resolve(
        self,
        *,
        check: bool = False,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Tuple[Optional[FQDN], Optional[IPAddress]]":
        """The pair ``(fqdn, ip)``; whichever half was not found is ``None``.

        =====================  =================================  ==================
        host is                ``fqdn``                           ``ip``
        =====================  =================================  ==================
        a name                 the name as written                forward lookup
        an address             reverse lookup                     the literal
        =====================  =================================  ==================

        The result is always a pair, so ``fqdn, ip = host.resolve()`` never
        fails to unpack. With ``check=True`` a half that could not be found
        raises :class:`ResolutionError` instead. The options are
        :meth:`ip`'s, and a name does its one lookup only.
        """
        from .._dns import resolver_keywords

        keywords = resolver_keywords(locals())
        return (self.fqdn(**keywords), self.ip(ipv6=ipv6, **keywords))

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return "Host(%r)" % (self.value,)

    def __bool__(self) -> bool:
        return bool(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Host):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)


#: Anything accepted where a single destination (hostname or address) is
#: expected -- ``ping``, ``tcp_check``, ``resolve``'s ``query`` and the like.
#: Not a ``parse()`` target: this is argument coercion, not type-building.
HostLike = Union[
    str,
    IPv4Address,
    IPv6Address,
    IPv4Interface,
    IPv6Interface,
    Host,
    FQDN,
]


def get_hostname(*, fqdn: bool = False) -> str:
    """This machine's host name, asked for when called.

    :func:`platform.node` by default. With ``fqdn=True``,
    :func:`socket.getfqdn`, which **may consult the resolver** and so can
    block; where no qualified name is known it returns the bare one.

    Nothing is read at import: on Windows :func:`platform.node` is a WMI
    query, which is too much to charge every ``import netimps``.
    """
    if fqdn:
        return _socket.getfqdn()
    return _platform.node()
