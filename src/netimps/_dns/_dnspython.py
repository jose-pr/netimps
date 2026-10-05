"""``resolve_dnspython``: the ``dnspython`` backend."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Tuple, Type, Union, overload
from .._exceptions import ResolutionError, ResolutionTimeoutError
from .._ip import HostLike, IPv4Address, IPv6Address
from ._common import query_argument
from ._common import (
    _NEEDS_DNS,
    _auto_rdtype,
    _budget,
    _is_doh_server,
    _nameservers,
    _native_record,
    _ns_entries,
)


def has_dns() -> bool:
    """Whether ``dnspython`` is installed, so :func:`resolve_dnspython` can run.

    Without it :func:`resolve` still answers address and reverse records from
    the other backends, and raises :class:`ResolutionError` naming the extra for
    a record type only ``dnspython`` serves.
    """
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        return False
    return True


@overload
def resolve_dnspython(
    query: "HostLike",
    rdtype: "Literal['a', 'A']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[str] = None,
) -> "List[IPv4Address]": ...


@overload
def resolve_dnspython(
    query: "HostLike",
    rdtype: "Literal['aaaa', 'AAAA']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[str] = None,
) -> "List[IPv6Address]": ...


@overload
def resolve_dnspython(
    query: "HostLike",
    rdtype: "Literal['ptr', 'PTR']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[str] = None,
) -> "List[str]": ...


@overload
def resolve_dnspython(
    query: "HostLike",
    rdtype: Optional[str] = None,
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[str] = None,
) -> "List[Any]": ...


def resolve_dnspython(
    query: "HostLike",
    rdtype: Optional[str] = None,
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[str] = None,
) -> "List[Any]":
    """Resolve ``query`` via ``dnspython`` and return the answers as a list.

    ::

        resolve_dnspython("example.com")                    # ['93.184.216.34']
        resolve_dnspython("example.com", "aaaa")
        resolve_dnspython("example.com", "mx", ns="1.1.1.1")
        resolve_dnspython("host")                           # tries the resolv.conf search list
        resolve_dnspython("host", search=["eng.example.com", "example.com"])
        resolve_dnspython("host", search=False)             # look up "host" literally
        resolve_dnspython("8.8.8.8")                        # rdtype=None -> ptr -> ['dns.google']

    Contract: always a ``list``, **empty** when the resolver answered that the
    name or the record does not exist -- never ``None``. Callers can therefore
    write ``if result:`` and index ``result[0]`` safely. A resolver that could
    not be asked is not an empty answer: see below.

    Records come back as **native types**: address records (``A``/``AAAA``) are
    :class:`ipaddress` objects, everything else is a ``str``::

        resolve_dnspython("example.com")[0].is_private   # an IPv4Address, not "1.2.3.4"
        resolve_dnspython("example.com", "mx")           # ['10 mail.example.com']
        resolve_dnspython("example.com", "txt")          # ['v=spf1 -all']  -- unquoted

    Names lose their trailing root dot and TXT strings lose their surrounding
    quotes, since neither is wanted in practice.

    :param query: the name (or address, for a ``"ptr"`` lookup) to look up.
        Also accepts an address object or an :class:`IPv4Interface`/
        :class:`IPv6Interface` (its ``.ip`` is used), not just a string.
    :param rdtype: DNS record type (``"a"``, ``"aaaa"``, ``"mx"`` ...). Second
        because it is the argument callers actually vary. ``None`` (default)
        auto-selects: ``"ptr"`` when ``query`` is an address literal (an
        ``"a"``/``"aaaa"`` lookup *of* an address makes no sense), ``"a"``
        otherwise. Pass an explicit ``rdtype`` to opt out of the
        auto-selection.
    :param ns: optional nameserver, or list of nameservers, to query instead of
        the system resolver. When omitted, the system resolver configuration
        (``/etc/resolv.conf``, or the Windows equivalent) supplies both the
        nameservers and, if ``search`` is enabled, the search list.
    :param timeout: seconds to spend on the whole resolution, retries included
        (``None`` for dnspython's default). Bounds *total* time, not each query
        -- a list of unreachable nameservers cannot stretch past it.
    :param port: nameserver port, for resolvers not on 53.
    :param tcp: query over TCP instead of UDP. Useful for large responses that
        would otherwise be truncated.
    :param search: how to expand an unqualified ``query``, the way ``ping`` or
        a browser would. ``True`` (default) tries the system resolver's own
        search list (the ``search``/``domain`` directive in ``resolv.conf``,
        or the Windows per-adapter DNS suffix list) -- the same source ``ns``
        draws its nameservers from when ``ns`` is omitted. ``False`` looks up
        ``query`` as-is only, no expansion. A list of domain names tries
        exactly those suffixes instead of the system list, regardless of
        ``ns``. Ignored for an already-qualified (trailing-dot) ``query``.
    :param source: the local address the queries are sent from (``None``:
        whatever the OS picks).

    NXDOMAIN and "no answer" yield ``[]``. A timeout raises
    :class:`ResolutionTimeoutError`; every server failing, or no resolver
    configuration to read, raises :class:`ResolutionError`. A malformed query
    or unknown record type raises :class:`ValueError`, since that is a caller
    bug rather than a DNS result.

    Needs the ``dns`` extra (``pip install "netimps[dns]"``); without it this
    raises :class:`ResolutionError` saying so. :func:`has_dns` tells which.
    """
    query = query_argument(query)
    if not rdtype:
        rdtype = _auto_rdtype(query)
    rdtype = rdtype.lower()

    try:
        from dns import exception as _dnsexc
        from dns import name as _name
        from dns import resolver as _resolver
    except ImportError as exc:
        raise ResolutionError(_NEEDS_DNS) from exc

    # Looked up by name rather than referenced directly: LifetimeTimeout only
    # exists in dnspython >= 2.0, and the set has shifted between releases, so
    # a hard reference would break on older versions. Anything missing simply
    # drops out of the tuple.
    def _classes(*names: str) -> "Tuple[Type[Exception], ...]":
        found = (getattr(_resolver, name, None) for name in names)
        return tuple(
            cls for cls in found if isinstance(cls, type) and issubclass(cls, Exception)
        )

    # Only when asked: the keyword is not in every dnspython release.
    extra: "Dict[str, Any]" = {"source": source} if source else {}
    # Parsed before the resolver exists: a malformed spelling is the caller's
    # mistake, whatever the install.
    entries = _ns_entries(ns)
    doh = [entry for entry in entries if _is_doh_server(entry)]
    servers = _nameservers([e for e in entries if e not in doh], port)
    try:
        r = _resolver.Resolver(configure=not (servers or doh))
        if servers or doh:
            _set_nameservers(r, servers, doh)
        elif port != 53:
            r.port = port
        search_domains = None
        if isinstance(search, (list, tuple)):
            search_domains = list(search)
            search = True
        if search_domains is not None:
            # An explicit domain list replaces the system search list
            # outright, regardless of where the nameservers came from.
            r.search = [_name.from_text(d) for d in search_domains]
        timeout = _budget(timeout)
        if timeout is not None:
            # `timeout` bounds a single query; `lifetime` bounds the whole
            # resolution including retries against every nameserver. Without
            # the lifetime, a list of dead servers blocks far longer than asked.
            r.timeout = timeout
            r.lifetime = timeout
        if rdtype == "ptr":
            # resolve_address builds the reverse (in-addr.arpa/ip6.arpa) name
            # from a plain address itself -- r.resolve(query, "ptr") would
            # require the caller to already have that name, which defeats
            # the point of accepting a literal address as `query`.
            answer = r.resolve_address(query, tcp=tcp, search=search, **extra)
        else:
            answer = r.resolve(query, rdtype, tcp=tcp, search=search, **extra)
    except ResolutionError:
        raise  # the deadline ending the resolution, not a socket failure
    except _classes("NXDOMAIN", "NoAnswer"):
        return []  # the resolver answered: there is no such record
    except _classes("LifetimeTimeout", "Timeout") as exc:
        raise ResolutionTimeoutError(
            "dnspython timed out asking about %r: %s" % (query, exc)
        ) from exc
    except _classes("NoNameservers", "NoResolverConfiguration") as exc:
        raise ResolutionError(
            "dnspython could not ask about %r: %s" % (query, exc)
        ) from exc
    except _dnsexc.DNSException as exc:
        # A malformed name or an unknown record type is the caller's mistake,
        # not a lookup outcome.
        raise ValueError(
            "invalid DNS query %r (%s): %s" % (query, rdtype, exc)
        ) from exc
    except OSError as exc:
        raise ResolutionError(
            "dnspython could not ask about %r: %s" % (query, exc)
        ) from exc
    return [_native_record(record) for record in answer]


def _set_nameservers(
    resolver: "Any", servers: "List[Tuple[str, int]]", doh: "List[str]"
) -> None:
    """Give dnspython ``servers`` with a port each, then the ``https://`` ones.

    The resolver's per-address port table does it in every release, and is
    keyed by address; the same address on two ports needs ``Do53Nameserver``
    (dnspython 2.4 on).
    """
    ports = dict(servers)
    if len(ports) == len(set(servers)):
        resolver.nameserver_ports = ports
        resolver.nameservers = [host for host, _ in servers] + doh
        return
    from dns.nameserver import Do53Nameserver

    resolver.nameservers = [Do53Nameserver(host, port) for host, port in servers] + doh
