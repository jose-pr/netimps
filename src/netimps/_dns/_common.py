"""Pieces every backend shares: the deadline, record-type helpers, nameserver spellings and the search list."""

from __future__ import annotations

import contextvars as _contextvars
import ipaddress as _ipaddress
import socket as _socket
import time as _time
from typing import List, Optional, Tuple, Union
from .._exceptions import NetimpsValueError, ResolutionTimeoutError
from .._parse import try_parse

_ADDRESS_RDTYPES = ("a", "aaaa")


#: The monotonic time at which the enclosing :func:`resolve` call must be done,
#: or ``None``. Every blocking step reads it through :func:`_budget`, so one
#: ``deadline=`` bounds the chain, a record-type pair and a search list alike
#: without each backend growing a parameter. Context-local, so concurrent
#: resolutions on other threads or tasks have their own.
_DEADLINE: "_contextvars.ContextVar[Optional[float]]" = _contextvars.ContextVar(
    "netimps_resolution_deadline", default=None
)


def _budget(timeout: "Optional[float]") -> "Optional[float]":
    """``timeout`` capped at the time left before the enclosing deadline.

    :class:`ResolutionTimeoutError` once the deadline has passed. With no
    deadline set it is ``timeout`` unchanged, ``None`` included.
    """
    end = _DEADLINE.get()
    if end is None:
        return timeout
    left = end - _time.monotonic()
    if left <= 0:
        raise ResolutionTimeoutError("the resolution deadline has passed")
    return left if timeout is None else min(timeout, left)


def _native_record(record):
    """Convert a dnspython record to a native Python value.

    Address records become :mod:`ipaddress` objects, so a caller can compare
    and do membership tests without re-parsing. Everything else stays a
    ``str``, with the trailing root dot stripped from names and the quotes
    stripped from TXT strings -- the forms callers actually want.
    """
    text = str(record)

    address = try_parse(text)
    if address is not None:
        return address
    if len(text) > 1 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]  # TXT records arrive quoted
    if text.endswith(".") and not text.endswith(".."):
        return text[:-1]  # names are fully qualified with a root dot
    return text


def _auto_rdtype(query: str) -> str:
    """The record type ``rdtype=None`` implies for ``query``.

    An address literal (v4 or v6) means the caller wants the reverse name --
    an ``"a"``/``"aaaa"`` lookup *of* an address is nonsensical, so ``"ptr"``
    is the only reading that makes the request meaningful. Anything else is
    treated as a hostname, defaulting to ``"a"``. Only consulted when
    ``rdtype`` is not given explicitly --
    an explicit ``rdtype="a"`` on an address still attempts a literal (and
    empty) A lookup rather than being silently overridden.
    """

    return "ptr" if try_parse(query) is not None else "a"


_NEEDS_DNS = 'the dnspython backend needs the "dns" extra: pip install "netimps[dns]"'


def _family_of(rdtype: str) -> int:
    return _socket.AF_INET6 if rdtype.lower() == "aaaa" else _socket.AF_INET


def _address_rdtypes(rdtype: "Union[Tuple[str, ...], List[str]]") -> "Tuple[str, ...]":
    """``rdtype`` as a tuple of lower-case address types, or ``ValueError``."""
    types = tuple(str(item).lower() for item in rdtype)
    if (
        not types
        or len(set(types)) != len(types)
        or any(item not in _ADDRESS_RDTYPES for item in types)
    ):
        raise ValueError(
            "a tuple rdtype names address records, each once, from %r; got %r"
            % (_ADDRESS_RDTYPES, tuple(rdtype))
        )
    return types


def _system_search_domains() -> "List[str]":
    """The system resolver's search list, if discoverable.

    Reuses ``dnspython``'s own ``resolv.conf``/Windows-registry parsing
    rather than re-implementing it -- this is the same list
    :func:`resolve_dnspython` draws on for its ``search=True``. Returns ``[]``
    if ``dnspython`` is not installed or nothing is configured; a caller
    treats that as "nothing to expand with", not an error.
    """
    try:
        from dns import resolver as _resolver
    except ImportError:
        return []
    try:
        r = _resolver.Resolver()
    except getattr(_resolver, "NoResolverConfiguration", ()):
        return []  # nothing configured to expand with; nslookup asks anyway
    if r.search:
        return [str(d).rstrip(".") for d in r.search]
    if r.domain and str(r.domain) not in (".", ""):
        return [str(r.domain).rstrip(".")]
    return []


def search_candidates(
    query: str,
    search: "Union[bool, List[str]]",
    *,
    system_domains: bool = False,
    wire: bool = False,
) -> "List[str]":
    """The names to ask about for ``query`` under ``search``, in the order asked.

    A trailing dot makes ``query`` absolute and it is asked as given. For the
    OS resolver and ``nslookup`` a list of domains asks ``query`` as given and
    then under each domain; ``False`` asks the dotted form, which no search
    list expands; ``True`` leaves expansion to the OS resolver, or with
    ``system_domains`` (``nslookup``, which has no list of its own) to the
    system search list.

    ``wire`` is the DNS wire backend's own order: only a single-label name is
    expanded, under each domain first and as given last, and ``True``/``False``
    ask ``query`` as given.
    """
    if wire:
        if (
            isinstance(search, (list, tuple))
            and not query.endswith(".")
            and "." not in query
        ):
            return ["%s.%s" % (query, domain.strip(".")) for domain in search] + [query]
        return [query]
    if query.endswith("."):
        return [query]
    if isinstance(search, (list, tuple)):
        domains = list(search)
    elif search:
        domains = _system_search_domains() if system_domains else []
    else:
        return [query + "."]
    return [query] + [
        "%s.%s" % (query.rstrip("."), d.rstrip(".")) for d in domains if d.strip(".")
    ]


def _port_number(text: str, entry: str) -> int:
    if not (text.isascii() and text.isdigit()):
        raise NetimpsValueError(
            "nameserver %r: port %r is not a number" % (entry, text)
        )
    return int(text)


def _is_doh_server(entry: object) -> bool:
    """A dnspython-only nameserver written as an ``https://`` URL."""
    return isinstance(entry, str) and entry.lstrip().lower().startswith("https://")


def _nameservers(
    entries: "List[str]", port: int, *, names: bool = False
) -> "List[Tuple[str, int]]":
    """``(host, port)`` per nameserver entry: ``host``, ``host:port``, a bare
    IPv6 address, ``[v6]`` or ``[v6]:port``; ``port`` fills an entry that names
    none. The one parser every backend that takes ``ns`` goes through.

    A host has to be an IP address unless ``names``, for ``nslookup``, which
    resolves a nameserver given by name.

    :raises NetimpsValueError: for an entry that is not one of those spellings,
        a port that is not ASCII digits in 1-65535, or a host that is no address.
    """
    out = []
    for entry in entries:
        if not isinstance(entry, str):
            raise TypeError("a nameserver is text, not %r" % (type(entry).__name__,))
        entry = entry.strip()
        if entry.startswith("["):
            host, close, rest = entry[1:].partition("]")
            if not close:
                raise NetimpsValueError("nameserver %r: unclosed '['" % (entry,))
            if rest and not rest.startswith(":"):
                raise NetimpsValueError("nameserver %r: unexpected %r" % (entry, rest))
            number = _port_number(rest[1:], entry) if rest.startswith(":") else port
        elif entry.count(":") == 1:
            host, _, rest = entry.partition(":")
            number = _port_number(rest, entry)
        else:
            host, number = entry, port
        if not 1 <= number <= 65535:
            raise NetimpsValueError(
                "nameserver %r: port %d is outside 1-65535" % (entry, number)
            )
        if not names or not host:
            try:
                _ipaddress.ip_address(host.split("%")[0])
            except ValueError:
                raise NetimpsValueError(
                    "nameserver %r is not an IP address" % (entry,)
                ) from None
        out.append((host, number))
    return out


def _ns_entries(ns: "Optional[Union[str, List[str]]]") -> "List[str]":
    """``ns`` as a list of entries; an empty string or list names none."""
    return (
        [ns]
        if isinstance(ns, str) and ns
        else list(ns or []) if not isinstance(ns, str) else []
    )
