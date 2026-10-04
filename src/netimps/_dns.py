"""DNS resolution (internal).

Three independently callable backends, each with the same
list-of-native-values-or-[]-on-failure contract, plus :func:`resolve` which
tries them in order and returns the first **non-empty** answer:

- :func:`resolve_dnspython` -- ``dnspython``, structured records, every
  ``rdtype``, explicit ``ns=``/``port=``/``search=`` control.
- :func:`resolve_system` -- :func:`socket.getaddrinfo`/
  :func:`socket.gethostbyaddr`, the OS resolver (hosts file, NSS, DNS).
  Address and reverse records (``a``/``aaaa``/``ptr``) only, no ``ns=``
  control -- it always asks the OS resolver, whatever that is configured to
  use.
- :func:`resolve_nslookup` -- shells out to the ``nslookup`` binary. Address
  and reverse records (``a``/``aaaa``/``ptr``) only, parsed from text output.
- :func:`resolve_wire` -- the DNS protocol itself, standard library only: UDP
  (TCP when truncated, or asked) to explicit nameservers, from an optional
  ``source`` address. In the chain only for an explicit ``ns=``/``source=``.

:func:`resolve_doh` asks one DNS-over-HTTPS endpoint (RFC 8484) and is not
part of the chain: a caller that names a DoH URL wants that answer alone.

``query`` accepts :data:`HostLike` everywhere (a hostname string, an
address string, an address object, or an interface object -- its ``.ip`` is
used). ``rdtype=None`` (the default on all four) auto-selects ``"ptr"`` for
an address-literal ``query`` and ``"a"`` otherwise.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import os as _os
import socket as _socket
import struct as _struct
import threading as _threading
import time as _time
from functools import partial as _partial
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
    overload,
)

from . import _dnswire, _proc
from ._exceptions import (
    NetimpsValueError,
    ResolutionError,
    ResolutionTimeoutError,
)
from ._ip import HostLike, IPv4Address, IPv6Address, _dst_argument
from ._parse import try_parse

__all__ = [
    "RESOLUTION_CACHE_TTL",
    "clear_resolution_cache",
    "resolve",
    "resolve_dnspython",
    "resolve_system",
    "resolve_nslookup",
    "resolve_wire",
    "resolve_doh",
]

#: Backends `resolve()` tries, in order, by name. Each entry is looked up on
#: this module, so the order is the single source of truth for the chain.
_BACKENDS = ("dnspython", "wire", "system", "nslookup")

_ADDRESS_RDTYPES = ("a", "aaaa")


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
    treated as a hostname, defaulting to ``"a"`` exactly as before this was
    configurable. Only consulted when ``rdtype`` is not given explicitly --
    an explicit ``rdtype="a"`` on an address still attempts a literal (and
    empty) A lookup rather than being silently overridden.
    """

    return "ptr" if try_parse(query) is not None else "a"


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

    Contract: always a ``list``, **empty** when the name does not resolve --
    never ``None``. Callers can therefore write ``if result:`` and index
    ``result[0]`` safely.

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
        otherwise -- the same default as before this was configurable. Pass
        an explicit ``rdtype`` to opt out of the auto-selection.
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

    A genuine lookup failure (NXDOMAIN, no answer, timeout, all servers failed)
    yields ``[]``; a malformed query or unknown record type raises
    :class:`ValueError`, since that is a caller bug rather than a DNS result.

    Requires the ``dnspython`` package (installed with ``netimps``).
    """
    query = _dst_argument(query)
    if not rdtype:
        rdtype = _auto_rdtype(query)
    rdtype = rdtype.lower()

    try:
        from dns import name as _name
        from dns import resolver as _resolver
    except ImportError as exc:
        raise ResolutionError("dnspython is not installed") from exc

    r = _resolver.Resolver(configure=not ns)
    if isinstance(ns, str):
        ns = [ns]
    if ns:
        r.nameservers = list(ns)
    if port != 53:
        r.port = port

    search_domains = None
    if isinstance(search, (list, tuple)):
        search_domains = list(search)
        search = True
    if search_domains is not None:
        # An explicit domain list replaces the system search list outright,
        # regardless of where the nameservers came from.
        r.search = [_name.from_text(d) for d in search_domains]
    if timeout is not None:
        # `timeout` bounds a single query; `lifetime` bounds the whole
        # resolution including retries against every nameserver. Without the
        # lifetime, a list of dead servers blocks for far longer than asked.
        r.timeout = timeout
        r.lifetime = timeout

    # Looked up by name rather than referenced directly: LifetimeTimeout only
    # exists in dnspython >= 2.0, and the set has shifted between releases, so
    # a hard reference would break on older versions. Anything missing simply
    # drops out of the tuple.
    _lookup_failures = tuple(
        exc
        for exc in (
            getattr(_resolver, name, None)
            for name in (
                "NXDOMAIN",  # name definitively does not exist
                "NoAnswer",  # name exists, no record of this type
                "NoNameservers",  # every nameserver refused or failed
                "LifetimeTimeout",  # ran out of time
                "Timeout",
                "NoResolverConfiguration",  # no system resolver to use
            )
        )
        if isinstance(exc, type) and issubclass(exc, Exception)
    )

    # Only when asked: the keyword is not in every dnspython release.
    extra: "Dict[str, Any]" = {"source": source} if source else {}
    try:
        if rdtype == "ptr":
            # resolve_address builds the reverse (in-addr.arpa/ip6.arpa) name
            # from a plain address itself -- r.resolve(query, "ptr") would
            # require the caller to already have that name, which defeats
            # the point of accepting a literal address as `query`.
            answer = r.resolve_address(query, tcp=tcp, search=search, **extra)
        else:
            answer = r.resolve(query, rdtype, tcp=tcp, search=search, **extra)
    except _lookup_failures:
        # A genuine "no result" -- the documented [] contract.
        return []
    except Exception as exc:
        # Everything else (malformed name, unknown rdtype) is a caller bug
        # rather than a lookup outcome. The old code swallowed these into [],
        # which turned a typo'd record type into a silent empty result.
        raise ValueError("invalid DNS query %r (%s): %s" % (query, rdtype, exc))
    return [_native_record(record) for record in answer]


def _bounded_lookup(lookup: "Callable[[], Any]", timeout: Optional[float]) -> "Any":
    """Run ``lookup`` under a wall-clock deadline (unbounded if ``timeout`` is
    ``None``), returning its result.

    **One mechanism for every record type.** :func:`socket.getaddrinfo` and
    :func:`socket.gethostbyaddr` are both blocking C calls with no timeout of
    their own, so both need this; the ``"ptr"`` branch used to call
    ``gethostbyaddr`` directly on the calling thread and was measured at 4.6s
    against a documented 0.1s deadline.

    A *daemon* thread, joined through a queue rather than a
    ThreadPoolExecutor. The executor looks like the obvious fit and is the
    wrong one: `__exit__` calls `shutdown(wait=True)` on every supported
    Python, so raising out of the `with` block joins the worker still stuck
    inside getaddrinfo() and the caller waits out the whole hang anyway --
    `timeout` would change *what* is raised but not *when*. Its atexit hook
    joins pool threads too, so even `shutdown(wait=False)` would move the hang
    to interpreter exit. A daemon thread is abandoned at both points, which is
    the contract.

    Whatever ``lookup`` raises is re-raised verbatim in the calling thread, so
    each caller keeps classifying its own errors (a ``gaierror``/``herror``
    means "no answer", not a transport failure). Only the deadline itself
    becomes a :class:`ResolutionTimeoutError`.
    """
    if timeout is None:
        return lookup()

    import queue as _queue
    import threading as _threading

    outcome: "_queue.Queue" = _queue.Queue(maxsize=1)

    def _run_lookup() -> None:
        try:
            outcome.put(("ok", lookup()))
        except BaseException as exc:  # relayed to the caller verbatim
            outcome.put(("error", exc))

    _threading.Thread(target=_run_lookup, daemon=True).start()
    try:
        kind, payload = outcome.get(timeout=timeout)
    except _queue.Empty:
        raise ResolutionTimeoutError(
            "resolve_system timed out after %.1fs" % (timeout,)
        )
    if kind == "error":
        raise payload
    return payload


def _resolve_system_once(
    query: str, family: int, timeout: Optional[float]
) -> "List[Any]":

    def _lookup():
        return _socket.getaddrinfo(query, None, family=family, type=_socket.SOCK_STREAM)

    try:
        infos = _bounded_lookup(_lookup, timeout)
    except _socket.gaierror:
        return []

    seen = []
    for info in infos:
        address = info[4][0]
        parsed = try_parse(address)
        if parsed is not None and parsed not in seen:
            seen.append(parsed)
    return seen


@overload
def resolve_system(
    query: "HostLike",
    rdtype: "Literal['a', 'A']",
    *,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[IPv4Address]": ...


@overload
def resolve_system(
    query: "HostLike",
    rdtype: "Literal['aaaa', 'AAAA']",
    *,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[IPv6Address]": ...


@overload
def resolve_system(
    query: "HostLike",
    rdtype: "Literal['ptr', 'PTR']",
    *,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[str]": ...


@overload
def resolve_system(
    query: "HostLike",
    rdtype: "Optional[Union[str, Tuple[str, ...]]]" = None,
    *,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[Any]": ...


def resolve_system(
    query: "HostLike",
    rdtype: "Optional[Union[str, Tuple[str, ...]]]" = None,
    *,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[Any]":
    """Resolve ``query`` via the OS resolver (:func:`socket.getaddrinfo`/
    :func:`socket.gethostbyaddr`).

    ::

        resolve_system("example.com")           # ['93.184.216.34']
        resolve_system("example.com", "aaaa")
        resolve_system("localhost")              # /etc/hosts, no DNS query
        resolve_system("host", search=False)     # "host" only, no suffix expansion
        resolve_system("host", search=["eng.example.com", "example.com"])
        resolve_system("8.8.8.8")                # rdtype=None -> ptr -> ['dns.google']

    Goes through **hosts file, NSS (`nsswitch.conf`) and DNS, in the order
    the OS resolver applies them** -- the same path ``getaddrinfo(3)``/
    ``gethostbyaddr(3)``-based tools use. Unlike :func:`resolve_dnspython`,
    this sees ``/etc/hosts`` entries, ``nsswitch.conf`` sources (mDNS, LDAP,
    whatever NSS is configured with) and any OS-level resolver cache.

    The trade-off: **address and reverse records only** (``rdtype`` must be
    ``"a"``, ``"aaaa"`` or ``"ptr"``; anything else raises
    :class:`ResolutionError` immediately, no query attempted), no ``ns=`` (it
    always asks whatever resolver the OS is configured with -- there is no
    per-call override), and no priority/TTL/other record metadata, since
    neither :func:`socket.getaddrinfo` nor :func:`socket.gethostbyaddr`
    exposes any of that.

    :param query: the hostname (or address, for ``"ptr"``) to look up. Also
        accepts an address object or an :class:`IPv4Interface`/
        :class:`IPv6Interface` (its ``.ip`` is used), not just a string.
    :param rdtype: ``"a"``, ``"aaaa"`` or ``"ptr"``. ``None`` (default)
        auto-selects: ``"ptr"`` when ``query`` is an address literal, ``"a"``
        otherwise. Anything else raises.
    :param timeout: seconds to wait *per candidate name tried* (see
        ``search``). There is no native per-call timeout for
        ``getaddrinfo``/``gethostbyaddr``, so each attempt runs in a daemon
        helper thread and is abandoned (without cancelling the underlying
        blocking call) past the deadline. The deadline bounds **wall time**:
        a resolver that hangs for a minute still raises
        :class:`ResolutionTimeoutError` at ``timeout``, and the abandoned thread
        holds up neither the caller nor interpreter exit. ``None`` waits
        indefinitely.
    :param search: how to expand an unqualified ``query``. Ignored for
        ``rdtype="ptr"`` -- an address has no search-list suffix to try.
        There is no per-call search-list override on
        :func:`socket.getaddrinfo` itself -- unlike ``dnspython``/
        ``nslookup``, the OS resolver takes no such parameter -- so
        ``search=True`` (default) simply leaves ``query`` as given and lets
        the OS resolver apply its own configured search list (glibc's
        ``ndots``/``search``, the Windows per-adapter DNS suffix).
        ``search=False`` appends a trailing ``.``, which every resolver reads
        as "already fully qualified" and skips search-list expansion for --
        the same trick a shell's own ``host``/``getent`` scripts use. A list
        of domain names instead tries ``query`` qualified with each, in
        order, one :func:`socket.getaddrinfo` call per candidate, stopping at
        the first with actual results -- this package's own expansion,
        independent of (and untouched by) the OS resolver's. Already-
        qualified (trailing-dot) names are unaffected by any of this.

    A genuine lookup failure (every candidate tried, none resolve) yields
    ``[]``, never ``None``. An unsupported ``rdtype`` raises
    :class:`ResolutionError`, since that is this backend's fixed limitation,
    not a DNS outcome to report as "no records".
    """
    query = _dst_argument(query)
    if isinstance(rdtype, (tuple, list)):
        # Both families in one getaddrinfo call, in the order the OS chose.
        _address_rdtypes(rdtype)
        family = _socket.AF_UNSPEC if len(rdtype) > 1 else _family_of(rdtype[0])
        return _search_system(query, family, timeout, search)
    if not rdtype:
        rdtype = _auto_rdtype(query)
    rdtype = rdtype.lower()

    if rdtype == "ptr":
        # Bounded by the same daemon-thread helper as the address path:
        # gethostbyaddr has no timeout of its own either, and calling it
        # directly (as this branch used to) ignored `timeout` outright.
        try:
            hostname, _aliases, _addrs = _bounded_lookup(
                _partial(_socket.gethostbyaddr, query), timeout
            )
        except (_socket.herror, _socket.gaierror):
            # herror: no PTR data for a literal address. gaierror: `query`
            # was treated as a hostname (gethostbyaddr's own behaviour for a
            # non-literal argument) and that hostname itself did not
            # resolve. Both are genuine "no answer", not a transport failure.
            return []
        return [hostname]

    if rdtype not in _ADDRESS_RDTYPES:
        raise ResolutionError(
            "resolve_system only supports rdtype in %r, got %r"
            % (_ADDRESS_RDTYPES + ("ptr",), rdtype)
        )

    return _search_system(query, _family_of(rdtype), timeout, search)


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


def _search_system(
    query: str,
    family: int,
    timeout: Optional[float],
    search: "Union[bool, List[str]]",
) -> "List[Any]":
    """The candidates ``search`` implies for ``query``, each asked of the OS
    resolver for ``family``, until one has an answer."""
    if isinstance(search, (list, tuple)) and not query.endswith("."):
        candidates = [query]
        candidates.extend(
            "%s.%s" % (query.rstrip("."), d.rstrip(".")) for d in search if d.strip(".")
        )
    else:
        q = query
        if not search and not q.endswith("."):
            q = q + "."
        candidates = [q]

    for candidate in candidates:
        result = _resolve_system_once(candidate, family, timeout)
        if result:
            return result
    return []


#: `nslookup` prints one of these on a genuine "no such name" -- distinct
#: from "nslookup could not even ask" (missing binary, refused connection to
#: a stated server), which stays a ResolutionError so the chain moves on.
_NSLOOKUP_NO_RECORD_MARKERS = (
    "can't find",
    "non-existent domain",
    "no answer",
    "no records",
    "nxdomain",
)


#: Seconds one ``nslookup`` run may take when the caller passes ``timeout=None``.
_NSLOOKUP_LIMIT_SECONDS = 30.0


def _parse_nslookup_output(text: str, rdtype: str) -> "tuple":
    """Parse the answer section of ``nslookup`` output.

    Returns ``(results, saw_answer)``: ``saw_answer`` is true whenever a
    ``Name:`` line for the query was found, even if it carried no address --
    Windows prints exactly that shape (bare ``Name:``, no ``Address(es):``,
    exit 0, no error text) for NODATA, a name whose parent zone exists but
    which itself has no record of the requested type. That is a genuine
    empty result, not an output shape this parser failed to understand, and
    the caller needs the distinction to tell the two apart.

    Two answer shapes have to coexist here, and neither is optional:

    - **BIND-style** (Linux ``dnsutils``, macOS) -- one block per address::

        Name:	example.com
        Address: 93.184.216.34

    - **Windows** -- one block per name, addresses on an ``Addresses:`` line
      *and* on following indented continuation lines with no label at all::

        Name:    example.com
        Addresses:  2606:4700:10::ac42:93f3
                  2606:4700:10::6814:179a
                  104.20.23.154

      A parser keyed on "does this line start with 'address'" misses those
      continuation lines entirely -- verified against live Windows output,
      where that silently dropped every address but the first.
    """

    lines = text.splitlines()
    # nslookup prints the query's own resolver ("Server:", "Address:") first,
    # then a blank line, then the answer section -- only the answer section
    # names actual records for `query`.
    if "" in lines:
        lines = lines[lines.index("") + 1 :]

    saw_answer = any(line.strip().lower().startswith("name:") for line in lines)

    results: "List[Any]" = []
    if rdtype == "ptr":
        for line in lines:
            if "name =" in line.lower():
                value = line.split("=", 1)[1].strip()
                if value.endswith(".") and not value.endswith(".."):
                    value = value[:-1]
                if value:
                    results.append(value)
        return results, (saw_answer or bool(results))

    in_addresses_block = False
    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.startswith("address"):
            # "Address: 93.184.216.34" (BIND), "Address 1: ...#53" (BIND,
            # multiple servers), or "Addresses: 2606:...  " (Windows, whose
            # first value sits on this same line).
            in_addresses_block = lowered.startswith("addresses")
            value = stripped.split(":", 1)[-1].strip()
            value = value.split("#", 1)[0].strip()
        elif in_addresses_block and line[:1].isspace() and stripped:
            # A Windows continuation line: indented, no label of its own.
            value = stripped
        else:
            in_addresses_block = False
            continue
        parsed = try_parse(value)
        if parsed is None or parsed in results:
            continue
        # Windows can print both families under one "Addresses:" block even
        # for a single -type= query in some resolver configurations -- filter
        # to the family actually requested rather than trust the label.
        is_v6 = parsed.version == 6
        if (rdtype == "aaaa") != is_v6:
            continue
        results.append(parsed)
    return results, (saw_answer or bool(results))


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
    r = _resolver.Resolver()
    if r.search:
        return [str(d).rstrip(".") for d in r.search]
    if r.domain and str(r.domain) not in (".", ""):
        return [str(r.domain).rstrip(".")]
    return []


def _check_nslookup_query(query: str) -> None:
    """Raise :class:`ValueError` unless ``query`` can only be read as a name.

    ``nslookup`` has **no ``--`` end-of-options separator**, so a ``query``
    starting with ``-`` cannot be escaped into position: the binary parses it
    as an option, finds no name argument, and drops into *interactive* mode --
    where it reads names to look up from **stdin**. Measured: that drained the
    calling program's stdin and sent each line to the configured nameserver as
    a DNS query name. The subprocess gets :data:`subprocess.DEVNULL` for stdin
    now (the right default for anything a library spawns), which closes the
    exfiltration, but a leading ``-`` is still rejected rather than escaped --
    there is nowhere safe to put it, and a lookup that silently became an
    option is not a lookup.

    Whitespace, control characters and an empty query get the same treatment:
    none can occur in a name any resolver would accept, and an empty argument
    reaches interactive mode by the same route.
    """
    if not query.strip():
        raise NetimpsValueError("query must be a non-empty hostname or address")
    if query.startswith("-"):
        raise NetimpsValueError(
            "refusing to look up %r: a leading '-' is read as an nslookup "
            "option, not a name, and nslookup has no '--' separator to "
            "escape it with" % (query,)
        )
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in query):
        raise NetimpsValueError(
            "refusing to look up %r: a hostname or address cannot contain "
            "whitespace or control characters" % (query,)
        )


def _resolve_nslookup_once(
    query: str,
    rdtype: str,
    ns: Optional[str],
    timeout: Optional[float],
) -> "List[Any]":
    # -type= is always passed explicitly, including for ptr: nslookup will
    # infer a reverse lookup from an address-shaped query on its own, but
    # that implicit form prints in the forward-lookup Name:/Address: shape
    # instead of the "<addr>.in-addr.arpa  name = <host>" line the parser
    # below expects, so relying on it would make the output shape depend on
    # which query the caller happened to type.
    cmd = ["nslookup", "-type=%s" % rdtype, query]
    if ns:
        cmd.append(ns)

    try:
        # The runner closes stdin: an nslookup that finds no usable name
        # argument goes interactive and would look up the caller's input.
        response = _proc.run(
            cmd[0],
            cmd[1:],
            timeout=_NSLOOKUP_LIMIT_SECONDS if timeout is None else timeout,
        )
    except TimeoutError as exc:
        raise ResolutionTimeoutError("nslookup timed out: %s" % (exc,)) from exc
    except OSError as exc:
        raise ResolutionError("nslookup unavailable: %s" % (exc,)) from exc

    text = response.stdout
    stderr_text = response.stderr
    # Windows nslookup prints "*** <server> can't find <name>: Non-existent
    # domain" on stderr, not stdout -- the NXDOMAIN marker check has to see
    # both, or a genuine "no such name" looks like an unparseable answer.
    lowered = (text + "\n" + stderr_text).lower()

    if any(marker in lowered for marker in _NSLOOKUP_NO_RECORD_MARKERS):
        # A stated "no such name"/"no records", whatever the exit status --
        # BIND's nslookup exits 1 on NXDOMAIN, Windows' exits 0.
        return []
    if response.returncode != 0:
        # Non-zero with none of those markers: the binary could not complete
        # the query at all (no reachable server, connection refused, a usage
        # error). Reporting that as [] would make a transport failure
        # indistinguishable from NXDOMAIN -- and, in resolve()'s chain, stop
        # the chain on it.
        detail = (stderr_text or text).strip().splitlines()
        raise ResolutionError(
            "nslookup exited %d for %r: %s"
            % (response.returncode, query, detail[-1] if detail else "no output")
        )

    results, saw_answer = _parse_nslookup_output(text, rdtype)
    if not results and not saw_answer:
        # Nonzero-looking success but nothing parsed, and not even a "Name:"
        # line to say NODATA -- an nslookup output shape this parser does
        # not recognise, not a definitive "no record".
        raise ResolutionError("could not parse nslookup output for %r" % (query,))
    return results


@overload
def resolve_nslookup(
    query: "HostLike",
    rdtype: "Literal['a', 'A']",
    *,
    ns: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[IPv4Address]": ...


@overload
def resolve_nslookup(
    query: "HostLike",
    rdtype: "Literal['aaaa', 'AAAA']",
    *,
    ns: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[IPv6Address]": ...


@overload
def resolve_nslookup(
    query: "HostLike",
    rdtype: "Literal['ptr', 'PTR']",
    *,
    ns: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[str]": ...


@overload
def resolve_nslookup(
    query: "HostLike",
    rdtype: Optional[str] = None,
    *,
    ns: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[Any]": ...


def resolve_nslookup(
    query: "HostLike",
    rdtype: Optional[str] = None,
    *,
    ns: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[Any]":
    """Resolve ``query`` by shelling out to the ``nslookup`` binary.

    ::

        resolve_nslookup("example.com")               # ['93.184.216.34']
        resolve_nslookup("example.com", "aaaa")
        resolve_nslookup("example.com", ns="1.1.1.1")
        resolve_nslookup("host")                       # tries the system search list
        resolve_nslookup("host", search=["eng.example.com", "example.com"])
        resolve_nslookup("8.8.8.8")                    # rdtype=None -> ptr -> ['dns.google']

    A fallback for when neither ``dnspython`` nor :func:`resolve_system` is
    usable: goes through whatever resolver ``nslookup`` itself is configured
    to use (the OS resolver's nameservers, unless ``ns=`` overrides it).

    :param query: the name (or address, for ``ptr``) to look up. Also accepts
        an address object or an :class:`IPv4Interface`/:class:`IPv6Interface`
        (its ``.ip`` is used), not just a string.
    :param rdtype: ``"a"``, ``"aaaa"`` or ``"ptr"``. ``None`` (default)
        auto-selects: ``"ptr"`` when ``query`` is an address literal, ``"a"``
        otherwise. Anything else raises :class:`ResolutionError` immediately,
        no subprocess spawned -- ``nslookup``'s plain-text output is only
        parsed reliably for these three.
    :param ns: nameserver to query, passed as ``nslookup``'s trailing
        ``server`` argument. ``None`` uses ``nslookup``'s own default.
    :param timeout: seconds to allow *each* subprocess attempt to run --
        one per candidate name tried under ``search``. ``None`` allows 30
        seconds: a program never runs unbounded.
    :param search: how to expand an unqualified ``query``. ``nslookup`` has
        no built-in search-list handling (unlike ``dnspython``), so this
        tries one ``nslookup`` call per candidate name, in order, and returns
        the first with actual records: ``True`` (default) tries ``query``
        qualified with each domain in the system resolver's search list (via
        the same ``resolv.conf``/registry parsing :func:`resolve_dnspython`
        uses -- ``[]`` there, e.g. ``dnspython`` not installed, falls back to
        the literal name only); ``False`` looks up ``query`` as-is only; a
        list of domain names tries exactly those suffixes. Ignored for an
        already-qualified (trailing-dot) ``query`` or a ``"ptr"`` lookup,
        neither of which a search list applies to.

    A genuine lookup failure (NXDOMAIN or equivalent, for every candidate
    tried) yields ``[]``. A missing ``nslookup`` binary, a timeout, a
    **non-zero exit with no "no such name" message** (no reachable server, a
    refused connection), or an unsupported ``rdtype`` raises
    :class:`ResolutionError` -- there was no definitive DNS answer to report,
    so :func:`resolve`'s chain moves on rather than treating it as NXDOMAIN.

    A ``query`` that ``nslookup`` would read as an option (one starting with
    ``-``) or that cannot be a name at all (empty, whitespace, control
    characters) raises :class:`ValueError` **before any subprocess is
    spawned**: ``nslookup`` has no ``--`` end-of-options separator, so such a
    query cannot be escaped into position -- left to reach the binary it
    becomes an option, and an ``nslookup`` with no name argument goes
    *interactive* and reads query names from stdin. The subprocess is given
    :data:`subprocess.DEVNULL` for stdin as well, so it can never read the
    caller's.
    """
    query = _dst_argument(query)
    _check_nslookup_query(query)
    if not rdtype:
        rdtype = _auto_rdtype(query)
    rdtype = rdtype.lower()
    if rdtype not in ("a", "aaaa", "ptr"):
        raise ResolutionError(
            "resolve_nslookup only supports rdtype in ('a', 'aaaa', 'ptr'), got %r"
            % (rdtype,)
        )

    domains: "List[str]" = []
    if rdtype != "ptr" and not query.endswith("."):
        if isinstance(search, (list, tuple)):
            domains = list(search)
        elif search:
            domains = _system_search_domains()
        else:
            # search=False must also stop nslookup's own OS-level search-list
            # expansion from kicking in on the bare literal query -- the same
            # trailing-dot trick resolve_system uses for the same reason.
            query = query + "."

    candidates = [query]
    candidates.extend(
        "%s.%s" % (query.rstrip("."), d.rstrip(".")) for d in domains if d.strip(".")
    )

    last_error: Optional[ResolutionError] = None
    for candidate in candidates:
        try:
            result = _resolve_nslookup_once(candidate, rdtype, ns, timeout)
        except ResolutionError as exc:
            last_error = exc
            continue
        if result:
            return result
        # A definitive empty answer for this candidate -- try the next
        # search suffix, the same way the OS resolver would, but keep [] as
        # the fallback if every candidate is genuinely a dead end.
    if last_error is not None:
        raise last_error
    return []


#: Seconds an answer is kept when a lookup passes ``cache=True``. Resolver
#: answers carry TTLs of their own that the backends do not expose, so this is a
#: fixed middle: long enough that a loop resolving one upstream per packet asks
#: once, short enough that a changed record is seen within the half minute.
#: Pass a number to choose your own.
RESOLUTION_CACHE_TTL = 30.0

#: The cache never grows past this many entries; the oldest go first.
_RESOLUTION_CACHE_LIMIT = 1024

_CACHE_LOCK = _threading.Lock()
#: key -> (monotonic stamp, answer). An empty tuple is a cached miss.
_RESOLUTION_CACHE: "Dict[Tuple[Any, ...], Tuple[float, Tuple[Any, ...]]]" = {}


def clear_resolution_cache() -> None:
    """Drop every cached answer, so the next ``cache=`` lookup asks again.

    For a caller that *knows* a record changed and should not wait out the TTL.
    Harmless when nothing is cached.
    """
    with _CACHE_LOCK:
        _RESOLUTION_CACHE.clear()


def _freeze(value: "Any") -> "Any":
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, str):
        return value.lower()
    return value


def _cache_key(
    query: str,
    rdtype: "Optional[Union[str, Tuple[str, ...]]]",
    ns: "Any",
    timeout: "Optional[float]",
    port: int,
    tcp: bool,
    search: "Any",
    backends: "Any",
    strict: bool,
    source: "Any",
) -> "Tuple[Any, ...]":
    """Every argument that can change the answer, in a hashable form.

    Names and addresses compare without case, since DNS does; the trailing root
    dot is not folded away, because it also decides whether a search list applies.
    """
    return (
        query.lower(),
        _freeze(rdtype) if rdtype else None,
        _freeze(ns),
        timeout,
        port,
        tcp,
        _freeze(search),
        _freeze(backends),
        strict,
        _freeze(source),
    )


def _cache_get(key: "Tuple[Any, ...]", ttl: float) -> "Optional[Tuple[Any, ...]]":
    with _CACHE_LOCK:
        entry = _RESOLUTION_CACHE.get(key)
        if entry is not None and (_time.monotonic() - entry[0]) < ttl:
            return entry[1]
    return None


def _cache_put(key: "Tuple[Any, ...]", answer: "List[Any]") -> None:
    with _CACHE_LOCK:
        _RESOLUTION_CACHE[key] = (_time.monotonic(), tuple(answer))
        while len(_RESOLUTION_CACHE) > _RESOLUTION_CACHE_LIMIT:
            del _RESOLUTION_CACHE[next(iter(_RESOLUTION_CACHE))]


@overload
def resolve(
    query: "HostLike",
    rdtype: "Literal['a', 'A']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    backends: "Optional[Union[str, List[str]]]" = None,
    strict: bool = False,
    source: Optional[Union[str, List[str]]] = None,
    cache: "Union[bool, float]" = False,
) -> "List[IPv4Address]": ...


@overload
def resolve(
    query: "HostLike",
    rdtype: "Literal['aaaa', 'AAAA']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    backends: "Optional[Union[str, List[str]]]" = None,
    strict: bool = False,
    source: Optional[Union[str, List[str]]] = None,
    cache: "Union[bool, float]" = False,
) -> "List[IPv6Address]": ...


@overload
def resolve(
    query: "HostLike",
    rdtype: "Literal['ptr', 'PTR']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    backends: "Optional[Union[str, List[str]]]" = None,
    strict: bool = False,
    source: Optional[Union[str, List[str]]] = None,
    cache: "Union[bool, float]" = False,
) -> "List[str]": ...


@overload
def resolve(
    query: "HostLike",
    rdtype: "Optional[Union[str, Tuple[str, ...]]]" = None,
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    backends: "Optional[Union[str, List[str]]]" = None,
    strict: bool = False,
    source: Optional[Union[str, List[str]]] = None,
    cache: "Union[bool, float]" = False,
) -> "List[Any]": ...


def resolve(
    query: "HostLike",
    rdtype: "Optional[Union[str, Tuple[str, ...]]]" = None,
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    backends: "Optional[Union[str, List[str]]]" = None,
    strict: bool = False,
    source: Optional[Union[str, List[str]]] = None,
    cache: "Union[bool, float]" = False,
) -> "List[Any]":
    """Resolve ``query``, trying each backend in ``backends`` until one gives
    a definitive answer.

    ::

        resolve("example.com")                    # ['93.184.216.34']
        resolve("example.com", "aaaa")
        resolve("example.com", "mx", ns="1.1.1.1")
        resolve("host", backends="system")        # OS resolver only
        resolve("host", backends=["nslookup", "dnspython"])  # custom order
        resolve("8.8.8.8")                        # rdtype=None -> ptr -> ['dns.google']

    Default order is ``["dnspython", "wire", "system", "nslookup"]``:
    dnspython first (structured records, full ``rdtype`` support, explicit
    ``ns=``/``search=`` control), then the standard-library DNS client --
    only for an explicit ``ns=`` or ``source=``, so ``ns=`` works without
    dnspython -- then the OS resolver (hosts file, NSS, OS cache -- address
    and reverse records, but no ``ns=`` override), then ``nslookup`` as a last
    resort if no Python-level path is usable.

    A backend is **skipped**, not tried and failed, when it structurally
    cannot serve the request: :func:`resolve_system` for a ``rdtype`` outside
    ``"a"``/``"aaaa"``/``"ptr"``, or for an explicit ``ns=``/``port=``/
    ``tcp=`` (the OS resolver takes no per-call nameserver, port or transport,
    so running it would silently ignore the caller's choice);
    :func:`resolve_dnspython` if ``dnspython`` is not installed.

    **Only a non-empty answer stops the chain.** An empty one does not, and
    that is deliberate: the backends resolve by structurally different
    mechanisms, and DNS's "no such name" says nothing about what the OS
    resolver can still answer. ``dnspython`` gets NXDOMAIN for ``localhost``
    on Windows and macOS while :func:`resolve_system` answers it from the
    hosts file; the same holds for ``.local``/mDNS names and anything else
    only an NSS source knows. A backend that could not even attempt the query
    (missing binary, timeout, transport failure) falls through as well. If
    every applicable backend answers empty, the result is ``[]`` -- and so it
    is when every one of them fails to *attempt*, unless ``strict=True``.

    The cost is latency on a genuinely non-existent name: two or three backend
    calls instead of one, the last of which may spawn ``nslookup``. Narrow
    ``backends`` to opt out -- ``backends="dnspython"`` keeps the single call.

    :param query: the name (or address, for reverse types) to look up. Also
        accepts an address object or an :class:`IPv4Interface`/
        :class:`IPv6Interface` (its ``.ip`` is used), not just a string.
    :param rdtype: DNS record type. ``None`` (default) auto-selects: ``"ptr"``
        when ``query`` is an address literal (an ``"a"``/``"aaaa"`` lookup
        *of* an address makes no sense), ``"a"`` otherwise -- the same
        default as before this was configurable. Pass an explicit ``rdtype``
        to opt out. ``"a"``/``"aaaa"``/``"ptr"`` reach every backend; other
        types are ``dnspython``-only (see :func:`resolve_dnspython`).
        ``("a", "aaaa")`` asks for both families at once: the OS resolver
        answers in one call, in the order it chose, and every other backend
        is asked for ``"a"`` and then ``"aaaa"`` with the answers joined.
    :param ns: nameserver(s) to query instead of the system resolver. Honoured
        by ``dnspython`` and ``nslookup`` (a single nameserver for the
        latter); excludes ``system`` from the chain, since it cannot honour a
        per-call nameserver.
    :param timeout: seconds per backend attempt.
    :param port: nameserver port; ``dnspython`` only, and excludes ``system``
        from the chain when it is not 53.
    :param tcp: query over TCP; ``dnspython`` only, and excludes ``system``
        from the chain when true.
    :param search: search-list behaviour, honoured by all three backends (see
        :func:`resolve_dnspython`, :func:`resolve_system` and
        :func:`resolve_nslookup` respectively). Only ``dnspython`` has this
        built in; the other two try one candidate name per call instead.
    :param backends: explicit backend order/subset, by name (``"dnspython"``,
        ``"system"``, ``"nslookup"``) or a single name as a plain string.
        ``None`` (default) uses all three in the default order, each filtered
        for applicability as described above.
    :param source: the local address -- or one per address family, as a
        list -- the queries go out from. Honoured by ``wire`` (each nameserver
        gets the address of its family) and ``dnspython`` (one address only);
        excludes ``system`` and ``nslookup``, which cannot choose it.
    :param cache: reuse a recent answer. ``False`` (the default) neither reads
        nor writes the cache; ``True`` keeps an answer for
        :data:`RESOLUTION_CACHE_TTL` seconds and a number is that many.
        Keyed on the name and **every** option, so a different ``ns`` or
        ``rdtype`` is a different entry. **An empty answer is cached like any
        other**, so a name that does not resolve is asked once per TTL; an
        outage (every backend failed to ask) and an exception are not cached.
        Call :func:`clear_resolution_cache` when the answer is known to have
        changed. Process-wide and thread-safe.
    :param strict: raise instead of returning ``[]`` when no backend could
        *ask* -- every applicable one failed with a :class:`ResolutionError`
        (resolver unreachable, timeout, ``nslookup`` missing). Off by default,
        so a resolver outage looks the same to the caller as a name that does
        not exist. Pass ``strict=True`` when the two must be told apart: the
        last backend's :class:`ResolutionError` is raised, with the reason in
        its message. It does **not** turn an empty *answer* into an error --
        a name that genuinely does not resolve still returns ``[]``.

    Contract: always a ``list``, **empty** on a genuine lookup failure, never
    ``None`` -- unless ``strict=True``, which is the only way this raises for
    a resolution outcome. A malformed query or unknown record type raises
    :class:`ValueError` immediately, without trying every backend, since that
    is a caller bug rather than a resolution outcome.
    """
    query = _dst_argument(query)
    if cache is False:
        return _resolve_chain(
            query, rdtype, ns, timeout, port, tcp, search, backends, strict, source
        )[0]
    key = _cache_key(
        query, rdtype, ns, timeout, port, tcp, search, backends, strict, source
    )
    ttl = RESOLUTION_CACHE_TTL if cache is True else float(cache)
    hit = _cache_get(key, ttl)
    if hit is not None:
        return list(hit)
    result, definitive = _resolve_chain(
        query, rdtype, ns, timeout, port, tcp, search, backends, strict, source
    )
    if definitive:
        _cache_put(key, result)
    return result


def _resolve_chain(
    query: str,
    rdtype: "Optional[Union[str, Tuple[str, ...]]]",
    ns: "Optional[Union[str, List[str]]]",
    timeout: Optional[float],
    port: int,
    tcp: bool,
    search: "Union[bool, List[str]]",
    backends: "Optional[Union[str, List[str]]]",
    strict: bool,
    source: "Optional[Union[str, List[str]]]",
) -> "Tuple[List[Any], bool]":
    """The chain behind :func:`resolve`: ``(answer, definitive)``.

    *definitive* is false only for the empty list returned because every
    applicable backend failed to *ask*, which is an outage and not an answer.
    """
    both: "Optional[Tuple[str, ...]]" = None
    if isinstance(rdtype, (tuple, list)):
        both = _address_rdtypes(rdtype)
        rdtype = both[0]
    elif not rdtype:
        rdtype = _auto_rdtype(query)
    rdtype = rdtype.lower()
    if isinstance(backends, str):
        backends = [backends]
    chain = list(backends) if backends is not None else list(_BACKENDS)

    unknown = [name for name in chain if name not in _BACKENDS]
    if unknown:
        raise ValueError(
            "unknown resolve backend(s) %r, expected from %r" % (unknown, _BACKENDS)
        )

    last_error: Optional[Exception] = None
    attempted = False
    answered = False  # at least one backend gave a definitive (empty) answer
    for name in chain:
        attempt: "Callable[[], List[Any]]"
        if name == "system":
            if rdtype not in ("a", "aaaa", "ptr") or ns or port != 53 or tcp or source:
                # Cannot honour a non-address rdtype, nor a per-call
                # nameserver/port/transport -- running it anyway would answer
                # a different question from the one asked.
                continue
            attempt = _partial(
                resolve_system,
                query,
                rdtype=both if both is not None and len(both) > 1 else rdtype,
                timeout=timeout,
                search=search,
            )
        elif name == "dnspython":
            sources = [source] if isinstance(source, str) else list(source or [])
            if len(sources) > 1:
                continue  # one source address only; `wire` picks per family
            attempt = _partial(
                resolve_dnspython,
                query,
                rdtype=rdtype,
                ns=ns,
                timeout=timeout,
                port=port,
                tcp=tcp,
                search=search,
                source=sources[0] if sources else None,
            )
        elif name == "wire":
            if not (ns or source) or rdtype not in _dnswire.RDTYPES:
                continue
            attempt = _partial(
                resolve_wire,
                query,
                rdtype=rdtype,
                ns=ns,
                timeout=timeout,
                port=port,
                tcp=tcp,
                search=search,
                source=source,
            )
        elif name == "nslookup":
            if rdtype not in ("a", "aaaa", "ptr") or source:
                continue
            if isinstance(ns, (list, tuple)):
                single_ns = ns[0] if ns else None
            else:
                single_ns = ns
            attempt = _partial(
                resolve_nslookup,
                query,
                rdtype=rdtype,
                ns=single_ns,
                timeout=timeout,
                search=search,
            )
        else:  # pragma: no cover -- `unknown` above already rejected these
            continue

        if both is not None and len(both) > 1 and name != "system":
            attempt = _each_rdtype(attempt, both)
        attempted = True
        try:
            result = attempt()
        except ResolutionError as exc:
            # Could not even ask: try the next backend, keep the error in case
            # none of them can.
            last_error = exc
            continue
        if result:
            return result, True
        # An empty answer is definitive for *this* backend's mechanism only,
        # so the chain keeps going; `answered` is what makes the final result
        # [] rather than a raise.
        answered = True

    if not attempted:
        # Name what excluded them: with `port=`/`tcp=` now excluding `system`
        # too, "cannot serve rdtype='a'" on its own would be a puzzle.
        excluded = []
        if ns:
            excluded.append("an explicit ns")
        if port != 53:
            excluded.append("port=%r" % (port,))
        if tcp:
            excluded.append("tcp=True")
        if source:
            excluded.append("source=%r" % (source,))
        raise ValueError(
            "no backend in %r can serve rdtype=%r%s"
            % (
                chain,
                rdtype,
                " with %s" % (" and ".join(excluded),) if excluded else "",
            )
        )
    if answered:
        return [], True
    assert last_error is not None
    if strict:
        raise last_error
    # Every applicable backend failed to *attempt* -- a resolver outage, not an
    # answer. Returning [] is the default because that is what a caller writing
    # `if not resolve(host):` has always got, and because the distinction
    # between "no such name" and "could not ask" is one most callers do not act
    # on differently. `strict=True` is for the ones that do.
    return [], False


def _each_rdtype(
    attempt: "Callable[..., List[Any]]", types: "Tuple[str, ...]"
) -> "Callable[[], List[Any]]":
    """``attempt`` run once per record type, the answers joined in order.

    ``attempt`` takes the record type as its ``rdtype`` keyword. A backend that
    could not ask for one type fails the whole attempt unless another type did
    answer: half an answer from a resolver that errored is still an answer, but
    an empty one is not evidence the name is absent.
    """

    def run() -> "List[Any]":
        found: "List[Any]" = []
        error: "Optional[ResolutionError]" = None
        for kind in types:
            try:
                found.extend(attempt(rdtype=kind))
            except ResolutionError as exc:
                error = error or exc
        if error is not None and not found:
            raise error
        return found

    return run


def _query(
    query: str,
    rdtype: "Union[str, Tuple[str, ...]]",
    *,
    check: bool,
    ns: "Optional[Union[str, List[str]]]",
    timeout: Optional[float],
    port: int,
    tcp: bool,
    search: "Union[bool, List[str]]",
    backends: "Optional[Union[str, List[str]]]",
    source: "Optional[Union[str, List[str]]]",
    cache: "Union[bool, float]",
) -> "List[Any]":
    """The one place :class:`~netimps.Host` and :class:`~netimps.FQDN` reach
    :func:`resolve`.

    With no resolver option the OS resolver alone answers: it is what the
    standard library's own lookups use, and a missed name costs it a few
    milliseconds where the full chain costs seconds. Naming a nameserver, port,
    transport, source address or ``backends`` hands the choice to
    :func:`resolve` and its chain.

    ``check`` re-raises a resolver outage (``strict=True``); the caller turns an
    empty answer into the error, since only it knows what was asked.
    """
    if backends is None and not (ns or port != 53 or tcp or source):
        backends = "system"
    return resolve(
        query,
        rdtype,
        ns=ns,
        timeout=timeout,
        port=port,
        tcp=tcp,
        search=search,
        backends=backends,
        strict=check,
        source=source,
        cache=cache,
    )


def lookup_ip(
    name: str,
    *,
    check: bool = False,
    ipv6: "Optional[bool]" = None,
    ns: "Optional[Union[str, List[str]]]" = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: "Union[bool, List[str]]" = True,
    backends: "Optional[Union[str, List[str]]]" = None,
    source: "Optional[Union[str, List[str]]]" = None,
    cache: "Union[bool, float]" = False,
) -> "Optional[Any]":
    """The first address ``name`` resolves to (internal; ``name`` is not a literal).

    ``ipv6`` picks the record type: ``True`` AAAA, ``False`` A, ``None`` both
    in one lookup. ``None`` is the answer for a miss, or
    :class:`ResolutionError` with ``check=True``.
    """
    rdtype: "Union[str, Tuple[str, ...]]" = (
        "aaaa" if ipv6 is True else "a" if ipv6 is False else ("a", "aaaa")
    )
    answers = _query(
        name,
        rdtype,
        check=check,
        ns=ns,
        timeout=timeout,
        port=port,
        tcp=tcp,
        search=search,
        backends=backends,
        source=source,
        cache=cache,
    )
    for answer in answers:
        if isinstance(answer, (_ipaddress.IPv4Address, _ipaddress.IPv6Address)):
            return answer
    if check:
        raise ResolutionError("%s has no address record" % (name,))
    return None


def lookup_fqdn(
    address: str,
    *,
    check: bool = False,
    ns: "Optional[Union[str, List[str]]]" = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: "Union[bool, List[str]]" = True,
    backends: "Optional[Union[str, List[str]]]" = None,
    source: "Optional[Union[str, List[str]]]" = None,
    cache: "Union[bool, float]" = False,
) -> "Optional[Any]":
    """The name ``address`` reverses to, as an ``FQDN`` without its root dot, or
    ``None`` (internal; ``address`` is a literal)."""
    from ._fqdn import FQDN

    answers = _query(
        address,
        "ptr",
        check=check,
        ns=ns,
        timeout=timeout,
        port=port,
        tcp=tcp,
        search=search,
        backends=backends,
        source=source,
        cache=cache,
    )
    for answer in answers:
        name = FQDN.try_parse(str(answer))
        if name is not None:
            return name
    if check:
        raise ResolutionError("%s has no reverse name" % (address,))
    return None


# --- the DNS protocol, standard library only ---------------------------------


def _servers(
    ns: "Optional[Union[str, List[str]]]", port: int
) -> "List[Tuple[str, int]]":
    """``(host, port)`` per nameserver: ``host``, ``host:port``, a bare IPv6
    address, ``[v6]`` or ``[v6]:port``. ``None``: the system's, from
    ``/etc/resolv.conf`` (POSIX only)."""
    entries = [ns] if isinstance(ns, str) else list(ns or [])
    if not entries:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as handle:
                entries = [
                    line.split()[1]
                    for line in handle
                    if line.split()[:1] == ["nameserver"] and len(line.split()) > 1
                ]
        except OSError:
            entries = []
        if not entries:
            raise ResolutionError(
                "resolve_wire needs ns= here: no /etc/resolv.conf to take the system's from"
            )
    out = []
    for entry in entries:
        entry = entry.strip()
        if entry.startswith("["):
            host, _, rest = entry[1:].partition("]")
            number = int(rest[1:]) if rest.startswith(":") else port
        elif entry.count(":") == 1:
            host, _, rest = entry.partition(":")
            number = int(rest)
        else:
            host, number = entry, port
        try:
            _ipaddress.ip_address(host.split("%")[0])
        except ValueError:
            raise ValueError("nameserver %r is not an IP address" % (entry,))
        out.append((host, number))
    return out


def _source_for(
    source: "Optional[Union[str, List[str]]]", host: str
) -> "Optional[str]":
    """The source address of ``host``'s family, ``None`` for any; a source
    list without one for that family skips the server (``ValueError``)."""
    if not source:
        return None
    sources = [source] if isinstance(source, str) else list(source)
    family = _ipaddress.ip_address(host.split("%")[0]).version
    for address in sources:
        if _ipaddress.ip_address(address.split("%")[0]).version == family:
            return address
    raise ValueError("no source address for IPv%d nameserver %s" % (family, host))


def _exchange(
    server: "Tuple[str, int]",
    payload: bytes,
    timeout: float,
    tcp: bool,
    source: "Optional[str]",
) -> bytes:
    host, port = server
    family = _socket.AF_INET6 if ":" in host else _socket.AF_INET
    sock = _socket.socket(family, _socket.SOCK_STREAM if tcp else _socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        if source:
            sock.bind((source, 0))
        sock.connect((host, port))
        if not tcp:
            sock.send(payload)
            return sock.recv(65535)
        sock.sendall(_struct.pack("!H", len(payload)) + payload)
        size = _struct.unpack("!H", _recv_exactly(sock, 2))[0]
        return _recv_exactly(sock, size)
    finally:
        sock.close()


def _recv_exactly(sock: "_socket.socket", count: int) -> bytes:
    data = b""
    while len(data) < count:
        piece = sock.recv(count - len(data))
        if not piece:
            raise OSError("connection closed after %d of %d bytes" % (len(data), count))
        data += piece
    return data


def _question(query: str, rdtype: "Optional[str]") -> "Tuple[str, str]":
    """``(name asked, rdtype)``: an address literal's PTR name for ``ptr``."""
    rdtype = (rdtype or _auto_rdtype(query)).lower()
    if rdtype not in _dnswire.RDTYPES:
        raise ResolutionError(
            "rdtype %r is not one the DNS wire backend reads (%s)"
            % (rdtype, ", ".join(sorted(_dnswire.RDTYPES)))
        )
    if rdtype == "ptr":
        try:
            return _dnswire.reverse_name(query), rdtype
        except ValueError:
            pass
    return query, rdtype


@overload
def resolve_wire(
    query: "HostLike",
    rdtype: "Literal['a', 'A']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[IPv4Address]": ...


@overload
def resolve_wire(
    query: "HostLike",
    rdtype: "Literal['aaaa', 'AAAA']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[IPv6Address]": ...


@overload
def resolve_wire(
    query: "HostLike",
    rdtype: "Literal['ptr', 'PTR']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[str]": ...


@overload
def resolve_wire(
    query: "HostLike",
    rdtype: Optional[str] = None,
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[Any]": ...


def resolve_wire(
    query: "HostLike",
    rdtype: Optional[str] = None,
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[Any]":
    """Resolve ``query`` by speaking DNS to ``ns`` directly -- no dnspython,
    no OS resolver. UDP, retried over TCP when the reply is truncated (or TCP
    throughout with ``tcp=True``); the nameservers in turn until one answers.

    ::

        resolve_wire("example.com", ns="1.1.1.1")
        resolve_wire("example.com", "aaaa", ns=["10.0.0.53:5353", "[fd00::53]"])
        resolve_wire("example.com", ns="10.0.0.53", source="10.0.0.7")

    :param ns: nameserver(s): ``host``, ``host:port``, ``[v6]:port``.
        ``None``: ``/etc/resolv.conf``'s (POSIX; elsewhere
        :class:`ResolutionError`).
    :param rdtype: ``a``, ``aaaa``, ``cname``, ``ptr``, ``mx``, ``txt``,
        ``ns``, ``srv``; ``None`` auto-selects as :func:`resolve` does.
        Another type is a :class:`ResolutionError` (the chain moves on).
    :param timeout: seconds for the whole resolution, every server included.
    :param port: the port of an ``ns`` entry that names none.
    :param source: the address the queries leave from -- one, or one per
        address family; a server whose family has none is skipped.
    :param search: a list of domains tries ``query`` under each, then as
        given; ``True``/``False`` ask for ``query`` as given (this backend
        reads no system search list).

    Contract as the other backends: native values, ``[]`` for NXDOMAIN or no
    record of the type, :class:`ResolutionError` when no server answered
    (:class:`ResolutionTimeoutError` when the deadline or a socket timeout
    was the reason). A reply the codec cannot read, or a name it cannot encode,
    is not raised as such: it counts as that server not answering, and the
    :class:`DNSDecodeError` is the ``__cause__`` of the final error.
    A CNAME chain inside the reply is followed.
    """
    query = _dst_argument(query)
    name, rdtype = _question(query, rdtype)
    servers = _servers(ns, port)
    names = [name]
    if isinstance(search, (list, tuple)) and not name.endswith(".") and "." not in name:
        names = ["%s.%s" % (name, domain.strip(".")) for domain in search] + [name]
    deadline = _time.monotonic() + (timeout if timeout is not None else 5.0)
    last: Optional[Exception] = None
    answered = False
    for candidate in names:
        for index, server in enumerate(servers):
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise ResolutionTimeoutError(
                    "no answer within %ss (last: %s)" % (timeout, last)
                ) from last
            # Each server gets its share of what is left, so a dead first one
            # cannot use up the time the next would have answered in.
            remaining /= len(servers) - index
            try:
                from_ = _source_for(source, server[0])
                ident = int.from_bytes(_os.urandom(2), "big")
                payload = _dnswire.build_query(candidate, rdtype, ident)
                reply = _dnswire.parse_response(
                    _exchange(server, payload, remaining, tcp, from_), ident
                )
                if reply.truncated and not tcp:
                    reply = _dnswire.parse_response(
                        _exchange(
                            server,
                            payload,
                            max(deadline - _time.monotonic(), 0.01),
                            True,
                            from_,
                        ),
                        ident,
                    )
            except (OSError, ValueError) as exc:
                last = exc
                continue
            if reply.rcode == _dnswire.NXDOMAIN:
                answered = True
                break
            if reply.rcode != _dnswire.NOERROR:
                last = ResolutionError(
                    "%s:%d answered rcode %d" % (server[0], server[1], reply.rcode)
                )
                continue
            values = reply.records(candidate, rdtype)
            if values:
                return values
            answered = True
            break
    if answered:
        return []
    if isinstance(last, _socket.timeout):
        raise ResolutionTimeoutError(
            "no nameserver answered in time: %s" % (last,)
        ) from last
    raise ResolutionError("no nameserver answered: %s" % (last,)) from last


def _urllib_fetch(
    url: str, body: bytes, headers: "dict", timeout: Optional[float]
) -> bytes:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            kind = (
                response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            )
            if kind != "application/dns-message":
                raise ResolutionError(
                    "%s answered %s, not application/dns-message"
                    % (url, kind or "nothing")
                )
            return response.read()
    except urllib.error.HTTPError as exc:
        raise ResolutionError("%s answered HTTP %d" % (url, exc.code)) from exc
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(exc, _socket.timeout) or isinstance(reason, _socket.timeout):
            raise ResolutionTimeoutError("%s: %s" % (url, reason)) from exc
        raise ResolutionError("%s: %s" % (url, reason)) from exc


@overload
def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: "Literal['a', 'A']",
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
) -> "List[IPv4Address]": ...


@overload
def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: "Literal['aaaa', 'AAAA']",
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
) -> "List[IPv6Address]": ...


@overload
def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: "Literal['ptr', 'PTR']",
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
) -> "List[str]": ...


@overload
def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
) -> "List[Any]": ...


def resolve_doh(
    query: "HostLike",
    url: str,
    *,
    rdtype: Optional[str] = None,
    timeout: Optional[float] = 5.0,
    fetch: "Optional[Callable[[str, bytes, dict, Optional[float]], bytes]]" = None,
) -> "List[Any]":
    """Resolve ``query`` with DNS over HTTPS (RFC 8484): the DNS message
    POSTed to ``url`` as ``application/dns-message``.

    ::

        resolve_doh("example.com", "https://cloudflare-dns.com/dns-query")

    :param fetch: ``fetch(url, body, headers, timeout) -> bytes`` sends the
        request -- so a caller with its own HTTP stack (a proxy, a CA bundle)
        uses it. ``None``: :mod:`urllib.request`. An ``OSError`` or
        ``ValueError`` from it is a :class:`ResolutionError`.
    :param rdtype: as :func:`resolve_wire`.

    Contract as the other backends: native values, ``[]`` for NXDOMAIN or no
    record of the type, :class:`ResolutionError` when the endpoint could not
    be asked or answered something else (:class:`ResolutionTimeoutError` on a
    timeout), with an unreadable reply as the error's ``__cause__``
    (:class:`DNSDecodeError`). A ``query`` the codec cannot encode (an empty or
    over-long label) raises :class:`DNSDecodeError` itself, before anything is
    sent. Not part of :func:`resolve`'s chain.
    """
    query = _dst_argument(query)
    name, rdtype = _question(query, rdtype)
    payload = _dnswire.build_query(name, rdtype, 0)
    headers = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
    }
    try:
        body = (fetch or _urllib_fetch)(url, payload, headers, timeout)
        reply = _dnswire.parse_response(body, 0)
    except ResolutionError:
        raise
    except _socket.timeout as exc:
        raise ResolutionTimeoutError("DNS over HTTPS via %s: %s" % (url, exc)) from exc
    except (OSError, ValueError) as exc:
        raise ResolutionError("DNS over HTTPS via %s: %s" % (url, exc)) from exc
    if reply.rcode == _dnswire.NXDOMAIN:
        return []
    if reply.rcode != _dnswire.NOERROR:
        raise ResolutionError("%s answered rcode %d" % (url, reply.rcode))
    return reply.records(name, rdtype)
