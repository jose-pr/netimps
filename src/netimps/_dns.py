"""DNS resolution (internal).

Three independently callable backends, each with the same
list-of-native-values-or-[]-on-failure contract, plus :func:`resolve` which
tries them in order and returns the first that produces a definitive answer:

- :func:`resolve_dnspython` -- ``dnspython``, structured records, every
  ``rdtype``, explicit ``ns=``/``port=``/``search=`` control.
- :func:`resolve_system` -- :func:`socket.getaddrinfo`, the OS resolver
  (hosts file, NSS, DNS). Address records (``a``/``aaaa``) only, no ``ns=``
  control -- it always asks the OS resolver, whatever that is configured to
  use.
- :func:`resolve_nslookup` -- shells out to the ``nslookup`` binary. Address
  records (``a``/``aaaa``/``ptr``) only, parsed from text output.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import socket as _socket
from subprocess import TimeoutExpired as _SubprocessTimeout
from subprocess import run as _run
from typing import Any, List, Optional, Union

__all__ = [
    "resolve",
    "resolve_dnspython",
    "resolve_system",
    "resolve_nslookup",
]

#: Backends `resolve()` tries, in order, by name. Each entry is looked up on
#: this module, so the order is the single source of truth for the chain.
_BACKENDS = ("dnspython", "system", "nslookup")

_ADDRESS_RDTYPES = ("a", "aaaa")


class ResolutionError(Exception):
    """A backend could not even attempt the query (missing binary, unsupported
    ``rdtype``, transport/setup failure). Distinct from a definitive DNS
    answer of "no such record", which is `[]`, not an exception.
    """


def _native_record(record):
    """Convert a dnspython record to a native Python value.

    Address records become :mod:`ipaddress` objects, so a caller can compare
    and do membership tests without re-parsing. Everything else stays a
    ``str``, with the trailing root dot stripped from names and the quotes
    stripped from TXT strings -- the forms callers actually want.
    """
    text = str(record)
    from . import try_parse

    address = try_parse(text)
    if address is not None:
        return address
    if len(text) > 1 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]  # TXT records arrive quoted
    if text.endswith(".") and not text.endswith(".."):
        return text[:-1]  # names are fully qualified with a root dot
    return text


def resolve_dnspython(
    query: str,
    rdtype: str = "a",
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
) -> "List[Any]":
    """Resolve ``query`` via ``dnspython`` and return the answers as a list.

    ::

        resolve_dnspython("example.com")                    # ['93.184.216.34']
        resolve_dnspython("example.com", "aaaa")
        resolve_dnspython("example.com", "mx", ns="1.1.1.1")
        resolve_dnspython("host")                           # tries the resolv.conf search list
        resolve_dnspython("host", search=["eng.example.com", "example.com"])
        resolve_dnspython("host", search=False)             # look up "host" literally

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

    :param query: the name (or address, for reverse types) to look up.
    :param rdtype: DNS record type (``"a"``, ``"aaaa"``, ``"mx"`` ...). Second
        because it is the argument callers actually vary.
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

    A genuine lookup failure (NXDOMAIN, no answer, timeout, all servers failed)
    yields ``[]``; a malformed query or unknown record type raises
    :class:`ValueError`, since that is a caller bug rather than a DNS result.

    Requires the ``dnspython`` package (installed with ``netimps``).
    """
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

    try:
        answer = r.resolve(query, rdtype, tcp=tcp, search=search)
    except _lookup_failures:
        # A genuine "no result" -- the documented [] contract.
        return []
    except Exception as exc:
        # Everything else (malformed name, unknown rdtype) is a caller bug
        # rather than a lookup outcome. The old code swallowed these into [],
        # which turned a typo'd record type into a silent empty result.
        raise ValueError("invalid DNS query %r (%s): %s" % (query, rdtype, exc))
    return [_native_record(record) for record in answer]


def _resolve_system_once(
    query: str, family: int, timeout: Optional[float]
) -> "List[Any]":
    from . import try_parse as _try_parse

    def _lookup():
        return _socket.getaddrinfo(query, None, family=family, type=_socket.SOCK_STREAM)

    if timeout is None:
        try:
            infos = _lookup()
        except _socket.gaierror:
            return []
    else:
        import concurrent.futures as _futures

        with _futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_lookup)
            try:
                infos = future.result(timeout=timeout)
            except _socket.gaierror:
                return []
            except _futures.TimeoutError as exc:
                raise ResolutionError(
                    "resolve_system timed out after %.1fs" % (timeout,)
                ) from exc

    seen = []
    for info in infos:
        address = info[4][0]
        parsed = _try_parse(address)
        if parsed is not None and parsed not in seen:
            seen.append(parsed)
    return seen


def resolve_system(
    query: str,
    rdtype: str = "a",
    timeout: Optional[float] = 5.0,
    search: Union[bool, List[str]] = True,
) -> "List[Any]":
    """Resolve ``query`` via the OS resolver (:func:`socket.getaddrinfo`).

    ::

        resolve_system("example.com")           # ['93.184.216.34']
        resolve_system("example.com", "aaaa")
        resolve_system("localhost")              # /etc/hosts, no DNS query
        resolve_system("host", search=False)     # "host" only, no suffix expansion
        resolve_system("host", search=["eng.example.com", "example.com"])

    Goes through **hosts file, NSS (`nsswitch.conf`) and DNS, in the order
    the OS resolver applies them** -- the same path ``getaddrinfo(3)``-based
    tools use. Unlike :func:`resolve_dnspython`, this sees ``/etc/hosts``
    entries, ``nsswitch.conf`` sources (mDNS, LDAP, whatever NSS is
    configured with) and any OS-level resolver cache.

    The trade-off: **address records only** (``rdtype`` must be ``"a"`` or
    ``"aaaa"``; anything else raises :class:`ResolutionError` immediately, no
    query attempted), no ``ns=`` (it always asks whatever resolver the OS is
    configured with -- there is no per-call override), and no priority/TTL/
    other record metadata, since :func:`socket.getaddrinfo` does not expose
    any of that.

    :param query: the hostname to look up.
    :param rdtype: ``"a"`` (default) or ``"aaaa"``. Anything else raises.
    :param timeout: seconds to wait *per candidate name tried* (see
        ``search``). There is no native per-call timeout for
        ``getaddrinfo``, so each attempt runs in a helper thread and is
        abandoned (without cancelling the underlying blocking call) past the
        deadline. ``None`` waits indefinitely.
    :param search: how to expand an unqualified ``query``. There is no
        per-call search-list override on :func:`socket.getaddrinfo` itself --
        unlike ``dnspython``/``nslookup``, the OS resolver takes no such
        parameter -- so ``search=True`` (default) simply leaves ``query`` as
        given and lets the OS resolver apply its own configured search list
        (glibc's ``ndots``/``search``, the Windows per-adapter DNS suffix).
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
    rdtype = (rdtype or "a").lower()
    if rdtype not in _ADDRESS_RDTYPES:
        raise ResolutionError(
            "resolve_system only supports rdtype in %r, got %r"
            % (_ADDRESS_RDTYPES, rdtype)
        )

    family = _socket.AF_INET6 if rdtype == "aaaa" else _socket.AF_INET

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
    from . import try_parse as _try_parse

    lines = text.splitlines()
    # nslookup prints the query's own resolver ("Server:", "Address:") first,
    # then a blank line, then the answer section -- only the answer section
    # names actual records for `query`.
    if "" in lines:
        lines = lines[lines.index("") + 1 :]

    saw_answer = any(line.strip().lower().startswith("name:") for line in lines)

    results = []
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
        parsed = _try_parse(value)
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
        response = _run(cmd, capture_output=True, timeout=timeout)
    except (OSError, _SubprocessTimeout) as exc:
        raise ResolutionError("nslookup unavailable or timed out: %s" % (exc,)) from exc

    text = (response.stdout or b"").decode("utf-8", "replace")
    stderr_text = (response.stderr or b"").decode("utf-8", "replace")
    # Windows nslookup prints "*** <server> can't find <name>: Non-existent
    # domain" on stderr, not stdout -- the NXDOMAIN marker check has to see
    # both, or a genuine "no such name" looks like an unparseable answer.
    lowered = (text + "\n" + stderr_text).lower()

    if response.returncode != 0 or any(
        marker in lowered for marker in _NSLOOKUP_NO_RECORD_MARKERS
    ):
        return []

    results, saw_answer = _parse_nslookup_output(text, rdtype)
    if not results and not saw_answer:
        # Nonzero-looking success but nothing parsed, and not even a "Name:"
        # line to say NODATA -- an nslookup output shape this parser does
        # not recognise, not a definitive "no record".
        raise ResolutionError("could not parse nslookup output for %r" % (query,))
    return results


def resolve_nslookup(
    query: str,
    rdtype: str = "a",
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

    A fallback for when neither ``dnspython`` nor :func:`resolve_system` is
    usable: goes through whatever resolver ``nslookup`` itself is configured
    to use (the OS resolver's nameservers, unless ``ns=`` overrides it).

    :param query: the name (or address, for ``ptr``) to look up.
    :param rdtype: ``"a"`` (default), ``"aaaa"`` or ``"ptr"``. Anything else
        raises :class:`ResolutionError` immediately, no subprocess spawned --
        ``nslookup``'s plain-text output is only parsed reliably for these.
    :param ns: nameserver to query, passed as ``nslookup``'s trailing
        ``server`` argument. ``None`` uses ``nslookup``'s own default.
    :param timeout: seconds to allow *each* subprocess attempt to run --
        one per candidate name tried under ``search``. ``None`` waits
        indefinitely.
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
    tried) yields ``[]``. A missing ``nslookup`` binary, a timeout, or an
    unsupported ``rdtype`` raises :class:`ResolutionError` -- there was no
    definitive DNS answer to report.
    """
    rdtype = (rdtype or "a").lower()
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


def resolve(
    query: str,
    rdtype: str = "a",
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    backends: "Optional[Union[str, List[str]]]" = None,
) -> "List[Any]":
    """Resolve ``query``, trying each backend in ``backends`` until one gives
    a definitive answer.

    ::

        resolve("example.com")                    # ['93.184.216.34']
        resolve("example.com", "aaaa")
        resolve("example.com", "mx", ns="1.1.1.1")
        resolve("host", backends="system")        # OS resolver only
        resolve("host", backends=["nslookup", "dnspython"])  # custom order

    Default order is ``["dnspython", "system", "nslookup"]``: dnspython first
    (structured records, full ``rdtype`` support, explicit ``ns=``/``search=``
    control), then the OS resolver (hosts file, NSS, OS cache -- but address
    records only, and no ``ns=`` override), then ``nslookup`` as a last resort
    if neither Python-level path is usable.

    A backend is **skipped**, not tried and failed, when it structurally
    cannot serve the request: :func:`resolve_system` for a non-address
    ``rdtype``, or for an explicit ``ns=``/``port=`` (it has no per-call
    nameserver override, so running it would silently ignore the caller's
    choice); :func:`resolve_dnspython` if ``dnspython`` is not installed.

    A backend that reaches a resolver and gets a **definitive DNS answer**
    (records, or a genuine NXDOMAIN/empty) stops the chain there -- including
    when that answer is ``[]``. Only a backend that could not even attempt the
    query (missing binary, timeout, transport failure) falls through to the
    next one. If every applicable backend fails that way, the last such error
    is raised.

    :param query: the name (or address, for reverse types) to look up.
    :param rdtype: DNS record type. ``"a"``/``"aaaa"`` reach every backend;
        other types are dnspython-only (see :func:`resolve_dnspython`) except
        ``"ptr"``, which nslookup also understands.
    :param ns: nameserver(s) to query instead of the system resolver. Honoured
        by ``dnspython`` and ``nslookup`` (a single nameserver for the
        latter); excludes ``system`` from the chain, since it cannot honour a
        per-call nameserver.
    :param timeout: seconds per backend attempt.
    :param port: nameserver port; ``dnspython`` only.
    :param tcp: query over TCP; ``dnspython`` only.
    :param search: search-list behaviour, honoured by all three backends (see
        :func:`resolve_dnspython`, :func:`resolve_system` and
        :func:`resolve_nslookup` respectively). Only ``dnspython`` has this
        built in; the other two try one candidate name per call instead.
    :param backends: explicit backend order/subset, by name (``"dnspython"``,
        ``"system"``, ``"nslookup"``) or a single name as a plain string.
        ``None`` (default) uses all three in the default order, each filtered
        for applicability as described above.

    Contract: always a ``list``, **empty** on a genuine lookup failure, never
    ``None``. A malformed query or unknown record type raises
    :class:`ValueError` immediately, without trying every backend, since that
    is a caller bug rather than a resolution outcome.
    """
    rdtype = (rdtype or "a").lower()
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
    for name in chain:
        if name == "system":
            if rdtype not in _ADDRESS_RDTYPES or ns:
                continue  # cannot honour a non-address rdtype or a custom ns
            attempted = True
            try:
                return resolve_system(query, rdtype, timeout=timeout, search=search)
            except ResolutionError as exc:
                last_error = exc
                continue
        elif name == "dnspython":
            attempted = True
            try:
                return resolve_dnspython(
                    query,
                    rdtype,
                    ns=ns,
                    timeout=timeout,
                    port=port,
                    tcp=tcp,
                    search=search,
                )
            except ResolutionError as exc:
                last_error = exc
                continue
        elif name == "nslookup":
            if rdtype not in ("a", "aaaa", "ptr"):
                continue
            single_ns = ns[0] if isinstance(ns, (list, tuple)) and ns else ns
            attempted = True
            try:
                return resolve_nslookup(
                    query, rdtype, ns=single_ns, timeout=timeout, search=search
                )
            except ResolutionError as exc:
                last_error = exc
                continue

    if not attempted:
        raise ValueError(
            "no backend in %r can serve rdtype=%r%s"
            % (chain, rdtype, " with an explicit ns" if ns else "")
        )
    assert last_error is not None
    raise last_error
