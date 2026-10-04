"""``resolve_nslookup``: the ``nslookup`` binary, parsed from its text output."""

from __future__ import annotations

from typing import Any, List, Literal, Optional, Union, overload
from .. import _proc
from .._exceptions import NetimpsValueError, ResolutionError, ResolutionTimeoutError
from .._ip import HostLike, IPv4Address, IPv6Address, _dst_argument
from .._parse import try_parse
from ._common import _auto_rdtype, _budget, _nameservers, search_candidates

#: What `nslookup` gives as the reason after the colon of a "can't find <name>:
#: <reason>" line when the server answered that there is no such name or no
#: record of the type. Every other reason (SERVFAIL, REFUSED, "No response from
#: server") is a server that could not be asked, which stays a ResolutionError
#: so the chain moves on.
_NSLOOKUP_NO_RECORD_REASONS = (
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
      where it keeps only the first address.
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


def _check_nslookup_query(query: str, role: str = "query") -> None:
    """Raise :class:`ValueError` unless ``query`` can only be read as a name.

    ``role`` names what is being checked in the message: the query, the
    nameserver or a search domain all reach ``nslookup`` as arguments.

    ``nslookup`` has **no ``--`` end-of-options separator**, so a ``query``
    starting with ``-`` cannot be escaped into position: the binary parses it
    as an option, finds no name argument, and drops into *interactive* mode --
    where it reads names to look up from **stdin**. Measured: that drained the
    calling program's stdin and sent each line to the configured nameserver as
    a DNS query name. The subprocess gets :data:`subprocess.DEVNULL` for stdin
    (the right default for anything a library spawns), which closes the
    exfiltration, but a leading ``-`` is still rejected rather than escaped --
    there is nowhere safe to put it, and a lookup that silently became an
    option is not a lookup.

    Whitespace, control characters and an empty query get the same treatment:
    none can occur in a name any resolver would accept, and an empty argument
    reaches interactive mode by the same route.
    """
    if not query.strip():
        raise NetimpsValueError("%s must be a non-empty hostname or address" % (role,))
    if query.startswith("-"):
        raise NetimpsValueError(
            "refusing %s %r: a leading '-' is read as an nslookup "
            "option, not a name, and nslookup has no '--' separator to "
            "escape it with" % (role, query)
        )
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in query):
        raise NetimpsValueError(
            "refusing %s %r: a hostname or address cannot contain "
            "whitespace or control characters" % (role, query)
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
        limit = _budget(_NSLOOKUP_LIMIT_SECONDS if timeout is None else timeout)
        assert limit is not None
        response = _proc.run(cmd[0], cmd[1:], timeout=limit)
    except TimeoutError as exc:
        raise ResolutionTimeoutError("nslookup timed out: %s" % (exc,)) from exc
    except OSError as exc:
        raise ResolutionError("nslookup unavailable: %s" % (exc,)) from exc

    text = response.stdout
    stderr_text = response.stderr
    # Windows nslookup prints "*** <server> can't find <name>: Non-existent
    # domain" on stderr, not stdout -- the check has to see both, or a genuine
    # "no such name" looks like an unparseable answer. The reason after the
    # colon decides: "No response from server" shares the "can't find" prefix
    # and exits 0 as well.
    combined = text + "\n" + stderr_text
    for line in combined.splitlines():
        if "can't find" not in line.lower():
            continue
        reason = line.rpartition(":")[2].strip() if ":" in line else ""
        if not reason or any(
            marker in reason.lower() for marker in _NSLOOKUP_NO_RECORD_REASONS
        ):
            # A stated "no such name"/"no records", whatever the exit status --
            # BIND's nslookup exits 1 on NXDOMAIN, Windows' exits 0.
            return []
        raise ResolutionError("nslookup could not ask about %r: %s" % (query, reason))
    lowered = combined.lower()
    if any(marker in lowered for marker in _NSLOOKUP_NO_RECORD_REASONS):
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

    A server answering "no such name" or "no such record" (NXDOMAIN or
    equivalent, for every candidate tried) yields ``[]``. A missing
    ``nslookup`` binary, a timeout, a **non-zero exit with no "can't find"
    line** (no reachable server, a refused connection), a "can't find" line
    whose reason after the colon is not a "no such name" answer (``SERVFAIL``,
    ``REFUSED``, Windows' ``No response from server``), or an unsupported
    ``rdtype`` raises :class:`ResolutionError` -- there was no definitive DNS
    answer to report, so :func:`resolve`'s chain moves on rather than treating
    it as NXDOMAIN.

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
    if ns:
        _check_nslookup_query(ns, "nameserver")
        host, number = _nameservers([ns], 53, names=True)[0]
        if number != 53:
            raise NetimpsValueError(
                "nslookup cannot ask nameserver %r on port %d: it has no "
                "per-call port; use resolve_wire or resolve_dnspython with "
                "port=" % (ns, number)
            )
        ns = host
    if isinstance(search, (list, tuple)):
        for domain in search:
            if domain.strip("."):
                _check_nslookup_query(domain, "search domain")
    if not rdtype:
        rdtype = _auto_rdtype(query)
    rdtype = rdtype.lower()
    if rdtype not in ("a", "aaaa", "ptr"):
        raise ResolutionError(
            "resolve_nslookup only supports rdtype in ('a', 'aaaa', 'ptr'), got %r"
            % (rdtype,)
        )

    candidates = (
        [query]
        if rdtype == "ptr"
        else search_candidates(query, search, system_domains=True)
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
