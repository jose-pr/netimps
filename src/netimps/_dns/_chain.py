"""``resolve``: the backend chain, its deadline and its cache."""

from __future__ import annotations

import time as _time
from functools import partial as _partial
from typing import Any, Callable, List, Literal, Optional, Tuple, Union, overload
from .. import _dnswire
from .._exceptions import ResolutionError
from .._ip import HostLike, IPv4Address, IPv6Address, _dst_argument
from ._cache import RESOLUTION_CACHE_TTL, _cache_get, _cache_key, _cache_put
from ._common import (
    _DEADLINE,
    _NEEDS_DNS,
    _address_rdtypes,
    _auto_rdtype,
    _budget,
    _is_doh_server,
    _nameservers,
    _ns_entries,
)
from ._dnspython import has_dns, resolve_dnspython
from ._nslookup import resolve_nslookup
from ._system import resolve_system
from ._wire import resolve_wire

#: Backends `resolve()` tries, in order, by name. Each entry is looked up on
#: this module, so the order is the single source of truth for the chain.
_BACKENDS = ("dnspython", "wire", "system", "nslookup")


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
    deadline: Optional[float] = None,
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
    deadline: Optional[float] = None,
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
    deadline: Optional[float] = None,
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
    deadline: Optional[float] = None,
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
    deadline: Optional[float] = None,
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
        *of* an address makes no sense), ``"a"`` otherwise. Pass an explicit
        ``rdtype``
        to opt out. ``"a"``/``"aaaa"``/``"ptr"`` reach every backend; other
        types are ``dnspython``-only (see :func:`resolve_dnspython`).
        ``("a", "aaaa")`` asks for both families at once: the OS resolver
        answers in one call, in the order it chose, and every other backend
        is asked for ``"a"`` and then ``"aaaa"`` with the answers joined.
    :param ns: nameserver(s) to query instead of the system resolver. Honoured
        by ``dnspython`` and ``nslookup`` (a single nameserver for the
        latter); excludes ``system`` from the chain, since it cannot honour a
        per-call nameserver.
    :param timeout: seconds for one backend attempt. What it bounds differs by
        backend: for ``dnspython`` and ``wire`` the whole backend call, every
        nameserver and retry included; for ``system`` and ``nslookup`` each
        candidate name of a search list. A record-type pair is one attempt per
        type.
    :param deadline: seconds for the **whole call**: every backend, record type
        and search candidate shares it, and each attempt gets ``timeout`` or
        what is left, whichever is smaller. ``None`` (the default) sets no
        overall limit. Once it has passed the remaining backends are not
        started; the outcome is ``[]``, or with ``strict=True`` the
        :class:`ResolutionTimeoutError`.
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

    Contract: always a ``list``, **empty** when the backends answered that there
    is no such name or record or, without ``strict``, when none could be asked;
    never ``None``. ``strict=True`` is the only way this raises for a resolver
    outage. A request only ``dnspython`` could serve raises
    :class:`ResolutionError` naming the ``dns`` extra when it is missing, strict
    or not. A malformed query or unknown record type raises
    :class:`ValueError` immediately, without trying every backend, since that
    is a caller bug rather than a resolution outcome.
    """
    query = _dst_argument(query)
    if cache is not False:
        key = _cache_key(
            query, rdtype, ns, timeout, port, tcp, search, backends, strict, source
        )
        ttl = RESOLUTION_CACHE_TTL if cache is True else float(cache)
        hit = _cache_get(key, ttl)
        if hit is not None:
            return list(hit)
    # An enclosing deadline stays in force; this call's own can only shorten it.
    outer = _DEADLINE.get()
    end = None if deadline is None else _time.monotonic() + deadline
    if end is None or (outer is not None and outer < end):
        end = outer
    token = _DEADLINE.set(end)
    try:
        result, definitive = _resolve_chain(
            query, rdtype, ns, timeout, port, tcp, search, backends, strict, source
        )
    finally:
        _DEADLINE.reset(token)
    if cache is not False and definitive:
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

    # Parsed once, with the parser every backend uses, so a malformed
    # spelling fails the same way on every install. An https:// entry is a
    # dnspython-only DoH server and is left to it.
    parsed = _nameservers(
        [e for e in _ns_entries(ns) if not _is_doh_server(e)], 53, names=True
    )
    other_port = any(number != 53 for _host, number in parsed)

    last_error: Optional[Exception] = None
    attempted = False
    dns_missing = False  # dnspython was skipped because the extra is absent
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
            if not has_dns():
                dns_missing = True
                continue
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
            if rdtype not in ("a", "aaaa", "ptr") or source or other_port:
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
            _budget(None)  # a passed deadline ends the chain
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

    if not attempted and dns_missing:
        # Only dnspython could have served this request: say what to install
        # rather than answering "no records" for a backend that never ran.
        raise ResolutionError(_NEEDS_DNS)
    if not attempted:
        # Name what excluded them: with `port=`/`tcp=` excluding `system`
        # too, "cannot serve rdtype='a'" on its own would be a puzzle.
        excluded = []
        if ns:
            excluded.append("an explicit ns")
        if port != 53:
            excluded.append("port=%r" % (port,))
        if other_port:
            excluded.append("a nameserver port")
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
    # `if not resolve(host):` expects, and because the distinction
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
