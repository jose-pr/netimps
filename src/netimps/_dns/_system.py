"""``resolve_system``: the OS resolver, with a wall-clock bound on every call."""

from __future__ import annotations

import socket as _socket
from functools import partial as _partial
from typing import Any, Callable, List, Literal, Optional, Tuple, Union, overload
from .._exceptions import ResolutionError, ResolutionTimeoutError
from .._ip import HostLike, IPv4Address, IPv6Address, _dst_argument
from .._parse import try_parse
from ._common import (
    _ADDRESS_RDTYPES,
    _address_rdtypes,
    _auto_rdtype,
    _budget,
    _family_of,
    search_candidates,
)


def _bounded_lookup(lookup: "Callable[[], Any]", timeout: Optional[float]) -> "Any":
    """Run ``lookup`` under a wall-clock deadline (unbounded if ``timeout`` is
    ``None``), returning its result.

    **One mechanism for every record type.** :func:`socket.getaddrinfo` and
    :func:`socket.gethostbyaddr` are both blocking C calls with no timeout of
    their own, so both need this: called directly on the calling thread,
    ``gethostbyaddr`` was measured at 4.6s against a 0.1s deadline.

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
    timeout = _budget(timeout)
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


#: ``getaddrinfo`` codes that say the resolver answered and there is no such
#: name or no address of the family. 11004 is Windows' ``WSANO_DATA``. Any other
#: code (``EAI_AGAIN``, ``EAI_FAIL``, ...) is a resolver that could not be asked.
_NO_ANSWER_GAI = frozenset(
    code
    for code in (
        _socket.EAI_NONAME,
        getattr(_socket, "EAI_NODATA", None),
        getattr(_socket, "EAI_ADDRFAMILY", None),
        11004,
    )
    if code is not None
)


#: ``gethostbyaddr`` codes for the same two answers: ``HOST_NOT_FOUND`` and
#: ``NO_DATA`` (1 and 4), and their Winsock spellings.
_NO_ANSWER_HERROR = frozenset((1, 4, 11001, 11004))


def _system_outage(exc: "OSError", query: str) -> "ResolutionError":
    """The error for a failed OS lookup that was not an answer of "no such record"."""
    return ResolutionError("the OS resolver could not look up %r: %s" % (query, exc))


def _is_no_answer(exc: "OSError") -> bool:
    if isinstance(exc, _socket.gaierror):
        return exc.errno in _NO_ANSWER_GAI
    if isinstance(exc, _socket.herror):
        return exc.errno in _NO_ANSWER_HERROR
    return False


def _resolve_system_once(
    query: str, family: int, timeout: Optional[float]
) -> "List[Any]":

    def _lookup():
        return _socket.getaddrinfo(query, None, family=family, type=_socket.SOCK_STREAM)

    try:
        infos = _bounded_lookup(_lookup, timeout)
    except _socket.gaierror as exc:
        if _is_no_answer(exc):
            return []
        raise _system_outage(exc, query) from exc

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

    Every candidate tried and none resolving (``EAI_NONAME``, no data) yields
    ``[]``, never ``None``. A temporary failure (``EAI_AGAIN``, ``EAI_FAIL``)
    raises :class:`ResolutionError`, and a deadline
    :class:`ResolutionTimeoutError`: the resolver could not be asked. An
    unsupported ``rdtype`` raises :class:`ResolutionError` too, since that is
    this backend's fixed limitation, not a DNS outcome to report as "no records".
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
        # gethostbyaddr has no timeout of its own either, so calling it
        # directly would ignore `timeout` outright.
        try:
            hostname, _aliases, _addrs = _bounded_lookup(
                _partial(_socket.gethostbyaddr, query), timeout
            )
        except (_socket.herror, _socket.gaierror) as exc:
            # herror: no PTR data for a literal address. gaierror: `query`
            # was treated as a hostname (gethostbyaddr's own behaviour for a
            # non-literal argument) and that hostname itself did not resolve.
            # Both are answers when the code says so; a temporary failure is not.
            if _is_no_answer(exc):
                return []
            raise _system_outage(exc, query) from exc
        return [hostname]

    if rdtype not in _ADDRESS_RDTYPES:
        raise ResolutionError(
            "resolve_system only supports rdtype in %r, got %r"
            % (_ADDRESS_RDTYPES + ("ptr",), rdtype)
        )

    return _search_system(query, _family_of(rdtype), timeout, search)


def _search_system(
    query: str,
    family: int,
    timeout: Optional[float],
    search: "Union[bool, List[str]]",
) -> "List[Any]":
    """The candidates ``search`` implies for ``query``, each asked of the OS
    resolver for ``family``, until one has an answer."""
    candidates = search_candidates(query, search)

    for candidate in candidates:
        result = _resolve_system_once(candidate, family, timeout)
        if result:
            return result
    return []
