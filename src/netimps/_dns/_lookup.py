"""The adapters ``Host`` and ``FQDN`` resolve through."""

from __future__ import annotations

import ipaddress as _ipaddress
from typing import Any, List, Optional, Tuple, Union
from .._exceptions import NoAnswerError
from ._chain import resolve


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
    deadline: "Optional[float]",
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
        deadline=deadline,
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
    deadline: "Optional[float]" = None,
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
        deadline=deadline,
    )
    for answer in answers:
        if isinstance(answer, (_ipaddress.IPv4Address, _ipaddress.IPv6Address)):
            return answer
    if check:
        raise NoAnswerError("%s has no address record" % (name,))
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
    deadline: "Optional[float]" = None,
) -> "Optional[Any]":
    """The name ``address`` reverses to, as an ``FQDN`` without its root dot, or
    ``None`` (internal; ``address`` is a literal)."""
    from .._fqdn import FQDN

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
        deadline=deadline,
    )
    for answer in answers:
        name = FQDN.try_parse(str(answer))
        if name is not None:
            return name
    if check:
        raise NoAnswerError("%s has no reverse name" % (address,))
    return None
