"""DNS resolution (internal).

Wraps ``dnspython`` behind one function with a predictable contract: a list of
native values, empty on a genuine lookup failure, and an exception only for a
caller mistake. Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

from typing import Any, List, Optional, Union

__all__ = ["resolve"]


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


def resolve(
    query: str,
    rdtype: str = "a",
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
) -> "List[Any]":
    """Resolve ``query`` via DNS and return the answers as a list of strings.

    ::

        resolve("example.com")                    # ['93.184.216.34']
        resolve("example.com", "aaaa")
        resolve("example.com", "mx", ns="1.1.1.1")

    Contract: always a ``list``, **empty** when the name does not resolve --
    never ``None``. Callers can therefore write ``if result:`` and index
    ``result[0]`` safely.

    Records come back as **native types**: address records (``A``/``AAAA``) are
    :class:`ipaddress` objects, everything else is a ``str``::

        resolve("example.com")[0].is_private     # an IPv4Address, not "1.2.3.4"
        resolve("example.com", "mx")             # ['10 mail.example.com']
        resolve("example.com", "txt")            # ['v=spf1 -all']  -- unquoted

    Names lose their trailing root dot and TXT strings lose their surrounding
    quotes, since neither is wanted in practice.

    :param query: the name (or address, for reverse types) to look up.
    :param rdtype: DNS record type (``"a"``, ``"aaaa"``, ``"mx"`` ...). Second
        because it is the argument callers actually vary.
    :param ns: optional nameserver, or list of nameservers, to query instead of
        the system resolver.
    :param timeout: seconds to spend on the whole resolution, retries included
        (``None`` for dnspython's default). Bounds *total* time, not each query
        -- a list of unreachable nameservers cannot stretch past it.
    :param port: nameserver port, for resolvers not on 53.
    :param tcp: query over TCP instead of UDP. Useful for large responses that
        would otherwise be truncated.

    A genuine lookup failure (NXDOMAIN, no answer, timeout, all servers failed)
    yields ``[]``; a malformed query or unknown record type raises
    :class:`ValueError`, since that is a caller bug rather than a DNS result.

    Requires the ``dnspython`` package (installed with ``netimps``).
    """
    from dns import resolver as _resolver

    r = _resolver.Resolver(configure=not ns)
    if isinstance(ns, str):
        ns = [ns]
    if ns:
        r.nameservers = list(ns)
    if port != 53:
        r.port = port
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
        answer = r.resolve(query, rdtype, tcp=tcp)
    except _lookup_failures:
        # A genuine "no result" -- the documented [] contract.
        return []
    except Exception as exc:
        # Everything else (malformed name, unknown rdtype) is a caller bug
        # rather than a lookup outcome. The old code swallowed these into [],
        # which turned a typo'd record type into a silent empty result.
        raise ValueError("invalid DNS query %r (%s): %s" % (query, rdtype, exc))
    return [_native_record(record) for record in answer]


def _source_argument(source, want_ipv6: bool = False) -> Optional[str]:
    """Coerce a source spec to the address string ``ping`` needs.

    Accepts an :class:`Interface`, an address object, or a string. Interfaces
    are reduced to an address because Windows ``-S`` will not take an adapter
    name; ``None`` means "nothing usable here", which the caller must treat as
    a failure rather than silently omitting the flag.
    """
    # A MAC identifies an adapter, so look up which one carries it. Unknown
    # MACs are None ("no such interface"), never a silent fallback.
    if isinstance(source, MACAddress) or (
        isinstance(source, str) and is_valid(source, MACAddress)
    ):
        wanted = MACAddress(source)
        source = next(
            (iface for iface in get_interfaces() if iface.mac == wanted), None
        )
        if source is None:
            return None

    if isinstance(source, Interface):
        candidates = source.ipv6 if want_ipv6 else source.ipv4
        for entry in candidates:
            if not entry.ip.is_loopback:
                return str(entry.ip)
        # Fall back to a loopback address if that is genuinely all it has.
        return str(candidates[0].ip) if candidates else None

    text = str(source).strip()
    return text or None
