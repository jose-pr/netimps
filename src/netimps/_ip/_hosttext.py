"""Host text: ``split_host``, ``split_zone`` and ``join_host``, IPv6-aware."""

from __future__ import annotations

from typing import Any, Optional, Tuple, Union
from .._exceptions import NetimpsValueError
from .._scheme import coerce_port
from ipaddress import IPv6Address
from ._host import HostLike, _host_text


def split_zone(text: "HostLike") -> "Tuple[str, Optional[str]]":
    """Split an IPv6 ``%zone`` suffix off a host: ``(host, zone)``.

    ::

        split_zone("fe80::1%eth0")   # ('fe80::1', 'eth0')
        split_zone("fe80::1%12")     # ('fe80::1', '12')
        split_zone("10.0.0.5")       # ('10.0.0.5', None)
        split_zone("example.com")    # ('example.com', None)

    Use it before :func:`try_parse` or an address comparison: ``ipaddress`` keeps
    the zone as part of the address, so ``fe80::1%eth0`` is not equal to
    ``fe80::1`` and matches nothing in :func:`get_interfaces`. The zone names an
    *interface*, which is why it is returned rather than thrown away. Brackets are
    :func:`split_host`'s business, not this function's.

    ``text`` takes the package's loose host union. Raises :class:`TypeError`
    for a value that is not a host type, and :class:`NetimpsValueError` for a
    ``%`` with nothing after it.
    """
    value = _host_text(text)
    host, sep, zone = value.partition("%")
    if not sep:
        return value, None
    if not zone:
        raise NetimpsValueError("empty zone after '%%' in %r" % (value,))
    return host, zone


def split_host(
    text: "Union[HostLike, Tuple[HostLike, Optional[int]]]",
    *,
    default_port: Optional[int] = None,
) -> "Tuple[str, Optional[int]]":
    """Split ``"host:port"`` into ``(host, port)``, handling IPv6 brackets.

    The parsing that looks trivial until IPv6 arrives, because a bare v6
    address is *full of colons*::

        split_host("example.com:8080")     # ('example.com', 8080)
        split_host("10.0.0.5")             # ('10.0.0.5', None)
        split_host("[::1]:8080")           # ('::1', 8080)
        split_host("::1")                  # ('::1', None)   -- not port 1
        split_host("example.com", 443)     # ('example.com', 443)

    The rule this implements: a bare IPv6 address must **not** be split on its
    last colon, and only a bracketed one may carry a port. ``"::1"`` is the
    address, never host ``"::"`` port ``1`` -- the mistake hand-rolled splitters
    almost always make.

    Brackets are stripped from the returned host, and a scope id is preserved
    (``"[fe80::1%eth0]:80"`` -> ``("fe80::1%eth0", 80)``). A bracketed literal
    with no port is the host alone: ``"[::1]"`` is ``("::1", None)``.
    ``default_port`` is used when no port is present.

    A ``(host, port)`` **pair** is taken too, with ``port`` an integer or
    ``None`` and ``default_port`` filling a ``None``::

        split_host(("example.com", None), default_port=69)   # ('example.com', 69)
        split_host(("[::1]", 80))                            # ('::1', 80)

    The host of a pair is split like any other, so a port written in both places
    is an error unless they agree.

    ``text`` accepts the package's usual loose union, not only a ``str``: an
    address object, an :class:`IPv4Interface`/:class:`IPv6Interface` (its ``.ip``
    is used), a :class:`Host` or an :class:`FQDN`, as :func:`join_host`, the
    inverse, does. A *network*, or a value that is not a host type at all
    (``None``, an ``int``, ``bytes``), raises :class:`TypeError`.

    Port text is ASCII digits, as RFC 3986 section 3.2.3 has it: ``"8_0"``,
    ``"+80"``, a space and non-ASCII digits are refused. What sits inside
    brackets has to be an IPv6 literal (section 3.2.2).

    Raises :class:`NetimpsValueError` on empty input, an unclosed bracket,
    brackets around anything but an IPv6 address, a port that is not ASCII digits
    in 0-65535, or an unbracketed string with two or more colons that is **not**
    a valid IPv6 address (``"host:80:extra"``, a half-typed address).
    """
    if isinstance(text, tuple):
        return _split_pair(text, default_port)
    text = _host_text(text)
    if not text.strip():
        raise NetimpsValueError("host must be a non-empty string, got %r" % (text,))
    text = text.strip()

    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise NetimpsValueError("unclosed '[' in %r" % (text,))
        host = text[1:end]
        if not _is_ipv6_literal(host):
            raise NetimpsValueError(
                "%r is bracketed but not an IPv6 address" % (text[: end + 1],)
            )
        rest = text[end + 1 :]
        if not rest:
            port = default_port
        elif rest.startswith(":"):
            port = _parse_port(rest[1:], text)
        else:
            raise NetimpsValueError("unexpected %r after ']' in %r" % (rest, text))
    elif text.count(":") > 1:
        # More than one colon and no brackets: a bare IPv6 address is the only
        # thing that can be, and splitting would turn "::1" into host "::"
        # port 1. Confirm it really parses rather than assuming: taking the
        # whole unparseable string as the host is a confident wrong answer the
        # caller cannot detect.
        if not _is_ipv6_literal(text):
            raise NetimpsValueError(
                "%r has several colons but is not an IPv6 address; "
                "bracket it as [host]:port if a port was meant" % (text,)
            )
        host, port = text, default_port
    elif ":" in text:
        host, _, raw_port = text.partition(":")
        port = _parse_port(raw_port, text)
    else:
        host, port = text, default_port

    if not host:
        raise NetimpsValueError("empty host in %r" % (text,))
    return host, port


def _split_pair(pair: "Tuple[Any, ...]", default_port: Optional[int]):
    """``split_host`` for a ``(host, port)`` pair."""
    if len(pair) != 2:
        raise NetimpsValueError(
            "a (host, port) pair has two items, got %d: %r" % (len(pair), pair)
        )
    raw_host, raw_port = pair
    host, inner = split_host(raw_host)
    if raw_port is None:
        return host, inner if inner is not None else default_port
    if isinstance(raw_port, str):
        port = _parse_port(raw_port, pair)
    else:
        port = _port_number(raw_port, pair)
    if inner is not None and inner != port:
        raise NetimpsValueError(
            "two ports for one host: %r in the host and %d beside it" % (inner, port)
        )
    return host, port


def _is_ipv6_literal(text: str) -> bool:
    """True if ``text`` is an IPv6 address, zone id and all.

    ``IPv6Address`` accepts a ``%zone`` suffix from Python 3.9 on, which is the
    floor here, so the scoped form needs no special casing.
    """
    try:
        IPv6Address(text)
    except ValueError:
        return False
    return True


def _port_number(port: object, original: object) -> int:
    """``port`` through :func:`netimps._scheme.coerce_port`, the one place a port
    is validated, with a range error as the package's value error."""
    try:
        return coerce_port(port)
    except TypeError:
        raise
    except ValueError as exc:
        raise NetimpsValueError("%s, in %r" % (exc, original)) from None


def _parse_port(raw: str, original: object) -> int:
    """Port text: ASCII digits only (RFC 3986 ``port = *DIGIT``), then the gate."""
    if not (raw.isascii() and raw.isdigit()):
        raise NetimpsValueError("invalid port %r in %r" % (raw, original))
    return _port_number(int(raw), original)


def join_host(host: "HostLike", port: "Optional[int]" = None) -> str:
    """Build ``"host:port"`` from its parts -- the inverse of :func:`split_host`.

    The direction everyone writes by hand and gets wrong on IPv6, because a bare
    v6 address is full of colons and must be bracketed before a port can be
    appended::

        join_host("example.com", 8080)     # 'example.com:8080'
        join_host("10.0.0.5", 8080)        # '10.0.0.5:8080'
        join_host("::1", 8080)             # '[::1]:8080'     -- not '::1:8080'
        join_host("fe80::1%eth0", 80)      # '[fe80::1%eth0]:80'
        join_host("::1")                   # '::1'            -- no port, no brackets
        join_host("example.com")           # 'example.com'

    ``host`` accepts a string, an :class:`IPv4Address`/:class:`IPv6Address`, an
    :class:`IPv4Interface`/:class:`IPv6Interface` (its ``.ip`` is used) or an
    :class:`FQDN`. An already-bracketed string is accepted and not
    double-bracketed.

    **Only an IPv6 *literal* is bracketed.** A hostname never is, however many
    colons someone has put in it -- brackets in a URI authority mean "the thing
    inside is an address", so bracketing a name would produce something no
    resolver will accept.

    Brackets are added when a port is present **or** absent, following the same
    rule: a lone ``"::1"`` needs none, since there is no colon to disambiguate
    from. That is what makes ``split_host(join_host(h, p)) == (h, p)`` hold.

    :raises TypeError: for a network, a value that is not a host type, or a
        ``port`` that is not an ``int`` (a ``bool`` is not one).
    :raises NetimpsValueError: for an empty host, brackets around anything but
        an IPv6 address, or a port outside 0-65535.
    """
    text = _host_text(host).strip()
    if not text:
        raise NetimpsValueError("host must not be empty")

    if text.startswith("[") or text.endswith("]"):
        # A mismatched bracket has to raise, not fall through: `"[::1"` is not an
        # IPv6 literal, so it would otherwise emerge unbracketed as `"[::1:80"`,
        # which is garbage the caller cannot detect. `split_host` rejects the
        # same input, and the pair must agree.
        if not (text.startswith("[") and text.endswith("]")):
            raise NetimpsValueError("mismatched brackets in %r" % (text,))
        # Already bracketed: validate the inside rather than trusting it, so a
        # malformed literal is caught here and not by the caller's resolver.
        if not _is_ipv6_literal(text[1:-1]):
            raise NetimpsValueError("%r is bracketed but not an IPv6 address" % (text,))
        text = text[1:-1]

    if _is_ipv6_literal(text):
        text = "[%s]" % (text,)

    if port is None:
        # Strip the brackets back off: with no port there is nothing to
        # disambiguate, and `split_host` returns the bare form, so keeping
        # them would break the round trip.
        return text[1:-1] if text.startswith("[") else text

    return "%s:%d" % (text, _port_number(port, port))
