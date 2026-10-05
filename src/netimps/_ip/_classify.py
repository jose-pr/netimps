"""Address classification: the named networks, scope, the v4-mapped form and the wildcard."""

from __future__ import annotations

import socket as _socket
from typing import Optional, Union
from .._fqdn import FQDN
from .._parse import parse
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from ._host import Host
from ._types import IPAddress, IPAddressLike, ip_literal


def _family_argument(family: object, *, required: bool = False) -> "Optional[int]":
    """``socket.AF_INET`` or ``socket.AF_INET6`` for a family spelled either way.

    A family is ``4`` or ``6``, or the platform's ``AF_INET``/``AF_INET6``
    (``AF_INET6`` is 10 on Linux, 23 on Windows and 30 on macOS, so it is never
    compared against a literal). ``None`` means "either" unless ``required``.

    :raises ValueError: for anything else, a ``bool`` and a misspelt family
        included, rather than answering about a family nobody asked for.
    """
    if family is None and not required:
        return None
    if isinstance(family, int) and not isinstance(family, bool):
        if family in (4, _socket.AF_INET):
            return _socket.AF_INET
        if family in (6, _socket.AF_INET6):
            return _socket.AF_INET6
    raise ValueError(
        "family must be 4, 6, socket.AF_INET or socket.AF_INET6%s, got %r"
        % ("" if required else " (or None)", family)
    )


def _required_family(family: object) -> int:
    """:func:`_family_argument` where ``None`` is not an answer."""
    resolved = _family_argument(family, required=True)
    assert resolved is not None
    return resolved


def _as_address(value: object) -> "IPAddress":
    """The address ``value`` stands for, for the classifiers.

    Takes what :data:`IPAddressLike` does, and an interface (its ``.ip``), a
    :class:`Host` or an :class:`FQDN` holding address text.

    :raises TypeError: for a network, or a value of any other type.
    :raises NetimpsValueError: for text that is no address.
    """
    # An interface first: ``IPv4Interface`` subclasses ``IPv4Address``, and
    # returned as such it would compare as address *and* network.
    if isinstance(value, (IPv4Interface, IPv6Interface)):
        return value.ip
    if isinstance(value, (IPv4Address, IPv6Address)):
        return value
    if isinstance(value, (IPv4Network, IPv6Network)):
        raise TypeError("expected an address, not a network (%r)" % (value,))
    if isinstance(value, (Host, FQDN)):
        value = str(value)
    if isinstance(value, bool) or not isinstance(value, (str, int, bytes)):
        raise TypeError(
            "expected an address (text, int, bytes or an address object), not %r"
            % (type(value).__name__,)
        )
    return parse(value, IPAddress)


def is_link_scoped(ip: "IPAddressLike") -> bool:
    """True if ``ip`` is confined to link scope or narrower.

    Covers loopback (``127/8``, ``::1`` -- host scope) and link-local
    (``169.254/16``, ``fe80::/10`` -- link scope), borrowing IPv6's scope
    vocabulary for both families::

        is_link_scoped(parse("127.0.0.1"))      # True  -- host scope
        is_link_scoped(parse("169.254.1.1"))    # True  -- link scope
        is_link_scoped(parse("10.0.0.5"))       # False -- private, global scope

    The shared practical property is that neither can usefully be routed off
    the local host or link, so proxying, forwarding or advertising such an
    address is always wrong. Keeping the definition in one place stops each
    caller from writing a subtly different version.

    .. note::
       This is **not** "is private". RFC 1918 ranges (``10/8``,
       ``192.168/16``) are globally *scoped* and routable within a site, so
       they return ``False`` -- use ``ip.is_private`` for that question.
    """
    address = unmap(_as_address(ip))
    return address.is_loopback or address.is_link_local


#: RFC 3927 link-local ("Automatic Private IP Addressing") -- what a host gives
#: itself when DHCP fails, so its presence usually means "no lease".
LINK_LOCAL_V4 = IPv4Network("169.254.0.0/16")


#: RFC 1122 loopback. Note this is the whole /8, not just 127.0.0.1.
LOOPBACK_V4 = IPv4Network("127.0.0.0/8")


#: The single IPv6 loopback address, as a network for symmetry.
LOOPBACK_V6 = IPv6Network("::1/128")


#: RFC 4291 IPv6 link-local.
LINK_LOCAL_V6 = IPv6Network("fe80::/10")


def unmap(value: "IPAddressLike") -> "IPAddress":
    """Collapse an IPv4-mapped IPv6 address to plain IPv4; pass anything else through.

    ``::ffff:10.0.0.5`` is how a dual-stack socket reports an IPv4 peer, and
    almost nothing a caller does wants it in that form -- an ACL comparing against
    ``10.0.0.0/8``, a log line, a config lookup::

        unmap("::ffff:10.0.0.5")    # IPv4Address('10.0.0.5')
        unmap("10.0.0.5")           # IPv4Address('10.0.0.5')   -- unchanged
        unmap("2001:db8::1")        # IPv6Address('2001:db8::1') -- unchanged

    Built on :attr:`ipaddress.IPv6Address.ipv4_mapped` rather than stripping a
    ``"::ffff:"`` prefix from the text. The string version looks equivalent and
    is not -- measured, these are all genuinely mapped addresses that a
    ``startswith("::ffff:") and "." in text`` test leaves untouched:

    ===========================  ==========  ============================
    input                        this gives  the string test gives
    ===========================  ==========  ============================
    ``::FFFF:10.0.0.5``          ``10.0.0.5``  unchanged (wrong case)
    ``::ffff:0:1``               ``0.0.0.1``   unchanged (no dot)
    ``0:0:0:0:0:ffff:0a00:0005`` ``10.0.0.5``  unchanged (expanded form)
    ===========================  ==========  ============================

    One address has many spellings, and only the parsed form sees through them.

    :raises NetimpsValueError: for text that is no address.
    :raises TypeError: for a value that is no address type.
    """
    address = _as_address(value)
    if isinstance(address, IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return mapped
    return address


def is_wildcard(value: "Union[IPAddressLike, None]") -> bool:
    """Whether ``value`` means "every local address" -- the bind-anything form.

    True for ``""``, ``None``, ``"0.0.0.0"``, ``"::"`` and any other spelling
    whose address form is unspecified (``"::0"``, ``"0000::0"``), and for the
    v4-mapped ``::ffff:0.0.0.0``::

        is_wildcard("")           # True -- what bind("") means
        is_wildcard("0.0.0.0")    # True
        is_wildcard("::")         # True
        is_wildcard("127.0.0.1")  # False

    A ``%zone`` suffix does not change whether the address is unspecified.

    Text that is no address is a host name, and a name is never the wildcard:
    the answer is ``False``. This is the one classifier that takes a name,
    because it is asked of a listen host, and ``bind`` takes a name there.

    :raises TypeError: for a value that is neither text nor an address.
    """
    if value is None:
        return True
    if isinstance(value, str):
        value = value.strip().split("%", 1)[0]
        if not value:
            return True
        literal = ip_literal(value)
        if literal is None:
            return False
        value = literal
    return bool(unmap(_as_address(value)).is_unspecified)
