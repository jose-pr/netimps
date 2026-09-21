"""Static-typing conformance for the public API. Never executed.

This file exists so a checker *proves* the promises ``src/netimps/AGENTS.md``
makes: that :func:`parse`/:func:`try_parse` preserve the selected result type
(union alias, concrete class, or arbitrary callable builder), that an explicit
``default=`` widens the result to a union, and that :func:`is_valid` returns a
plain ``bool`` which narrows nothing.

Running it::

    python -m mypy --no-incremental src/netimps tests/typing/api.py

**``--no-incremental`` is not optional here.**
``typing_extensions.TypeForm`` -- what the ``parse`` overloads use to keep a
union alias from collapsing -- is serialised into ``.mypy_cache`` as a plain
``type[...]``. Any run that reads ``netimps`` back from that cache therefore
loses every union-alias overload and reports ~25 spurious errors in this file,
all of the form "Expression is of type Any". Measured with mypy 1.20.2 on
2026-09-21, and reproducible in a dozen lines outside this package: check
``src/netimps`` in one invocation, then this file in another, and the second
one fails. Passing both targets to a single invocation is only safe while the
cache is cold -- which is exactly the guarantee a CI runner stops giving the
moment anyone caches ``.mypy_cache``.

``assert_type`` comes from ``typing_extensions`` because ``typing.assert_type``
is 3.11+ and 3.9 is the floor. Nothing has to install it -- mypy resolves the
name from its own bundled typeshed, and this file never runs.
"""

from __future__ import annotations

from typing import Iterator, Optional, Union

from typing_extensions import assert_type

from netimps import (
    IPAddress,
    IPAddressLike,
    IPInterface,
    IPInterfaceLike,
    IPNetwork,
    IPNetworkLike,
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    Interface,
    MACAddress,
    interface_for,
    interfaces_for,
    is_local_address,
    is_valid,
    parse,
    try_parse,
)


class Built:
    """An arbitrary callable builder -- the third thing ``type`` may be."""

    def __init__(self, value: object, *, enabled: bool = False) -> None:
        self.value = value
        self.enabled = enabled


class Fallback:
    """A ``default=`` that shares no base class with any parse result."""


address_like: IPAddressLike = b"\x7f\x00\x00\x01"
interface_like: IPInterfaceLike = ("127.0.0.1", 8)
network_like: IPNetworkLike = ("127.0.0.1", 8)
fallback = Fallback()

# ---------------------------------------------------------------------------
# parse: the selected result type survives, whatever form ``type`` takes
# ---------------------------------------------------------------------------

assert_type(parse("127.0.0.1"), IPAddress)  # the default
assert_type(parse(address_like, IPAddress), IPAddress)
assert_type(parse(interface_like, IPInterface), IPInterface)
assert_type(parse(network_like, IPNetwork), IPNetwork)

assert_type(parse("127.0.0.1", IPv4Address), IPv4Address)
assert_type(parse("::1", IPv6Address), IPv6Address)
assert_type(parse("127.0.0.1/8", IPv4Interface), IPv4Interface)
assert_type(parse("::1/128", IPv6Interface), IPv6Interface)
assert_type(parse("127.0.0.0/8", IPv4Network), IPv4Network)
assert_type(parse("::1/128", IPv6Network), IPv6Network)
assert_type(parse("02:00:00:00:00:01", MACAddress), MACAddress)
assert_type(parse("value", Built, enabled=True), Built)

# ``type`` is spelled the same positionally and by keyword, and extra kwargs
# reach the builder without disturbing the result type.
assert_type(parse("127.0.0.0/8", type=IPNetwork), IPNetwork)
assert_type(parse("127.0.0.5/8", IPNetwork, strict=False), IPNetwork)
assert_type(parse("127.0.0.0/8", IPv4Network, strict=True), IPv4Network)

# The ``*Like`` aliases are input-only. They are rejected in a ``type``
# position at *runtime* (``_check_parser`` raises ``TypeError``); a checker
# cannot see that, so there is nothing to assert here -- only a reminder that
# a green run of this file does not license ``parse(x, IPAddressLike)``.

# ---------------------------------------------------------------------------
# try_parse: the same, wrapped in Optional -- or in a union with ``default``
# ---------------------------------------------------------------------------

assert_type(try_parse("127.0.0.1"), Optional[IPAddress])
assert_type(try_parse("127.0.0.1", IPAddress), Optional[IPAddress])
assert_type(try_parse("127.0.0.1/8", IPInterface), Optional[IPInterface])
assert_type(try_parse("127.0.0.0/8", IPNetwork), Optional[IPNetwork])
assert_type(try_parse("127.0.0.0/8", type=IPNetwork), Optional[IPNetwork])
assert_type(try_parse("127.0.0.1", IPv4Address), Optional[IPv4Address])
assert_type(try_parse("::1", IPv6Network), Optional[IPv6Network])
assert_type(try_parse("02:00:00:00:00:01", MACAddress), Optional[MACAddress])
assert_type(try_parse("value", Built, enabled=True), Optional[Built])

# An explicit ``default`` widens the result instead of replacing it, whether it
# is passed positionally or by keyword.
assert_type(
    try_parse("bad", IPAddress, default=fallback),
    Union[IPAddress, Fallback],
)
assert_type(
    try_parse("bad", IPAddress, fallback),
    Union[IPAddress, Fallback],
)
assert_type(
    try_parse("bad", IPv4Address, fallback),
    Union[IPv4Address, Fallback],
)
assert_type(
    try_parse("bad", MACAddress, fallback),
    Union[MACAddress, Fallback],
)
assert_type(
    try_parse("bad", Built, default=fallback),
    Union[Built, Fallback],
)
assert_type(
    try_parse("bad", default=fallback),
    Union[IPAddress, Fallback],
)

# ---------------------------------------------------------------------------
# is_valid: a plain ``bool``, for every ``type`` form, narrowing nothing
# ---------------------------------------------------------------------------

assert_type(is_valid("127.0.0.1"), bool)
assert_type(is_valid("127.0.0.1", IPAddress), bool)
assert_type(is_valid("127.0.0.0/8", IPNetwork), bool)
assert_type(is_valid("127.0.0.0/8", type=IPNetwork), bool)
assert_type(is_valid("127.0.0.1", IPv4Address), bool)
assert_type(is_valid("02:00:00:00:00:01", MACAddress), bool)
assert_type(is_valid("value", Built, enabled=True), bool)
assert_type(MACAddress.is_valid("02:00:00:00:00:01"), bool)
assert_type(MACAddress.try_parse("02:00:00:00:00:01"), Optional[MACAddress])

# Regression guard, and the reason the two lines below are not dead weight: a
# ``TypeGuard`` on either ``is_valid`` would be *unsound*. Validity proves the
# input is convertible, not that it already is the target type -- the parse
# builds a different object from it. If a ``TypeGuard`` is ever reintroduced,
# the narrowed type stops being ``object`` and these assertions fail.
raw: object = "127.0.0.1"
if is_valid(raw, IPAddress):
    assert_type(raw, object)

raw_mac: object = "02:00:00:00:00:01"
if MACAddress.is_valid(raw_mac):
    assert_type(raw_mac, object)

# ---------------------------------------------------------------------------
# Interface lookup helpers
# ---------------------------------------------------------------------------

iface = Interface("loopback")
assert_type(interface_for(iface), Optional[Interface])
assert_type(interface_for(IPv4Address("127.0.0.1")), Optional[Interface])
assert_type(interface_for(IPv4Interface("127.0.0.1/8")), Optional[Interface])
assert_type(interface_for(IPv4Network("127.0.0.0/8")), Optional[Interface])
assert_type(interface_for(MACAddress("02:00:00:00:00:01")), Optional[Interface])
assert_type(interfaces_for(IPv4Network("127.0.0.0/8")), Iterator[Interface])
for matched in interfaces_for(IPv4Network("127.0.0.0/8")):
    assert_type(matched, Interface)

assert_type(is_local_address("127.0.0.1"), bool)
