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

import socket
from typing import Any, Iterator, List, Optional, Tuple, Union

from typing_extensions import assert_type

from netimps import (
    Backoff,
    Datagram,
    FQDN,
    Host,
    SocketOption,
    UDPEndpoint,
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
    NetimpsError,
    NetimpsValueError,
    ResolutionError,
    ResolutionTimeoutError,
    DNSDecodeError,
    AddressInUseError,
    get_interface,
    iter_interfaces,
    is_broadcast,
    is_local_address,
    is_valid,
    is_wildcard,
    clear_resolution_cache,
    is_local_host,
    is_unicast,
    bind,
    join_host,
    max_udp_payload,
    parse,
    try_parse,
    unmap,
    tcp_check,
    get_hostname,
    discover_mtu,
    has_dns,
    ping,
    resolve,
    resolve_dnspython,
    resolve_doh,
    resolve_nslookup,
    resolve_system,
    resolve_wire,
    split_host,
    split_zone,
    wait_for_port,
    PingResult,
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

# An explicit ``default`` widens the result instead of replacing it.
assert_type(
    try_parse("bad", IPAddress, default=fallback),
    Union[IPAddress, Fallback],
)
assert_type(
    try_parse("bad", IPv4Address, default=fallback),
    Union[IPv4Address, Fallback],
)
assert_type(
    try_parse("bad", MACAddress, default=fallback),
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
assert_type(MACAddress.parse("02:00:00:00:00:01"), MACAddress)
assert_type(MACAddress("02:00:00:00:00:01").format("-", upper=True), str)
assert_type(format(MACAddress("02:00:00:00:00:01"), "-X"), str)
assert_type(bytes(MACAddress("02:00:00:00:00:01")), bytes)
assert_type(MACAddress.try_parse("nope", fallback), Union[MACAddress, Fallback])
assert_type(FQDN.parse("example.com"), FQDN)
assert_type(FQDN.try_parse("nope..", default=fallback), Union[FQDN, Fallback])
assert_type(Host.parse("db.internal"), Host)
assert_type(Host.try_parse(""), Optional[Host])

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
assert_type(get_interface(iface), Optional[Interface])
assert_type(get_interface(IPv4Address("127.0.0.1")), Optional[Interface])
assert_type(get_interface(IPv4Interface("127.0.0.1/8")), Optional[Interface])
assert_type(get_interface(IPv4Network("127.0.0.0/8")), Optional[Interface])
assert_type(get_interface(MACAddress("02:00:00:00:00:01")), Optional[Interface])
assert_type(iter_interfaces(IPv4Network("127.0.0.0/8")), Iterator[Interface])
for matched in iter_interfaces(IPv4Network("127.0.0.0/8")):
    assert_type(matched, Interface)

assert_type(is_local_address("127.0.0.1"), bool)
assert_type(iface.ips, Tuple[Union[IPv4Interface, IPv6Interface], ...])
assert_type(iface.is_loopback, bool)
assert_type(
    Interface("lo", ips=[IPv4Interface("127.0.0.1/8")], is_loopback=True), Interface
)

# ---------------------------------------------------------------------------
# FQDN -- the name algebra. The properties that return Optional are the point:
# a checker must force the `is None` branch at the top of a name, because the
# natural `while f.domain:` walk depends on it terminating.
# ---------------------------------------------------------------------------

fqdn = FQDN("www.example.com")
assert_type(fqdn.labels, Tuple[str, ...])
assert_type(fqdn.parts, Tuple[str, ...])
assert_type(fqdn.hostname, str)
assert_type(fqdn.name, str)
assert_type(fqdn.tld, str)
assert_type(fqdn.domain, Optional[FQDN])
assert_type(fqdn.parent, Optional[FQDN])
assert_type(fqdn.domains, Tuple[FQDN, ...])
assert_type(fqdn.parents, Tuple[FQDN, ...])
assert_type(fqdn.is_fully_qualified(), bool)
assert_type(fqdn.is_absolute(), bool)

# The algebra returns FQDN, never Optional -- only `.domain` can run out.
assert_type(fqdn / "deep", FQDN)
assert_type(fqdn / FQDN("deep"), FQDN)
assert_type(fqdn.child("a", "b"), FQDN)
assert_type(fqdn.with_hostname("mail"), FQDN)
assert_type(fqdn.with_name("mail"), FQDN)
assert_type(fqdn.relative_to("example.com"), FQDN)
assert_type(fqdn.reverse(), FQDN)
assert_type(fqdn.fully_qualified(), FQDN)
assert_type(fqdn.relative(), FQDN)
assert_type(fqdn.is_subdomain_of("example.com"), bool)
assert_type(fqdn.is_subdomain_of(FQDN("example.com")), bool)

assert_type(FQDN.try_parse("example.com"), Optional[FQDN])
assert_type(FQDN.is_valid("example.com"), bool)

# Walking up terminates, and the checker knows it can.
current: Optional[FQDN] = fqdn
while current is not None:
    assert_type(current.hostname, str)
    current = current.domain

# Host narrows to a name; an address costs a reverse lookup, which may find none.
assert_type(Host("www.example.com").fqdn(), Optional[FQDN])
assert_type(Host("www.example.com").fqdn(check=True, ns="192.0.2.53"), Optional[FQDN])

# The three resolving methods, and the pair `resolve()` always returns.
assert_type(Host("db.internal").ip(), Optional[IPAddress])
assert_type(
    Host("db.internal").ip(check=True, ipv6=True, backends=["system"], refresh=True),
    Optional[IPAddress],
)
assert_type(Host("db.internal").resolve(), Tuple[Optional[FQDN], Optional[IPAddress]])
host_name, host_ip = Host("db.internal").resolve(check=True, tcp=True)
assert_type(host_name, Optional[FQDN])
assert_type(host_ip, Optional[IPAddress])
assert_type(fqdn.ip(), Optional[IPAddress])
assert_type(fqdn.resolve(), Tuple[FQDN, Optional[IPAddress]])
assert_type(fqdn.resolve(ipv6=False, timeout=None), Tuple[FQDN, Optional[IPAddress]])

# FQDN's text interop and the containment predicate.
assert_type(fqdn + "/path", str)
assert_type("https://" + fqdn, str)
assert_type(fqdn.to_unicode(), str)
assert_type(fqdn.is_wildcard, bool)
assert_type(fqdn.is_hostname(), bool)
assert_type(fqdn.common_ancestor("example.com"), Optional[FQDN])
assert_type(fqdn.encode(), bytes)
assert_type(bytes(fqdn), bytes)
assert_type(FQDN.decode(b"\x01a\x00"), FQDN)
assert_type(FQDN.decode_at(b"\x01a\x00", 0), Tuple[FQDN, int])
assert_type(fqdn.wire_length, int)


# ---------------------------------------------------------------------------
# The consumer-sweep additions. `unmap` returning the union matters: a caller
# that assumed IPv4Address would be wrong for an unmapped v6 input.
# ---------------------------------------------------------------------------

assert_type(join_host("example.com", 8080), str)
assert_type(join_host("::1"), str)
assert_type(unmap("::ffff:10.0.0.5"), IPAddress)
assert_type(is_wildcard("0.0.0.0"), bool)

option = SocketOption(1, 2, 3)
assert_type(option.level, int)
assert_type(option.name, int)


# The UDP-server helpers. `reply_socket` returns a real socket, not Optional:
# it falls back to the wildcard rather than giving up.
assert_type(is_broadcast("255.255.255.255"), bool)
assert_type(max_udp_payload(1500), int)


# `aclose()` is a coroutine and `async with` yields the endpoint itself.
async def _async_closing(endpoint: UDPEndpoint) -> None:
    assert_type(await endpoint.aclose(), None)
    async with endpoint as entered:
        assert_type(entered, UDPEndpoint)


# `reply_socket`'s `port` takes an int *or* any iterable of ints, and still
# returns a concrete socket. Checked from a consumer's config, because the
# widening is only useful if a caller's own `range`/`list`/generator type-checks.
def _reply_socket_port_forms(endpoint: UDPEndpoint, packet: Datagram) -> None:
    assert_type(endpoint.reply_socket(packet), socket.socket)
    assert_type(endpoint.reply_socket(packet, 69), socket.socket)
    assert_type(endpoint.reply_socket(packet, range(50000, 50100)), socket.socket)
    assert_type(endpoint.reply_socket(packet, [50000, 50001]), socket.socket)
    assert_type(endpoint.reply_socket(packet, (p for p in (1, 2))), socket.socket)


# `reply_address` is a socket address like `sender`, not an address object: it is
# what goes straight into `sendto`. The union is the point -- a v4 reply is the
# 2-tuple an AF_INET `sendto` demands, a v6 one keeps its scope id.
def _reply_address_is_a_socket_address(packet: Datagram) -> None:
    assert_type(
        packet.reply_address,
        Union[Tuple[str, int], Tuple[str, int, int, int]],
    )
    assert_type(
        packet.sender,
        Union[Tuple[str, int], Tuple[str, int, int, int]],
    )


# `Backoff` is a stateful timer, not an iterator: `.delay` and the two mutators
# are floats, and `.attempt` an int.
def _backoff_is_a_timer(timer: Backoff) -> None:
    assert_type(timer.delay, float)
    assert_type(timer.advance(), float)
    assert_type(timer.reset(), float)
    assert_type(timer.attempt, int)


# The hierarchy is part of the typing contract: a handler written against a
# builtin must still narrow, and one written against the package base must
# accept every package exception.
def _exceptions_subclass_what_they_promise() -> None:
    def _package(error: NetimpsError) -> None: ...

    def _value(error: ValueError) -> None: ...

    def _timeout(error: TimeoutError) -> None: ...

    def _os(error: OSError) -> None: ...

    _package(NetimpsValueError("x"))
    _package(ResolutionError("x"))
    _package(ResolutionTimeoutError("x"))
    _package(DNSDecodeError("x"))
    _package(AddressInUseError(98, "x"))
    _value(NetimpsValueError("x"))
    _value(DNSDecodeError("x"))
    _timeout(ResolutionTimeoutError("x"))
    _os(AddressInUseError(98, "x"))
    _package(ResolutionTimeoutError("x"))


# A `Host` and an `FQDN` are accepted wherever a destination is: `HostLike`
# names both, so neither needs a `str()` at the call site.
assert_type(tcp_check(Host("www.example.com"), 443), bool)
assert_type(tcp_check(FQDN("www.example.com"), 443), bool)
assert_type(get_hostname(), str)
assert_type(get_hostname(fqdn=True), str)


# `rdtype` picks the element type of every resolver's list; anything the
# package does not model is a list of whatever the record decodes to.
assert_type(resolve("h", "a"), List[IPv4Address])
assert_type(resolve("h", "AAAA"), List[IPv6Address])
assert_type(resolve("h", "aaaa", ns="192.0.2.53", tcp=True), List[IPv6Address])
assert_type(resolve("192.0.2.1", "ptr"), List[str])
assert_type(resolve("h"), List[Any])
assert_type(resolve("h", "mx"), List[Any])
assert_type(resolve("h", ("a", "aaaa")), List[Any])
assert_type(resolve_system("h", "a"), List[IPv4Address])
assert_type(resolve_system("h", "ptr"), List[str])
assert_type(resolve_nslookup("h", "aaaa"), List[IPv6Address])
assert_type(resolve_dnspython("h", "a", ns="192.0.2.53"), List[IPv4Address])
assert_type(resolve_dnspython("h", "txt"), List[Any])
assert_type(resolve_wire("h", "aaaa", source="192.0.2.1"), List[IPv6Address])
assert_type(resolve_doh("h", "https://dns.example/q", rdtype="a"), List[IPv4Address])
assert_type(resolve_doh("h", "https://dns.example/q"), List[Any])
assert_type(has_dns(), bool)
assert_type(
    resolve_doh("h", "http://dns.example/q", rdtype="a", allow_http=True),
    List[IPv4Address],
)

# Options are keyword-only, and the options `discover_mtu` forwards to `ping`
# are named rather than swallowed by a `**kwargs`.
assert_type(ping("h", tries=3, method="tcp", port=80), PingResult)
assert_type(ping("h").rtt, Optional[float])
assert_type(discover_mtu("h", tries=3, ipv6=False, ttl=64), Optional[int])
assert_type(wait_for_port("h", 80, deadline=5.0, timeout=1.0), bool)
assert_type(split_host("example.com:80", default_port=443), Tuple[str, Optional[int]])
assert_type(is_broadcast("10.0.0.255"), bool)

# `family` is optional and inferred; `connreset` is a tri-state.
assert_type(bind("::1", 0), socket.socket)
assert_type(bind(family=None, connreset=None), socket.socket)
assert_type(bind("", 67, family=socket.AF_INET, connreset=False), socket.socket)


# `destination` is the address the datagram was sent to, `is_unicast` is three
# valued (unknown without pktinfo), and `datagrams` takes a callable that
# returns whether to carry on.
def _datagram_destination(packet: Datagram) -> None:
    assert_type(packet.destination, Optional[IPAddress])
    assert_type(packet.is_unicast, Optional[bool])
    assert_type(is_unicast("10.0.0.5"), bool)
    assert_type(
        is_unicast(packet.destination or "::", packet.interface, cache=True), bool
    )


async def _datagrams_on_error(endpoint: UDPEndpoint) -> None:
    async for packet in endpoint.datagrams(
        on_error=lambda exc: isinstance(exc, OSError)
    ):
        assert_type(packet, Any)


# `split_host` takes a pair as well as text; `split_zone` returns an optional zone.
assert_type(split_host(("h", None), default_port=69), Tuple[str, Optional[int]])
assert_type(split_zone("fe80::1%eth0"), Tuple[str, Optional[str]])
assert_type(is_local_host("localhost", resolve=False, cache=True), bool)


# `cache=` is `bool | float` everywhere it appears; the element type still follows
# `rdtype`.
assert_type(resolve("h", "a", cache=True), List[IPv4Address])
assert_type(resolve("h", "aaaa", cache=30.0), List[IPv6Address])
assert_type(resolve("h", cache=False), List[Any])
assert_type(Host("h").ip(cache=True), Optional[IPAddress])
assert_type(Host("h").resolve(cache=5), Tuple[Optional[FQDN], Optional[IPAddress]])
assert_type(FQDN("h.example").ip(cache=True), Optional[IPAddress])
assert_type(clear_resolution_cache(), None)
