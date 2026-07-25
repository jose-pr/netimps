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
    def __init__(self, value: object, *, enabled: bool = False) -> None:
        self.value = value
        self.enabled = enabled


class Fallback:
    pass


address_like: IPAddressLike = b"\x7f\x00\x00\x01"
interface_like: IPInterfaceLike = ("127.0.0.1", 8)
network_like: IPNetworkLike = ("127.0.0.1", 8)
fallback = Fallback()

assert_type(parse("127.0.0.1"), IPAddress)
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

assert_type(try_parse("127.0.0.1"), Optional[IPAddress])
assert_type(try_parse("127.0.0.1", IPAddress), Optional[IPAddress])
assert_type(try_parse("127.0.0.1/8", IPInterface), Optional[IPInterface])
assert_type(try_parse("127.0.0.0/8", IPNetwork), Optional[IPNetwork])
assert_type(try_parse("02:00:00:00:00:01", MACAddress), Optional[MACAddress])
assert_type(try_parse("value", Built, enabled=True), Optional[Built])
assert_type(
    try_parse("bad", IPAddress, default=fallback),
    Union[IPAddress, Fallback],
)
assert_type(
    try_parse("bad", Built, default=fallback),
    Union[Built, Fallback],
)
assert_type(
    try_parse("bad", default=fallback),
    Union[IPAddress, Fallback],
)

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
raw: object = "127.0.0.1"
if is_valid(raw, IPAddress):
    assert_type(raw, object)
