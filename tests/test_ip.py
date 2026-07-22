import ipaddress

import pytest

import netimps
from netimps import (
    IPAddr,
    IPIface,
    IPNet,
    IPv4Address,
    IPv4Interface,
    is_valid_ip,
    parse_ip,
    parse_network,
)


def test_ipaddress_forms():
    assert IPAddr("10.0.0.5") == ipaddress.ip_address("10.0.0.5")
    assert IPAddr(0x0A000005) == IPv4Address("10.0.0.5")
    existing = IPv4Address("192.168.1.1")
    assert IPAddr(existing) == existing


def test_ipinterface_exploded_surface():
    iface = IPIface("10.0.0.5/24")
    assert isinstance(iface, IPv4Interface)
    assert iface.ip.exploded == "10.0.0.5"
    assert iface.netmask.exploded == "255.255.255.0"
    assert iface.network.network_address.exploded == "10.0.0.0"


def test_ipnetwork_membership_and_exploded():
    net = IPNet("192.168.1.0/24")
    assert net.network_address.exploded == "192.168.1.0"
    assert net.netmask.exploded == "255.255.255.0"
    assert IPAddr("192.168.1.42") in net
    assert IPAddr("10.0.0.1") not in net


def test_ipnetwork_non_strict_by_default():
    # A host address with a prefix must not raise; it normalises to its network.
    net = IPNet("10.0.0.5/24")
    assert net.network_address.exploded == "10.0.0.0"
    with pytest.raises(ValueError):
        IPNet("10.0.0.5/24", strict=True)


def test_parse_ip_empty_and_none_are_falsy():
    assert parse_ip("") is None
    assert parse_ip("   ") is None
    assert parse_ip(None) is None


def test_parse_ip_valid_and_invalid():
    assert parse_ip("10.0.0.5") == IPv4Address("10.0.0.5")
    assert parse_ip(IPv4Address("10.0.0.5")) == IPv4Address("10.0.0.5")
    with pytest.raises(ValueError):
        parse_ip("not-an-ip")


def test_parse_network():
    assert parse_network("") is None
    assert parse_network(None) is None
    assert parse_network("192.168.0.0/16").network_address.exploded == "192.168.0.0"
    # non-strict: host bits tolerated
    assert parse_network("192.168.0.7/16").network_address.exploded == "192.168.0.0"


@pytest.mark.parametrize(
    "value, expected",
    [
        ("10.0.0.1", True),
        ("::1", True),
        ("256.0.0.1", False),
        ("not-an-ip", False),
        ("", False),
        (None, False),
        (12345, True),  # int is a valid ipaddress input
    ],
)
def test_is_valid_ip(value, expected):
    assert is_valid_ip(value) is expected


def test_public_api_exports():
    for name in netimps.__all__:
        assert hasattr(netimps, name), name


def test_types_are_types_and_factories_are_callable():
    """The noun names are unions to annotate with; the short names build values."""
    import typing

    for name in ("IPAddress", "IPInterface", "IPNetwork", "IPAddressLike",
                 "IPNetworkLike", "MACLike"):
        alias = getattr(netimps, name)
        # A Union alias, not a callable factory.
        assert typing.get_origin(alias) is typing.Union, name

    assert netimps.IPAddr("10.0.0.5") == IPv4Address("10.0.0.5")
    assert netimps.IPIface("10.0.0.5/24").network == netimps.IPNet("10.0.0.0/24")
    assert netimps.IPNet("10.0.0.5/24") == ipaddress.ip_network("10.0.0.0/24")


def test_unions_usable_as_annotations():
    """Regression: the aliases must resolve under get_type_hints."""
    import typing

    def annotated(a: netimps.IPAddress, b: netimps.IPNetwork) -> None:
        ...

    hints = typing.get_type_hints(annotated)
    assert hints["a"] == netimps.IPAddress
    assert hints["b"] == netimps.IPNetwork
