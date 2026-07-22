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
    try_parse,
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


def test_try_parse_handles_empty_and_none():
    """try_parse replaces the old parse_ip empty-string special case."""
    assert try_parse("", IPAddr) is None
    assert try_parse("   ", IPAddr) is None
    assert try_parse(None, IPAddr) is None


def test_try_parse_ip_valid_and_invalid():
    assert try_parse("10.0.0.5", IPAddr) == IPv4Address("10.0.0.5")
    assert try_parse(IPv4Address("10.0.0.5"), IPAddr) == IPv4Address("10.0.0.5")
    # Unlike the removed parse_ip, malformed input is None rather than a raise.
    assert try_parse("not-an-ip", IPAddr) is None


def test_try_parse_network():
    assert try_parse("", IPNet) is None
    assert try_parse(None, IPNet) is None
    assert try_parse("192.168.0.0/16", IPNet).network_address.exploded == "192.168.0.0"
    # non-strict: host bits tolerated
    assert try_parse("192.168.0.7/16", IPNet).network_address.exploded == "192.168.0.0"


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

    for name in (
        "IPAddress",
        "IPInterface",
        "IPNetwork",
        "IPAddressLike",
        "IPNetworkLike",
        "MACLike",
    ):
        alias = getattr(netimps, name)
        # A Union alias, not a callable factory.
        assert typing.get_origin(alias) is typing.Union, name

    assert netimps.IPAddr("10.0.0.5") == IPv4Address("10.0.0.5")
    assert netimps.IPIface("10.0.0.5/24").network == netimps.IPNet("10.0.0.0/24")
    assert netimps.IPNet("10.0.0.5/24") == ipaddress.ip_network("10.0.0.0/24")


def test_unions_usable_as_annotations():
    """Regression: the aliases must resolve under get_type_hints."""
    import typing

    def annotated(a: netimps.IPAddress, b: netimps.IPNetwork) -> None: ...

    hints = typing.get_type_hints(annotated)
    assert hints["a"] == netimps.IPAddress
    assert hints["b"] == netimps.IPNetwork


# --------------------------------------------------------------------------- #
# generic is_valid                                                             #
# --------------------------------------------------------------------------- #


def test_is_valid_generic_with_any_factory():
    from netimps import IPAddr, IPIface, IPNet, MACAddress, is_valid

    assert is_valid("10.0.0.5", IPAddr)
    assert is_valid("10.0.0.5/24", IPIface)
    assert is_valid("10.0.0.0/24", IPNet)
    assert is_valid("aa:bb:cc:dd:ee:ff", MACAddress)
    assert not is_valid("nonsense", IPAddr)
    assert not is_valid(None, IPAddr)
    assert not is_valid(object(), MACAddress)


def test_is_valid_only_swallows_bad_input_errors():
    """An unexpected error is a real failure, not a 'False' validation result."""
    from netimps import is_valid

    def raises_os_error(_value):
        raise OSError("network unreachable")

    with pytest.raises(OSError):
        is_valid("anything", raises_os_error)


def test_named_validators_match_generic():
    from netimps import (
        IPAddr,
        IPNet,
        MACAddress,
        is_valid,
        is_valid_ip,
        is_valid_mac,
        is_valid_network,
    )

    for value in ["10.0.0.5", "", "nope", None, "::1"]:
        assert is_valid_ip(value) == is_valid(value, IPAddr)
    for value in ["10.0.0.0/24", "10.0.0.5/24", "nope", None]:
        assert is_valid_network(value) == is_valid(value, IPNet)
    for value in ["aa:bb:cc:dd:ee:ff", "nope", None, 12]:
        assert is_valid_mac(value) == is_valid(value, MACAddress)


# --------------------------------------------------------------------------- #
# generic try_parse                                                            #
# --------------------------------------------------------------------------- #


def test_try_parse_returns_value_or_none():
    from netimps import IPAddr, IPIface, IPNet, MACAddress, try_parse

    assert try_parse("10.0.0.5", IPAddr) == IPv4Address("10.0.0.5")
    assert try_parse("10.0.0.5/24", IPIface) == ipaddress.ip_interface("10.0.0.5/24")
    assert try_parse("10.0.0.0/24", IPNet) == ipaddress.ip_network("10.0.0.0/24")
    assert str(try_parse("aa:bb:cc:dd:ee:ff", MACAddress)) == "aa:bb:cc:dd:ee:ff"

    assert try_parse("nonsense", IPAddr) is None
    assert try_parse(None, IPAddr) is None
    assert try_parse("", IPAddr) is None
    assert try_parse(object(), MACAddress) is None


def test_try_parse_only_swallows_bad_input_errors():
    from netimps import try_parse

    def raises_os_error(_value):
        raise OSError("network unreachable")

    with pytest.raises(OSError):
        try_parse("anything", raises_os_error)


def test_try_parse_agrees_with_is_valid():
    """The two must never disagree about whether a value parses."""
    from netimps import IPAddr, IPNet, MACAddress, is_valid, try_parse

    for parser in (IPAddr, IPNet, MACAddress):
        for value in [
            "10.0.0.5",
            "10.0.0.0/24",
            "aa:bb:cc:dd:ee:ff",
            "nope",
            "",
            None,
            5,
        ]:
            assert (try_parse(value, parser) is not None) == is_valid(value, parser)
