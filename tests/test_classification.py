"""Classifiers and ``try_parse``: one answer on every Python, one rule for input.

The mapped-address cases run on every supported interpreter, because the stdlib
only started delegating the ``is_*`` properties of a v4-mapped address in 3.13:
the same call answered ``True`` on 3.14 and ``False`` on 3.9.
"""

import ipaddress

import pytest

import netimps
from netimps import (
    FQDN,
    Host,
    IPAddress,
    IPNetwork,
    MACAddress,
    NetimpsValueError,
    is_broadcast,
    is_link_scoped,
    is_local_address,
    is_local_host,
    is_multicast,
    is_unicast,
    is_valid,
    is_wildcard,
    parse,
    try_parse,
    unmap,
)

# --------------------------------------------------------------------------- #
# A v4-mapped address is classified as the v4 address inside it                #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "mapped, expected",
    [
        ("::ffff:127.0.0.1", True),
        ("::ffff:169.254.1.1", True),
        ("::ffff:10.0.0.5", False),
        ("::FFFF:7f00:1", True),
    ],
)
def test_is_link_scoped_unmaps_first(mapped, expected):
    assert is_link_scoped(parse(mapped)) is expected
    assert is_link_scoped(mapped) is expected


@pytest.mark.parametrize(
    "mapped, expected",
    [("::ffff:0.0.0.0", True), ("::ffff:1.2.3.4", False), ("::ffff:0:0", True)],
)
def test_is_wildcard_unmaps_first(mapped, expected):
    assert is_wildcard(mapped) is expected
    assert is_wildcard(ipaddress.IPv6Address(mapped)) is expected


def test_is_multicast_and_is_unicast_agree_on_a_mapped_address():
    assert is_multicast("::ffff:224.0.0.1") is True
    assert is_unicast("::ffff:224.0.0.1") is False
    assert is_unicast("::ffff:0.0.0.0") is False
    assert is_broadcast("::ffff:255.255.255.255") is True


# --------------------------------------------------------------------------- #
# One rule for the family of predicates                                        #
# --------------------------------------------------------------------------- #

PREDICATES = [
    is_link_scoped,
    is_multicast,
    is_local_address,
    is_broadcast,
    is_unicast,
    is_wildcard,
]


@pytest.mark.parametrize("predicate", PREDICATES, ids=lambda p: p.__name__)
def test_text_that_is_no_address_raises_the_value_error(predicate):
    """They answered three ways: raise, `False`, and `AttributeError`."""
    for text in ("not an address", "999.1.1.1", "example.com", "[::1]", "1.2.3"):
        with pytest.raises(NetimpsValueError):
            predicate(text)


@pytest.mark.parametrize("predicate", PREDICATES, ids=lambda p: p.__name__)
def test_a_value_of_the_wrong_type_raises_type_error(predicate):
    for value in (5.5, ["10.0.0.1"], object(), True):
        with pytest.raises(TypeError):
            predicate(value)
    with pytest.raises(TypeError):
        predicate(ipaddress.ip_network("10.0.0.0/24"))


@pytest.mark.parametrize(
    "predicate",
    [is_link_scoped, is_multicast, is_local_address, is_broadcast, is_unicast],
    ids=lambda p: p.__name__,
)
def test_every_address_like_is_taken(predicate):
    """`IPAddressLike`: text, an `int`, packed `bytes` and an address object."""
    results = {
        predicate("127.0.0.1"),
        predicate(2130706433),
        predicate(bytes([127, 0, 0, 1])),
        predicate(ipaddress.IPv4Address("127.0.0.1")),
        predicate(Host("127.0.0.1")),
    }
    assert len(results) == 1 and isinstance(results.pop(), bool)


def test_the_loopback_answers():
    assert is_link_scoped("127.0.0.1") is True
    assert is_link_scoped(2130706433) is True
    assert is_link_scoped("::1") is True
    assert is_link_scoped("10.0.0.5") is False
    assert is_multicast("224.0.0.251") is True
    assert is_multicast("10.0.0.1") is False
    assert is_multicast(ipaddress.ip_interface("239.1.2.3/32")) is True


def test_is_wildcard_keeps_its_two_special_spellings():
    """`bind("")` is the wildcard, and `None` stands for "no address given"."""
    assert is_wildcard("") is True
    assert is_wildcard(None) is True
    assert is_wildcard("  ") is True
    assert is_wildcard("0.0.0.0%eth0") is True


def test_is_local_host_alone_takes_a_name_and_never_raises():
    for value in ("not an address", "example.com", "", None, 5, object()):
        assert is_local_host(value) is False


def test_unmap_takes_every_address_like():
    assert unmap(2130706433) == ipaddress.IPv4Address("127.0.0.1")
    assert unmap(bytes([10, 0, 0, 5])) == ipaddress.IPv4Address("10.0.0.5")
    assert unmap("::ffff:10.0.0.5") == ipaddress.IPv4Address("10.0.0.5")
    assert unmap(ipaddress.IPv6Address("::ffff:10.0.0.5")) == ipaddress.IPv4Address(
        "10.0.0.5"
    )
    with pytest.raises(NetimpsValueError):
        unmap("nope")


# --------------------------------------------------------------------------- #
# try_parse and is_valid: a rejected value is not a bad option                  #
# --------------------------------------------------------------------------- #


def test_a_bad_option_is_a_type_error_not_a_rejected_value():
    """`try_parse("10.0.0.5", IPAddress, strict=True)` answered `None` while
    `parse` raised `TypeError`: a caller's bug read as bad input."""
    with pytest.raises(TypeError):
        parse("10.0.0.5", IPAddress, strict=True)
    with pytest.raises(TypeError):
        try_parse("10.0.0.5", IPAddress, strict=True)
    with pytest.raises(TypeError):
        is_valid("10.0.0.5", IPAddress, strict=True)
    with pytest.raises(TypeError):
        try_parse("10.0.0.5", IPAddress, nonsense=1)
    with pytest.raises(TypeError):
        try_parse("00:11:22:33:44:55", MACAddress, strict=True)
    with pytest.raises(TypeError):
        try_parse("example.com", Host, strict=True)


def test_the_option_check_follows_the_builder():
    assert try_parse("10.0.0.5/24", IPNetwork, strict=False) == ipaddress.ip_network(
        "10.0.0.0/24"
    )
    # A host-bits network is *text that does not parse* under strict.
    assert try_parse("10.0.0.5/24", IPNetwork, strict=True) is None
    assert is_valid("10.0.0.5/24", IPNetwork, strict=True) is False
    assert is_valid("10.0.0.0/24", IPNetwork, strict=True) is True


def test_a_callable_type_has_its_options_checked_too():
    def build(value, *, flag=False):
        if not flag:
            raise ValueError("flag required")
        return value

    def build_any(value, **kwargs):
        return kwargs

    assert try_parse("x", build, flag=True) == "x"
    assert try_parse("x", build) is None
    assert try_parse("x", build_any, anything=1) == {"anything": 1}
    with pytest.raises(TypeError):
        try_parse("x", build, other=1)
    with pytest.raises(TypeError):
        is_valid("x", build, other=1)


def test_text_that_does_not_parse_still_answers_the_default():
    assert try_parse("zzz", IPAddress) is None
    assert try_parse("zzz", IPAddress, default=5) == 5
    assert try_parse(None, IPAddress, default="d") == "d"
    assert is_valid("zzz", IPAddress) is False
    assert try_parse(object(), MACAddress) is None


# --------------------------------------------------------------------------- #
# Host() applies the HostLike rule                                             #
# --------------------------------------------------------------------------- #


def test_a_host_built_from_an_interface_is_its_address(monkeypatch):
    asked = []

    def spy(host, *args, **kwargs):
        asked.append(host)
        raise OSError("no resolver here")

    monkeypatch.setattr(netimps._ip._socket, "getaddrinfo", spy, raising=False)
    host = Host(ipaddress.ip_interface("127.0.0.1/8"))
    assert str(host) == "127.0.0.1"
    assert host.is_address is True
    assert host.ip() == ipaddress.IPv4Address("127.0.0.1")
    assert asked == []
    assert str(Host(ipaddress.ip_interface("fe80::1/64"))) == "fe80::1"


def test_a_host_takes_the_other_hostlike_values_as_before():
    assert str(Host(ipaddress.ip_address("::1"))) == "::1"
    assert str(Host(FQDN("example.com."))) == "example.com."
    assert str(Host(Host("a.b"))) == "a.b"
    assert str(Host(None)) == ""
    assert str(Host(" example.com ")) == "example.com"


def test_a_host_built_from_a_network_names_no_host():
    with pytest.raises(TypeError):
        Host(ipaddress.ip_network("10.0.0.0/24"))
