"""``classify``: text read as a MAC, a network, an interface or an address."""

import pytest

import netimps
from netimps import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    MACAddress,
    classify,
)


@pytest.mark.parametrize(
    "text, expected",
    [
        ("00:00:5e:00:53:01", MACAddress("00:00:5e:00:53:01")),
        ("00-00-5e-00-53-01", MACAddress("00:00:5e:00:53:01")),
        ("10.0.0.0/24", IPv4Network("10.0.0.0/24")),
        ("10.0.0.5/32", IPv4Network("10.0.0.5/32")),
        ("10.0.0.5/24", IPv4Interface("10.0.0.5/24")),
        ("10.0.0.5", IPv4Address("10.0.0.5")),
        ("::1", IPv6Address("::1")),
    ],
)
def test_each_reading(text, expected):
    got = classify(text)
    assert got == expected
    assert type(got) is type(expected)


def test_a_bare_address_is_an_address_not_a_host_network():
    """The reading order: only a ``/`` makes text a network."""
    assert isinstance(classify("192.0.2.1"), IPv4Address)


@pytest.mark.parametrize(
    "text", ["junk", "", "1.2.3", "10.0.0.5/33", "10.0.0.5/24/3", "example.com"]
)
def test_text_that_is_none_of_them_raises(text):
    with pytest.raises(netimps.NetimpsValueError):
        classify(text)


def test_a_name_is_never_resolved(no_such_host):
    """``classify`` answers from the text alone; a name needs ``Host``."""
    with pytest.raises(netimps.NetimpsValueError):
        classify("localhost")


def test_a_non_string_is_a_type_error():
    with pytest.raises(TypeError):
        classify(3)  # type: ignore[arg-type]
