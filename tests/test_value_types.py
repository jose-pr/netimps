"""The value types cannot change after construction, and copy and pickle work.

Assigning to a public attribute used to succeed on these types, so a value
shared through the interface cache or a dict key could be altered under its
holder. Making them read-only also breaks the default pickle restore, which
assigns state back onto a blank instance, so each carries an explicit reduce;
the round-trip tests are what keep that from regressing.
"""

import copy
import ipaddress
import pickle

import pytest

import netimps
from netimps import FQDN, Host, Interface, MACAddress, PingResult, Route


def _interface() -> Interface:
    return Interface(
        name="eth0",
        index=2,
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        ips=[ipaddress.ip_interface("10.0.0.5/24")],
        mtu=1500,
        raw={"flags": 1},
        is_loopback=False,
    )


SAMPLES = {
    "Host": lambda: Host("db.internal"),
    "MACAddress": lambda: MACAddress("aa:bb:cc:dd:ee:ff"),
    "PingResult": lambda: PingResult(
        True, "10.0.0.5", rtt_ms=1.5, ttl=64, src=ipaddress.ip_address("10.0.0.5")
    ),
    "Route": lambda: Route(
        "10.0.0.5",
        src=ipaddress.ip_address("10.0.0.1"),
        gateway=ipaddress.ip_address("10.0.0.254"),
        interface_index=2,
    ),
    "Interface": _interface,
    "FQDN": lambda: FQDN("www.example.com"),
}

#: One public attribute per type that must refuse assignment.
ATTRIBUTES = {
    "Host": "value",
    "MACAddress": "_octets",
    "PingResult": "ok",
    "Route": "gateway",
    "Interface": "name",
    "FQDN": "_labels",
}


@pytest.mark.parametrize("kind", sorted(SAMPLES))
def test_assigning_or_deleting_an_attribute_raises(kind):
    """A value that can be assigned to is not a value: it breaks as a key."""
    value = SAMPLES[kind]()
    with pytest.raises(AttributeError):
        setattr(value, ATTRIBUTES[kind], None)
    with pytest.raises(AttributeError):
        delattr(value, ATTRIBUTES[kind])
    with pytest.raises(AttributeError):
        value.something_new = 1


@pytest.mark.parametrize("kind", sorted(SAMPLES))
@pytest.mark.parametrize(
    "roundtrip",
    [
        copy.copy,
        copy.deepcopy,
        lambda v: pickle.loads(pickle.dumps(v)),
        lambda v: pickle.loads(pickle.dumps(v, protocol=0)),
    ],
    ids=["copy", "deepcopy", "pickle", "pickle0"],
)
def test_copy_and_pickle_round_trip(kind, roundtrip):
    """The default restore assigns slots one by one and hits the read-only guard."""
    value = SAMPLES[kind]()
    again = roundtrip(value)
    assert again == value
    assert hash(again) == hash(value)
    assert type(again) is type(value)


def test_an_interface_round_trips_every_field_including_the_loopback_flag():
    """The flag is outside equality, so an equality check alone would not see it drop."""
    flagged = Interface("lo", is_loopback=True)
    assert pickle.loads(pickle.dumps(flagged)).is_loopback is True
    assert pickle.loads(pickle.dumps(_interface())).raw == {"flags": 1}
    assert copy.deepcopy(Interface("x")).is_loopback is False


def test_interface_ips_is_a_tuple_whatever_the_caller_passed():
    """A list handed to the constructor must not stay shared with the caller."""
    addresses = [ipaddress.ip_interface("10.0.0.5/24")]
    iface = Interface("eth0", ips=addresses)
    addresses.append(ipaddress.ip_interface("10.0.0.6/24"))
    assert iface.ips == (ipaddress.ip_interface("10.0.0.5/24"),)
    assert Interface("none").ips == ()


def test_interface_has_no_loopback_attribute():
    """`is_loopback` is the one spelling; the stored flag is private."""
    assert not hasattr(Interface("lo"), "loopback")


def test_a_host_still_memoises_though_it_cannot_be_assigned(monkeypatch):
    """The memo is written around the guard; losing that makes every call re-resolve."""
    host = Host("10.0.0.5")
    first = host.ip()
    assert first == ipaddress.ip_address("10.0.0.5")
    assert host.ip() is first


def test_enumerated_interfaces_are_read_only():
    """The ctypes builders construct once; none may leave a mutable object."""
    for iface in netimps.get_interfaces():
        assert isinstance(iface.ips, tuple)
        with pytest.raises(AttributeError):
            iface.mac = None  # type: ignore[misc]
