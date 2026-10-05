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
import socket

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
        True, "10.0.0.5", rtt=0.0015, ttl=64, src=ipaddress.ip_address("10.0.0.5")
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
    calls = []

    def counting(name, *args, **kwargs):
        calls.append(name)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.9", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", counting)
    host = Host("db.internal")
    first = host.ip()
    assert first == ipaddress.ip_address("192.0.2.9")
    assert host.ip() is first
    assert len(calls) == 1


def test_enumerated_interfaces_are_read_only():
    """The ctypes builders construct once; none may leave a mutable object."""
    for iface in netimps.get_interfaces():
        assert isinstance(iface.ips, tuple)
        with pytest.raises(AttributeError):
            iface.mac = None  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# A subclass comes back as itself                                              #
# --------------------------------------------------------------------------- #


class _SubMAC(MACAddress):
    pass


class _SubHost(Host):
    pass


class _SubFQDN(FQDN):
    pass


_SUBCLASSES = {
    "MACAddress": lambda: _SubMAC("aa:bb:cc:dd:ee:ff"),
    "Host": lambda: _SubHost("db.internal"),
    "FQDN": lambda: _SubFQDN("www.example.com"),
    "FQDN derived": lambda: _SubFQDN("1.2.3.4.sub").reverse(),
}


@pytest.mark.parametrize("kind", sorted(_SUBCLASSES))
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
def test_copy_and_pickle_keep_the_subclass(kind, roundtrip):
    """`__reduce__` named the base class, so a subclass came back as its parent
    and lost every method it added."""
    value = _SUBCLASSES[kind]()
    again = roundtrip(value)
    assert type(again) is type(value)
    assert again == value


def test_an_fqdn_pickled_before_the_class_was_recorded_still_loads():
    """The unpickle function keeps its two-argument form, so a pickle written
    without the class loads as an `FQDN`."""
    # Private: the pickle restore hook is not public.
    from netimps._fqdn import _rebuild_fqdn

    assert _rebuild_fqdn(("a", "b"), True) == FQDN("a.b.")
