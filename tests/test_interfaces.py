"""Tests for native interface enumeration.

The ctypes paths cannot be asserted against fixed values -- the host's adapters
are whatever they are -- so these check *invariants* (shapes, types, internal
consistency) rather than specific addresses, plus the pure helpers and the
fallback path, which are testable exactly.
"""

import ipaddress

import pytest

import netimps
from netimps import Interface, MACAddress, get_interfaces
from netimps import _ifaddrs

# --------------------------------------------------------------------------- #
# Pure helpers                                                                 #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "mask, expected",
    [
        (b"\xff\xff\xff\x00", 24),
        (b"\xff\xff\xff\xff", 32),
        (b"\x00\x00\x00\x00", 0),
        (b"\xff\xff\xf0\x00", 20),
        (b"\xff\x00\x00\x00", 8),
        (b"\xff\xff\xff\xfc", 30),
    ],
)
def test_prefix_from_netmask_ipv4(mask, expected):
    assert _ifaddrs._prefix_from_netmask(mask) == expected


def test_prefix_from_netmask_ipv6():
    assert _ifaddrs._prefix_from_netmask(b"\xff" * 8 + b"\x00" * 8) == 64
    assert _ifaddrs._prefix_from_netmask(b"\xff" * 16) == 128


def test_prefix_stops_at_first_zero_bit():
    """A non-contiguous mask must not over-count trailing set bits."""
    # 0xff 0x0f -> counting stops after the 8 leading ones.
    assert _ifaddrs._prefix_from_netmask(b"\xff\x0f\xff\xff") == 8


def test_make_ip_interface_rejects_garbage():
    assert _ifaddrs._make_ip_interface("not-an-ip", 24) is None
    assert _ifaddrs._make_ip_interface("10.0.0.1", 99) is None
    assert _ifaddrs._make_ip_interface("10.0.0.1", 24) is not None


# --------------------------------------------------------------------------- #
# Interface value type                                                         #
# --------------------------------------------------------------------------- #


def test_is_loopback_uses_addresses_not_name():
    """The whole point of the property: names differ per OS, addresses do not."""
    # Named like a Windows adapter, but carrying loopback addresses.
    win_style = Interface(
        name="Loopback Pseudo-Interface 1",
        ips=[ipaddress.ip_interface("127.0.0.1/8"), ipaddress.ip_interface("::1/128")],
    )
    assert win_style.is_loopback

    # Named "lo" but holding a routable address -- must NOT be loopback.
    liar = Interface(name="lo", ips=[ipaddress.ip_interface("10.0.0.5/24")])
    assert not liar.is_loopback

    # No addresses at all is not loopback (nothing to conclude from).
    assert not Interface(name="lo").is_loopback


def test_ipv4_ipv6_split():
    iface = Interface(
        name="eth0",
        ips=[
            ipaddress.ip_interface("10.0.0.5/24"),
            ipaddress.ip_interface("fe80::1/64"),
        ],
    )
    assert [str(i) for i in iface.ipv4] == ["10.0.0.5/24"]
    assert [str(i) for i in iface.ipv6] == ["fe80::1/64"]


def test_interface_repr_and_equality():
    a = Interface(name="eth0", index=2, mac=MACAddress("aa:bb:cc:dd:ee:ff"))
    b = Interface(name="eth0", index=2, mac=MACAddress("aa:bb:cc:dd:ee:ff"))
    assert a == b
    assert a != Interface(name="eth1", index=2)
    assert a != "not an interface"
    assert "eth0" in repr(a)
    assert "aa:bb:cc:dd:ee:ff" in repr(a)


# --------------------------------------------------------------------------- #
# Live enumeration -- invariants only                                          #
# --------------------------------------------------------------------------- #


def test_get_interfaces_returns_usable_data():
    ifaces = get_interfaces()
    assert ifaces, "every host has at least one interface"
    for iface in ifaces:
        assert isinstance(iface.name, str) and iface.name
        assert isinstance(iface.index, int)
        assert iface.mac is None or isinstance(iface.mac, MACAddress)
        for ip in iface.ips:
            # Real ip_interface objects, so .network/.ip behave as the stdlib does.
            assert isinstance(ip, (ipaddress.IPv4Interface, ipaddress.IPv6Interface))
            assert ip.network.prefixlen <= ip.max_prefixlen


def test_loopback_is_present_somewhere():
    """127.0.0.1 or ::1 must show up on any host, under whatever adapter name."""
    all_ips = [ip.ip for iface in get_interfaces() for ip in iface.ips]
    assert any(ip.is_loopback for ip in all_ips), all_ips


def test_raw_is_opt_in():
    assert all(i.raw is None for i in get_interfaces())
    with_raw = get_interfaces(raw=True)
    assert all(isinstance(i.raw, dict) for i in with_raw)


def test_enumeration_is_stable():
    """Two consecutive calls agree -- no leaked state between invocations."""
    assert get_interfaces() == get_interfaces()


# --------------------------------------------------------------------------- #
# Fallback path                                                                #
# --------------------------------------------------------------------------- #


def test_fallback_reports_host_routes():
    ifaces = _ifaddrs._fallback_interfaces(False)
    assert len(ifaces) == 1
    iface = ifaces[0]
    assert iface.name == "<unknown>"
    assert iface.mac is None
    # Degraded mode: every address is a host route, since no real prefix is
    # available without the native call.
    for ip in iface.ips:
        assert ip.network.prefixlen == ip.max_prefixlen


def test_get_interfaces_degrades_instead_of_raising(monkeypatch):
    """A failing native call must not propagate -- callers get the fallback."""

    def boom(_raw):
        raise OSError("native enumeration exploded")

    monkeypatch.setattr(_ifaddrs, "_windows_interfaces", boom)
    monkeypatch.setattr(_ifaddrs, "_posix_interfaces", boom)

    ifaces = _ifaddrs.get_interfaces()
    assert ifaces and ifaces[0].name == "<unknown>"


def test_fallback_raw_flags_degradation(monkeypatch):
    def boom(_raw):
        raise OSError("nope")

    monkeypatch.setattr(_ifaddrs, "_windows_interfaces", boom)
    monkeypatch.setattr(_ifaddrs, "_posix_interfaces", boom)

    iface = _ifaddrs.get_interfaces(raw=True)[0]
    assert iface.raw["degraded"] is True


def test_exported_from_package():
    assert netimps.get_interfaces is _ifaddrs.get_interfaces
    assert netimps.Interface is _ifaddrs.Interface
