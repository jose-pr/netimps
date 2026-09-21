"""Tests for native interface enumeration.

The ctypes paths cannot be asserted against fixed values -- the host's adapters
are whatever they are -- so these check *invariants* (shapes, types, internal
consistency) rather than specific addresses, plus the pure helpers and the
fallback path, which are testable exactly.
"""

import ctypes
import ipaddress
import socket

import pytest

import netimps
from netimps import Interface, MACAddress, get_interfaces, iter_addresses
from netimps import _ifaddrs, _iface_spec

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


def test_is_loopback_uses_the_kernel_flag_not_the_name():
    """The kernel's own answer wins, and the name is never consulted.

    ``loopback=`` is what enumeration fills from ``IFF_LOOPBACK`` (POSIX) or
    ``IF_TYPE_SOFTWARE_LOOPBACK`` (Windows). Names differ per OS and are
    meaningless; the flag does not.
    """
    # Named like a Windows adapter, flagged by the kernel.
    win_style = Interface(
        name="Loopback Pseudo-Interface 1",
        ips=[ipaddress.ip_interface("127.0.0.1/8"), ipaddress.ip_interface("::1/128")],
        loopback=True,
    )
    assert win_style.is_loopback

    # Named "lo", and the kernel says it is not one. The name loses.
    liar = Interface(
        name="lo", ips=[ipaddress.ip_interface("127.0.0.1/8")], loopback=False
    )
    assert not liar.is_loopback


def test_is_loopback_flag_wins_over_a_routable_address():
    """A loopback interface carrying a routable address is still loopback.

    Regression, WSL2: ``lo`` gets the host-gateway address
    ``10.255.255.254/32`` bound to it on every installation, and the old
    address heuristic concluded from that routable address that the host had
    *no* loopback interface at all. Same shape on any keepalived / anycast /
    VIP host, where binding a service address to ``lo`` is the standard
    pattern. Needs no particular host to reproduce.
    """
    wsl_lo = Interface(
        name="lo",
        ips=[
            ipaddress.ip_interface("127.0.0.1/8"),
            ipaddress.ip_interface("10.255.255.254/32"),
            ipaddress.ip_interface("::1/128"),
        ],
        loopback=True,
    )
    assert wsl_lo.is_loopback
    # ...and the heuristic alone -- no flag -- is exactly what got it wrong.
    assert not Interface(name="lo", ips=list(wsl_lo.ips)).is_loopback


def test_is_loopback_falls_back_to_addresses_without_a_flag():
    """Hand-built objects and the degraded path report no flag."""
    # Named like a Windows adapter, but carrying loopback addresses.
    win_style = Interface(
        name="Loopback Pseudo-Interface 1",
        ips=[ipaddress.ip_interface("127.0.0.1/8"), ipaddress.ip_interface("::1/128")],
    )
    assert win_style.loopback is None
    assert win_style.is_loopback

    # Named "lo" but holding a routable address -- must NOT be loopback.
    liar = Interface(name="lo", ips=[ipaddress.ip_interface("10.0.0.5/24")])
    assert not liar.is_loopback

    # No addresses at all is not loopback (nothing to conclude from).
    assert not Interface(name="lo").is_loopback


def test_is_loopback_tolerates_a_link_local_address():
    """macOS lo0 carries fe80::1 alongside the loopback addresses.

    Regression: an "every address is loopback" test reports lo0 as
    non-loopback there, which broke interface_for() and bind(interface=) on
    macOS CI. Link-local addresses are not routable, so they do not make an
    interface non-loopback.
    """
    macos_lo0 = Interface(
        name="lo0",
        ips=[
            ipaddress.ip_interface("127.0.0.1/8"),
            ipaddress.ip_interface("::1/128"),
            ipaddress.ip_interface("fe80::1/64"),
        ],
    )
    assert macos_lo0.is_loopback

    # A routable address still disqualifies it.
    assert not Interface(
        name="eth0",
        ips=[
            ipaddress.ip_interface("10.0.0.5/24"),
            ipaddress.ip_interface("fe80::1/64"),
        ],
    ).is_loopback

    # Link-local only, with no loopback address, is not the loopback interface.
    assert not Interface(
        name="eth0", ips=[ipaddress.ip_interface("fe80::1/64")]
    ).is_loopback


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


def test_interface_is_hashable_and_agrees_with_equality():
    """Defining __eq__ without __hash__ made set(get_interfaces()) raise."""
    a = Interface(
        name="eth0",
        index=2,
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        ips=[ipaddress.ip_interface("10.0.0.5/24")],
        mtu=1500,
    )
    b = Interface(
        name="eth0",
        index=2,
        mac=MACAddress("aa:bb:cc:dd:ee:ff"),
        ips=[ipaddress.ip_interface("10.0.0.5/24")],
        mtu=1500,
    )
    assert a == b and hash(a) == hash(b)
    assert len({a, b}) == 1
    assert {a: "v"}[b] == "v"
    assert Interface.__hash__ is not None


def test_live_interfaces_go_into_a_set():
    """The obvious operation on the package's flagship return value."""
    ifaces = get_interfaces()
    assert set(ifaces) == set(get_interfaces())
    # Duplicates collapse, which is the point of putting them in a set.
    assert len(set(ifaces + ifaces)) == len(set(ifaces))


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


def test_some_interface_reports_is_loopback():
    """A host with a loopback address must have an interface that admits it.

    This assertion is the point of the fix: two tests in
    ``test_centralized.py`` open with ``next(i for i in get_interfaces() if
    i.is_loopback)`` and skip when it is ``None`` -- a skip the author marked
    ``# pragma: no cover`` as unreachable, and which on WSL2 was the branch
    that *always* ran. A silent skip is worse than a failure; assert it here so
    the same regression is loud.
    """
    ifaces = get_interfaces()
    if not any(ip.ip.is_loopback for i in ifaces for ip in i.ips):
        pytest.skip("no loopback address bound on this host")
    assert [i.name for i in ifaces if i.is_loopback]


def test_enumerated_macs_are_never_all_zero():
    """Linux reports the loopback MAC as 00:00:00:00:00:00; nobody else does.

    ``iface.mac is None`` has to mean the same thing on every platform, or a
    per-platform branch appears in caller code.
    """
    assert _ifaddrs._mac(b"\x00" * 6) is None
    # A MAC that merely *starts* with zero bytes is still a MAC.
    assert _ifaddrs._mac(b"\x00\x00\x5e\x00\x53\x01") == MACAddress("00:00:5e:00:53:01")
    for iface in get_interfaces():
        assert iface.mac is None or int(iface.mac) != 0


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


def test_fallback_reports_host_routes(no_such_host):
    ifaces = _ifaddrs._fallback_interfaces(False)
    assert len(ifaces) == 1
    iface = ifaces[0]
    assert iface.name == "<unknown>"
    assert iface.mac is None
    # Degraded mode: every address is a host route, since no real prefix is
    # available without the native call.
    for ip in iface.ips:
        assert ip.network.prefixlen == ip.max_prefixlen


def test_get_interfaces_degrades_instead_of_raising(monkeypatch, no_such_host):
    """A failing native call must not propagate -- callers get the fallback."""

    def boom(_raw):
        raise OSError("native enumeration exploded")

    monkeypatch.setattr(_ifaddrs, "_windows_interfaces", boom)
    monkeypatch.setattr(_ifaddrs, "_posix_interfaces", boom)

    ifaces = _ifaddrs.get_interfaces()
    assert ifaces and ifaces[0].name == "<unknown>"


def test_fallback_raw_flags_degradation(monkeypatch, no_such_host):
    def boom(_raw):
        raise OSError("nope")

    monkeypatch.setattr(_ifaddrs, "_windows_interfaces", boom)
    monkeypatch.setattr(_ifaddrs, "_posix_interfaces", boom)

    iface = _ifaddrs.get_interfaces(raw=True)[0]
    assert iface.raw["degraded"] is True


def test_exported_from_package():
    assert netimps.get_interfaces is _ifaddrs.get_interfaces
    assert netimps.Interface is _ifaddrs.Interface


# --------------------------------------------------------------------------- #
# Interface.primary_ip                                                            #
# --------------------------------------------------------------------------- #


def test_primary_ip_prefers_non_loopback():
    iface = Interface(
        name="eth0",
        ips=[
            ipaddress.ip_interface("127.0.0.1/8"),
            ipaddress.ip_interface("10.0.0.5/24"),
        ],
    )
    assert iface.primary_ip() == ipaddress.ip_interface("10.0.0.5/24")


def test_primary_ip_falls_back_to_loopback_only_if_thats_all():
    iface = Interface(name="lo", ips=[ipaddress.ip_interface("127.0.0.1/8")])
    assert iface.primary_ip() == ipaddress.ip_interface("127.0.0.1/8")
    # ...unless the caller needs something routable.
    assert iface.primary_ip(loopback_ok=False) is None


def test_primary_ip_family_selection():
    iface = Interface(
        name="eth0",
        ips=[
            ipaddress.ip_interface("10.0.0.5/24"),
            ipaddress.ip_interface("2001:db8::1/64"),
        ],
    )
    assert iface.primary_ip() == ipaddress.ip_interface("10.0.0.5/24")
    assert iface.primary_ip(ipv6=True) == ipaddress.ip_interface("2001:db8::1/64")


def test_primary_ip_returns_none_when_family_absent():
    iface = Interface(name="eth0", ips=[ipaddress.ip_interface("10.0.0.5/24")])
    assert iface.primary_ip(ipv6=True) is None
    assert Interface(name="empty").primary_ip() is None


def test_primary_ip_returns_parsed_not_string():
    """Same element type as .ips -- one of them, not a different shape."""
    for iface in get_interfaces():
        chosen = iface.primary_ip()
        if chosen is not None:
            assert not isinstance(chosen, str)
            assert isinstance(chosen, (ipaddress.IPv4Address, ipaddress.IPv6Address))


# --------------------------------------------------------------------------- #
# macOS/BSD sockaddr_dl MAC extraction                                         #
# --------------------------------------------------------------------------- #


_VRRP_MAC = b"\x00\x00\x5e\x00\x53\x01"


def _fake_sockaddr_dl(name, mac=_VRRP_MAC, sdl_len=None):
    """Build a BSD ``sockaddr_dl`` the way ``getifaddrs`` reports one.

    Returns ``(buffer, struct)`` -- the buffer must be kept alive by the
    caller, since the struct only points into it. The allocation is sized the
    way the kernel sizes it (header + name + address), which is the whole
    point: it is usually *smaller* than ``sizeof(_SockaddrDl)``.
    """
    from netimps._ifaddrs import _SockaddrDl

    offset = _SockaddrDl.sdl_data.offset
    size = offset + len(name) + len(mac)
    buf = ctypes.create_string_buffer(size)
    sdl = ctypes.cast(buf, ctypes.POINTER(_SockaddrDl)).contents
    sdl.sdl_len = size if sdl_len is None else sdl_len
    sdl.sdl_family = 18  # AF_LINK
    sdl.sdl_nlen = len(name)
    sdl.sdl_alen = len(mac)
    ctypes.memmove(ctypes.addressof(sdl) + offset, name + mac, len(name) + len(mac))
    return buf, sdl


def test_sockaddr_dl_matches_the_c_struct():
    """20 bytes, as ``net/if_dl.h`` declares it -- not 54.

    Regression: ``sdl_data`` was declared at 46 bytes and the whole of it was
    read, so every MAC extraction over-read the kernel's allocation by 34
    bytes. It never faulted (getifaddrs returns one contiguous arena) and the
    extracted MAC was right, but it was undefined behaviour one page boundary
    away from a crash.
    """
    from netimps._ifaddrs import _SockaddrDl

    assert ctypes.sizeof(_SockaddrDl) == 20
    assert _SockaddrDl.sdl_data.offset == 8
    assert _SockaddrDl.sdl_data.size == 12


def test_sockaddr_dl_mac_extraction():
    """The AF_LINK branch reads the MAC through the struct's own address.

    Regression: `sdl_data` is a `c_char` array, so ctypes converts it to
    `bytes` on attribute access -- `addressof()` on that copy raises
    `TypeError: addressof() argument must be _ctypes._CData, not bytes`. Only
    macOS/BSD take this branch, so CI on those runners was the first to see it.

    The MAC also starts `sdl_nlen` bytes in, after the interface name, rather
    than at a fixed offset.
    """
    _buf, sdl = _fake_sockaddr_dl(b"en01")
    assert _ifaddrs._mac_from_sockaddr_dl(sdl) == MACAddress("00:00:5e:00:53:01")


def test_sockaddr_dl_mac_past_the_declared_end_of_sdl_data():
    """``sockaddr_dl`` is variable-length: a long name pushes the MAC out.

    ``sdl_data`` is 12 bytes in the C declaration, so a 14-character adapter
    name puts the hardware address entirely beyond it -- and ``sdl_len``, the
    kernel's own size, is what says those bytes exist.
    """
    name = b"bridge-example"  # 14 > sizeof(sdl_data)
    _buf, sdl = _fake_sockaddr_dl(name)
    assert sdl.sdl_len == 8 + len(name) + 6
    assert _ifaddrs._mac_from_sockaddr_dl(sdl) == MACAddress("00:00:5e:00:53:01")


def test_sockaddr_dl_refuses_to_read_past_sdl_len():
    """The bound is the kernel's, not the struct declaration's."""
    _buf, sdl = _fake_sockaddr_dl(b"en01", sdl_len=12)  # header + name only
    assert _ifaddrs._mac_from_sockaddr_dl(sdl) is None


def test_sockaddr_dl_without_a_six_byte_address():
    """Tunnels and the like report ``sdl_alen`` 0; there is no MAC to read."""
    _buf, sdl = _fake_sockaddr_dl(b"utun0", mac=b"")
    assert _ifaddrs._mac_from_sockaddr_dl(sdl) is None


def test_sockaddr_dl_data_is_not_addressable_directly():
    """Pins *why* the offset arithmetic is needed, so it is not 'simplified'."""
    from netimps._ifaddrs import _SockaddrDl

    sdl = _SockaddrDl()
    with pytest.raises(TypeError):
        ctypes.addressof(sdl.sdl_data)


# --------------------------------------------------------------------------- #
# iter_addresses                                                               #
# --------------------------------------------------------------------------- #


def test_iter_addresses_validates_family_eagerly():
    """The ValueError must come from the *call*, not the first next().

    A bad argument reported on first iteration surfaces from a stack frame
    that no longer names the caller -- and a caller that builds the iterator
    and never consumes it never hears about it at all.
    """
    with pytest.raises(ValueError):
        iter_addresses(family=99)  # deliberately not wrapped in list()


def test_iter_addresses_family_error_names_both_conventions():
    """``family=`` takes 4/6 here and AF_* next door; say so in the message."""
    with pytest.raises(ValueError, match=r"socket\.AF_INET6.*wants 6"):
        iter_addresses(family=socket.AF_INET6)
    with pytest.raises(ValueError, match=r"socket\.AF_INET.*wants 4"):
        iter_addresses(family=socket.AF_INET)


def test_iter_addresses_still_yields_pairs():
    ifaces = [
        Interface(
            name="eth0",
            ips=[
                ipaddress.ip_interface("10.0.0.5/24"),
                ipaddress.ip_interface("fe80::1/64"),
            ],
        )
    ]
    assert [str(a) for _i, a in iter_addresses(ifaces)] == ["10.0.0.5/24", "fe80::1/64"]
    assert [str(a) for _i, a in iter_addresses(ifaces, family=4)] == ["10.0.0.5/24"]
    assert [str(a) for _i, a in iter_addresses(ifaces, family=6)] == ["fe80::1/64"]


# --------------------------------------------------------------------------- #
# _iface_spec: one rule for both resolutions                                   #
# --------------------------------------------------------------------------- #


@pytest.fixture
def one_adapter(monkeypatch):
    """A single known adapter, so the assertions are exact, not host-dependent.

    Everything reaches enumeration through ``._ifaddrs.get_interfaces`` (a
    function-local import in each caller), so one patch covers them all.
    """
    adapter = Interface(
        name="fake0",
        index=37,
        mac=MACAddress("02:00:00:00:00:01"),
        ips=[
            ipaddress.ip_interface("192.0.2.10/24"),
            ipaddress.ip_interface("2001:db8::10/64"),
        ],
    )
    monkeypatch.setattr(_ifaddrs, "get_interfaces", lambda **k: [adapter])
    return adapter


def test_interface_address_honours_the_wanted_family(one_adapter):
    """A wrong-family literal used to reach inet_aton/bind and fail there."""
    with pytest.raises(ValueError, match="IPv4 one was requested"):
        _iface_spec.interface_address("2001:db8::10", want_ipv6=False)
    with pytest.raises(ValueError, match="IPv6 one was requested"):
        _iface_spec.interface_address("192.0.2.10", want_ipv6=True)
    # Either family: no check.
    assert str(_iface_spec.interface_address("2001:db8::10", want_ipv6=None)) == (
        "2001:db8::10"
    )


def test_interface_address_tolerant_callers_still_see_the_address(one_adapter):
    """strict=False hands the address back for the caller to judge.

    ``_udp`` maps an IPv4 source for an IPv6 socket to a v4-mapped address and
    raises its own message for the reverse, so it must receive the address
    rather than ``None``.
    """
    resolved = _iface_spec.interface_address(
        "2001:db8::10", want_ipv6=False, strict=False
    )
    assert str(resolved) == "2001:db8::10"


def test_both_resolutions_apply_the_same_locality_rule(one_adapter):
    """The same spec must not be accepted for IPv4 and rejected for IPv6.

    ``interface_address`` used to pass any parseable literal straight through
    while ``interface_index`` insisted the address be held locally -- so an
    IPv4 multicast join to an address this host does not have was accepted and
    the identical IPv6 one refused.
    """
    with pytest.raises(ValueError, match="no local interface holds address"):
        _iface_spec.interface_address("198.51.100.7")
    with pytest.raises(ValueError, match="no local interface holds address"):
        _iface_spec.interface_index("198.51.100.7")

    assert str(_iface_spec.interface_address("192.0.2.10")) == "192.0.2.10"
    assert _iface_spec.interface_index("192.0.2.10") == 37

    # Tolerant callers keep the old leniency, which _udp documents and uses.
    assert (
        str(_iface_spec.interface_address("198.51.100.7", strict=False))
        == "198.51.100.7"
    )
    assert _iface_spec.interface_index("198.51.100.7", strict=False) is None


def test_locality_rule_steps_aside_for_degraded_enumeration(monkeypatch, no_such_host):
    """Nothing to check against when enumeration itself fell back.

    The fallback reports one ``"<unknown>"`` interface holding whatever
    ``getaddrinfo(gethostname())`` returned -- never 127.0.0.1 -- so checking
    an address against it would reject addresses the host really has.
    """
    monkeypatch.setattr(
        _ifaddrs, "get_interfaces", lambda **k: _ifaddrs._fallback_interfaces(False)
    )
    assert str(_iface_spec.interface_address("198.51.100.7")) == "198.51.100.7"


def test_interface_spec_honours_a_zone_suffix(one_adapter):
    """``%zone`` is the part of a scoped address that names an interface.

    ``ipaddress`` keeps the zone, so ``fe80::1%12`` equals no enumerated
    address and every scoped literal failed the lookup outright.
    """
    # Numeric zone (Linux, Windows): the index the OS itself wrote.
    assert _iface_spec.interface_index("fe80::1%37") == 37
    # Named zone (macOS, BSD).
    assert _iface_spec.interface_index("fe80::1%fake0") == 37
    # The address keeps its zone; only the lookup drops it.
    resolved = _iface_spec.interface_address("2001:db8::10%fake0", want_ipv6=True)
    assert str(resolved) == "2001:db8::10%fake0"
