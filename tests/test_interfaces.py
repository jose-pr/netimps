"""Tests for native interface enumeration.

The ctypes paths cannot be asserted against fixed values -- the host's adapters
are whatever they are -- so these check *invariants* (shapes, types, internal
consistency) rather than specific addresses, plus the pure helpers and the
fallback path, which are testable exactly.
"""

import ctypes
import ipaddress
import math
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

    ``is_loopback=`` is what enumeration fills from ``IFF_LOOPBACK`` (POSIX) or
    ``IF_TYPE_SOFTWARE_LOOPBACK`` (Windows). Names differ per OS and are
    meaningless; the flag does not.
    """
    # Named like a Windows adapter, flagged by the kernel.
    win_style = Interface(
        name="Loopback Pseudo-Interface 1",
        ips=[ipaddress.ip_interface("127.0.0.1/8"), ipaddress.ip_interface("::1/128")],
        is_loopback=True,
    )
    assert win_style.is_loopback

    # Named "lo", and the kernel says it is not one. The name loses.
    liar = Interface(
        name="lo", ips=[ipaddress.ip_interface("127.0.0.1/8")], is_loopback=False
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
        is_loopback=True,
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
    assert win_style.is_loopback

    # Named "lo" but holding a routable address -- must NOT be loopback.
    liar = Interface(name="lo", ips=[ipaddress.ip_interface("10.0.0.5/24")])
    assert not liar.is_loopback

    # No addresses at all is not loopback (nothing to conclude from).
    assert not Interface(name="lo").is_loopback


def test_is_loopback_tolerates_a_link_local_address():
    """macOS lo0 carries fe80::1 alongside the loopback addresses.

    Regression: an "every address is loopback" test reports lo0 as
    non-loopback there, which broke get_interface() and bind(interface=) on
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


# --------------------------------------------------------------------------- #
# The opt-in enumeration cache                                                #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _clean_interface_cache():
    """No test may inherit or leave a cached enumeration.

    The cache is process-wide, so a leaked entry would make a later test pass
    for the wrong reason -- or fail depending on execution order, which is
    worse.
    """
    netimps.clear_interface_cache()
    yield
    netimps.clear_interface_cache()


class _Enumerations:
    """How many real enumerations happen inside the block, via the public API.

    Deliberately not a monkeypatch of the private `_enumerate_interfaces`: that
    is what `interface_enumerations()` exists to replace, and a test coupled to
    an internal cannot notice when the public counter stops working.
    """

    def __init__(self):
        self._before = netimps.interface_enumerations()

    def __len__(self):
        return netimps.interface_enumerations() - self._before


def _counting_enumerator(monkeypatch):
    """Count real enumerations from here on. `monkeypatch` is unused now."""
    return _Enumerations()


def test_the_default_does_not_cache_at_all(monkeypatch):
    """`cache=False` must be exactly the old behaviour: every call enumerates.

    A cache that switched itself on would turn a cheap correct call into a
    cheap stale one, which is the failure mode worth guarding against here.
    """
    calls = _counting_enumerator(monkeypatch)
    for _ in range(3):
        netimps.get_interfaces()
    assert len(calls) == 3


def test_cache_true_collapses_repeated_calls(monkeypatch):
    """One enumeration for a burst, which is the whole point."""
    calls = _counting_enumerator(monkeypatch)
    first = netimps.get_interfaces(cache=True)
    for _ in range(20):
        assert netimps.get_interfaces(cache=True) == first
    assert len(calls) == 1


def test_a_number_is_a_ttl_in_seconds(monkeypatch):
    calls = _counting_enumerator(monkeypatch)
    netimps.get_interfaces(cache=5.0)
    netimps.get_interfaces(cache=5.0)
    assert len(calls) == 1


def test_the_ttl_expires(monkeypatch):
    """Asserted against a fake clock, not by sleeping.

    A real sleep would make this test slow *and* flaky; the TTL is a comparison
    against `time.monotonic`, so moving that is the honest way to test it.
    """
    from netimps import _ifaddrs

    calls = _counting_enumerator(monkeypatch)
    now = [1000.0]
    monkeypatch.setattr(_ifaddrs._time, "monotonic", lambda: now[0])

    netimps.get_interfaces(cache=1.0)
    now[0] += 0.5
    netimps.get_interfaces(cache=1.0)
    assert len(calls) == 1, "expired early"
    now[0] += 0.6  # now 1.1s past the first call
    netimps.get_interfaces(cache=1.0)
    assert len(calls) == 2, "did not expire"


def test_cache_zero_means_always_stale_not_no_cache(monkeypatch):
    """`cache=0` is the reseed, and the reason there is no `refresh=` argument.

    A TTL of zero is always expired, so it enumerates *and* stores -- after
    which a normal cached call is served from the fresh entry. Truthiness
    testing would have made this "do not cache" and left a second argument
    necessary.
    """
    calls = _counting_enumerator(monkeypatch)
    netimps.get_interfaces(cache=True)
    assert len(calls) == 1
    netimps.get_interfaces(cache=0)
    assert len(calls) == 2, "cache=0 did not re-enumerate"
    netimps.get_interfaces(cache=True)
    assert len(calls) == 2, "cache=0 did not reseed the entry"


def test_cache_one_is_a_one_second_ttl_not_the_default(monkeypatch):
    """`cache=1` must not be read as `cache=True`.

    `1 == True` in Python, so only an identity test tells them apart. With
    `INTERFACE_CACHE_TTL` at 1.0 they happen to coincide today, so this asserts
    the discrimination directly rather than through observable timing.
    """
    from netimps import _ifaddrs

    monkeypatch.setattr(_ifaddrs, "INTERFACE_CACHE_TTL", 999.0)
    calls = _counting_enumerator(monkeypatch)
    now = [1000.0]
    monkeypatch.setattr(_ifaddrs._time, "monotonic", lambda: now[0])

    netimps.get_interfaces(cache=1)
    now[0] += 2.0
    netimps.get_interfaces(cache=1)
    assert len(calls) == 2, "cache=1 was treated as the default TTL"


def test_infinite_ttl_never_expires_and_clear_is_the_invalidation(monkeypatch):
    """The strategy to prefer when the caller knows what changes the answer.

    A TTL is a guess; an event is not. This is the shape a DHCP server arrived
    at independently -- cache indefinitely, clear on `bind()`.
    """
    from netimps import _ifaddrs

    calls = _counting_enumerator(monkeypatch)
    now = [1000.0]
    monkeypatch.setattr(_ifaddrs._time, "monotonic", lambda: now[0])

    netimps.get_interfaces(cache=math.inf)
    now[0] += 10_000.0
    netimps.get_interfaces(cache=math.inf)
    assert len(calls) == 1, "an infinite TTL expired"

    netimps.clear_interface_cache()
    netimps.get_interfaces(cache=math.inf)
    assert len(calls) == 2, "clear_interface_cache did not invalidate"


def test_clear_is_harmless_when_nothing_is_cached():
    netimps.clear_interface_cache()
    netimps.clear_interface_cache()


def test_raw_is_cached_separately(monkeypatch):
    """The two return different data; one entry for both would hand a caller
    the wrong shape."""
    calls = _counting_enumerator(monkeypatch)
    netimps.get_interfaces(cache=True)
    netimps.get_interfaces(raw=True, cache=True)
    assert len(calls) == 2, "raw and non-raw must be cached separately"
    plain = netimps.get_interfaces(cache=True)
    raw = netimps.get_interfaces(raw=True, cache=True)
    assert len(calls) == 2
    assert all(i.raw is None for i in plain)
    # `raw` is populated where the platform supplies anything at all.
    assert any(i.raw is not None for i in raw) or not raw


def test_a_cached_call_cannot_be_corrupted_by_its_caller():
    """**The hazard a cache introduces.**

    A cache that hands the stored objects to every caller lets one caller's
    change reach the next. `Interface` cannot change after construction and
    `.ips` is a tuple, so the only thing left to corrupt is the returned list
    itself, which is the caller's own.
    """
    first = netimps.get_interfaces(cache=math.inf)
    if not first:
        pytest.skip("no interfaces to mutate")
    with pytest.raises(AttributeError):
        first[0].name = "renamed"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        first[0].ips.append("poison")  # type: ignore[attr-defined]
    first.append("appended to the list")  # type: ignore[arg-type]

    second = netimps.get_interfaces(cache=math.inf)
    assert second[0].name != "renamed"
    assert "appended to the list" not in second
    assert isinstance(second[0].ips, tuple)


def test_a_cached_raw_dict_is_also_copied():
    """`.raw` is a dict, so it is the one field a caller could still mutate."""
    found = netimps.get_interfaces(raw=True, cache=math.inf)
    with_raw = [i for i in found if i.raw is not None]
    if not with_raw:
        pytest.skip("this platform populated no raw data")
    with_raw[0].raw["poison"] = True
    again = netimps.get_interfaces(raw=True, cache=math.inf)
    assert all("poison" not in (i.raw or {}) for i in again)


@pytest.mark.parametrize(
    "call",
    [
        lambda c: netimps.get_interface("127.0.0.1", cache=c),
        lambda c: list(netimps.iter_interfaces("127.0.0.1", cache=c)),
        lambda c: netimps.is_local_address("10.0.0.1", cache=c),
    ],
    ids=["get_interface", "iter_interfaces", "is_local_address"],
)
def test_the_query_helpers_share_the_cache(monkeypatch, call):
    """All three funnel through the same enumeration, so one argument reaches
    every one of them and they populate one shared entry."""
    calls = _counting_enumerator(monkeypatch)
    call(math.inf)
    call(math.inf)
    assert len(calls) == 1, "the helper did not use the cache"

    netimps.clear_interface_cache()
    call(False)
    call(False)
    assert len(calls) == 3, "the helper cached when it was told not to"


def test_interface_for_still_answers_the_same_with_and_without_the_cache():
    """A cache that changed the answer would be worse than no cache."""
    netimps.clear_interface_cache()
    uncached = netimps.get_interface("127.0.0.1")
    cached = netimps.get_interface("127.0.0.1", cache=math.inf)
    assert uncached == cached


def test_the_endpoint_cache_uses_the_one_shared_ttl():
    """Two caches of the same fact must not disagree about how stale is stale."""
    from netimps._udp import UDPEndpoint

    assert UDPEndpoint._IFACE_CACHE_TTL == netimps.INTERFACE_CACHE_TTL


def test_the_default_ttl_is_sized_for_a_burst():
    """Pinned so a future change to this number is deliberate.

    One second bounds the cost at a single enumeration per second whatever the
    arrival rate, which is what a burst-collapsing cache is for; it is not a
    long-lived snapshot, and a longer window would only widen the time a
    renamed adapter goes unnoticed.
    """
    assert netimps.INTERFACE_CACHE_TTL == 1.0


def test_the_uncached_path_passes_no_keyword_to_get_interfaces(monkeypatch):
    """An existing test double must keep working after this upgrade.

    A test double for `get_interfaces` may take no keyword arguments, so
    passing `cache=False` to one raises TypeError. The default path therefore
    keeps its original call shape, which is cheap to preserve and silent to
    break.
    """
    from netimps import _ifaddrs

    seen = []

    def no_kwargs_stub():
        seen.append("called")
        return []

    monkeypatch.setattr(_ifaddrs, "get_interfaces", no_kwargs_stub)
    assert netimps.get_interface("10.9.9.9") is None
    assert seen == ["called"]


def test_is_broadcast_takes_the_shared_cache(monkeypatch):
    """The one per-packet entry point the cache work had left out.

    Without an `interface` this consults every adapter's prefixes, because
    `10.0.0.255` is only a broadcast if something carries `10.0.0.0/24`.
    Measured at **1.25 ms** per call against 0.004 ms when the interface is
    passed, and a server asking the question of every request pays it per
    packet.
    """
    calls = _counting_enumerator(monkeypatch)
    address = netimps.parse("10.9.9.255")
    for _ in range(5):
        netimps.is_broadcast(address, cache=math.inf)
    assert len(calls) == 1

    netimps.clear_interface_cache()
    for _ in range(3):
        netimps.is_broadcast(address)
    assert len(calls) == 4, "the default must still enumerate every call"


def test_is_broadcast_gives_the_same_answer_cached_or_not():
    """A cache that changed the answer would be worse than no cache."""
    netimps.clear_interface_cache()
    for probe in ("255.255.255.255", "10.9.9.255", "127.0.0.1", "::1"):
        uncached = netimps.is_broadcast(probe)
        cached = netimps.is_broadcast(probe, cache=math.inf)
        assert uncached == cached, probe


def test_is_broadcast_with_an_interface_never_enumerates(monkeypatch):
    """Passing the interface stays the fastest path, and must not consult the
    cache or the syscall at all."""
    iface = netimps.get_interface("127.0.0.1")
    if iface is None:
        pytest.skip("no loopback interface resolved")
    calls = _counting_enumerator(monkeypatch)
    netimps.is_broadcast(netimps.parse("10.9.9.255"), iface)
    assert len(calls) == 0


def test_the_limited_broadcast_short_circuits_before_any_enumeration(monkeypatch):
    """`255.255.255.255` needs no context, so it must not pay for one."""
    calls = _counting_enumerator(monkeypatch)
    assert netimps.is_broadcast("255.255.255.255") is True
    assert len(calls) == 0


def test_reply_socket_does_not_enumerate_per_datagram(monkeypatch):
    """`_is_repliable` calls `is_broadcast`, so `reply_socket` inherited the
    per-call enumeration whenever the arrival index did not resolve.

    It uses the shared cache now, as the endpoint's own arrival-interface
    lookup already did.
    """
    from netimps import UDPEndpoint, bind
    from netimps._udp import Datagram

    calls = _counting_enumerator(monkeypatch)
    netimps.clear_interface_cache()
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        datagram = Datagram(
            data=b"",
            sender=("127.0.0.1", 1),
            local_address=netimps.parse("127.0.0.1"),
            interface=None,
        )
        for _ in range(5):
            endpoint.reply_socket(datagram).close()
    assert len(calls) <= 1, "enumerated more than once across five replies"


def test_interface_enumerations_counts_syscalls_not_lookups():
    """The property `cache=` exists for, made observable.

    With a cache, a lookup and an enumeration stop being the same event, and the
    enumeration is the one a packet flood multiplies -- so that is what this
    counts. Twenty cached lookups must cost exactly one.
    """
    netimps.clear_interface_cache()
    before = netimps.interface_enumerations()
    for _ in range(20):
        netimps.get_interface("127.0.0.1", cache=math.inf)
    assert netimps.interface_enumerations() - before == 1


def test_interface_enumerations_ignores_an_uncached_cache_drop():
    """Dropping a cache enumerates nothing by itself; the next call pays."""
    netimps.get_interfaces(cache=True)
    before = netimps.interface_enumerations()
    netimps.clear_interface_cache()
    assert netimps.interface_enumerations() == before
    netimps.get_interfaces(cache=True)
    assert netimps.interface_enumerations() == before + 1


@pytest.mark.parametrize(
    "call, expected",
    [
        (lambda: netimps.get_interfaces(), 1),
        (lambda: netimps.get_interfaces(cache=0), 1),
        (lambda: netimps.is_broadcast(netimps.parse("10.9.9.255")), 1),
        (lambda: netimps.is_broadcast("255.255.255.255"), 0),
        (lambda: netimps.clear_interface_cache(), 0),
    ],
    ids=["uncached", "cache=0", "is_broadcast", "limited-broadcast", "clear"],
)
def test_interface_enumerations_per_call(call, expected):
    before = netimps.interface_enumerations()
    call()
    assert netimps.interface_enumerations() - before == expected


def test_interface_enumerations_counts_both_raw_flags_into_one_total():
    """The cache is keyed by `raw`, so a process using both warms up twice --
    documented, because a caller reasoning about cost needs to know."""
    netimps.clear_interface_cache()
    before = netimps.interface_enumerations()
    netimps.get_interfaces(cache=True)
    netimps.get_interfaces(raw=True, cache=True)
    assert netimps.interface_enumerations() - before == 2
    netimps.get_interfaces(cache=True)
    netimps.get_interfaces(raw=True, cache=True)
    assert netimps.interface_enumerations() - before == 2


def test_interface_enumerations_only_increases():
    before = netimps.interface_enumerations()
    netimps.get_interfaces()
    netimps.clear_interface_cache()
    netimps.get_interfaces(cache=True)
    assert netimps.interface_enumerations() >= before + 2


# --------------------------------------------------------------------------- #
# primary_ip ranking, and the scope a link-local bind needs                   #
# --------------------------------------------------------------------------- #


def _iface(name, index, *addresses):
    return netimps.Interface(
        name=name,
        index=index,
        mac=None,
        ips=[ipaddress.ip_interface(a) for a in addresses],
        mtu=1500,
    )


def test_primary_ip_prefers_a_routable_address_over_link_local():
    """The defect, and it is platform-independent.

    An interface commonly lists its link-local address **first** -- `fe80::` is
    configured before SLAAC or DHCPv6 finishes on Linux and macOS NICs -- and
    the old rule was "the first entry that is not loopback". That returned an
    address which is useless as a bind target and unreachable off-link, in
    preference to the global address sitting right behind it.
    """
    nic = _iface("eth0", 2, "fe80::dead:beef/64", "2001:db8::5/64", "10.0.0.5/24")
    assert str(nic.primary_ip(ipv6=True).ip) == "2001:db8::5"


def test_primary_ip_prefers_loopback_over_link_local():
    """`::1` is what a caller means by the loopback adapter.

    Measured on a macOS loopback adapter, whose entries are `127.0.0.1/8`,
    `::1/128`, `fe80::1/64`: the old rule picked `fe80::1`, and
    `bind(interface=...)` then failed with "Can't assign requested address".

    This is deliberately **not** the ranking the report proposed (global, then
    link-local, then loopback) -- that order returns `fe80::1` here too, so it
    would not have fixed the failure it was reported for. The only interface
    carrying both a loopback and a link-local address is loopback itself, so
    ranking loopback higher takes nothing from a real NIC.
    """
    lo0 = _iface("lo0", 1, "127.0.0.1/8", "::1/128", "fe80::1/64")
    assert str(lo0.primary_ip(ipv6=True).ip) == "::1"
    assert str(lo0.primary_ip().ip) == "127.0.0.1"


def test_primary_ip_still_yields_link_local_when_that_is_all_there_is():
    """A NIC before SLAAC completes has nothing else to offer."""
    nic = _iface("eth0", 2, "fe80::1234/64")
    assert str(nic.primary_ip(ipv6=True).ip) == "fe80::1234"


def test_primary_ip_skips_the_loopback_rank_when_loopback_is_not_ok():
    """`loopback_ok=False` asks for something bindable off-host, so a
    link-local address beats `None`."""
    lo0 = _iface("lo0", 1, "::1/128", "fe80::1/64")
    assert str(lo0.primary_ip(ipv6=True, loopback_ok=False).ip) == "fe80::1"
    only_loopback = _iface("lo0", 1, "::1/128")
    assert only_loopback.primary_ip(ipv6=True, loopback_ok=False) is None


def test_primary_ip_keeps_os_order_within_a_rank():
    """Ranking must not reorder two addresses of equal standing."""
    nic = _iface("eth0", 2, "2001:db8::1/64", "2001:db8::2/64")
    assert str(nic.primary_ip(ipv6=True).ip) == "2001:db8::1"


def test_primary_ip_treats_apipa_as_link_local_for_v4():
    """169.254/16 is the same problem wearing the other family's clothes: an
    interface holding both an LINK_LOCAL_V4 address and a lease must answer with the
    lease."""
    nic = _iface("eth0", 2, "169.254.9.9/16", "10.0.0.5/24")
    assert str(nic.primary_ip().ip) == "10.0.0.5"


def test_primary_ip_is_none_for_an_interface_with_no_addresses():
    assert _iface("eth0", 2).primary_ip() is None
    assert _iface("eth0", 2).primary_ip(ipv6=True) is None


def test_bind_scopes_a_link_local_interface_address():
    """A link-local bind needs its zone or the kernel cannot know which adapter.

    **Load-bearing on every POSIX platform, and it fails without the fix.**
    Measured on Linux against a real NIC: the bare form, `%index` in the string
    and `%name` in the string all raise `EINVAL`, and only the 4-tuple scope id
    binds. macOS reports the same refusal as "Can't assign requested address".

    Windows is the outlier that makes a local-only run misleading: it resolves
    the scope itself from an unambiguous link-local address and reports the same
    `scope_id` either way, so this test passes there with or without the fix.
    """
    candidates = [
        iface
        for iface in netimps.get_interfaces()
        for entries in [[getattr(e, "ip", e) for e in iface.ips]]
        if iface.index
        and any(a.version == 6 and a.is_link_local for a in entries)
        and not any(a.version == 6 and not a.is_link_local for a in entries)
    ]
    if not candidates:
        pytest.skip("no link-local-only IPv6 adapter on this host")

    iface = candidates[0]
    sock = netimps.bind("", 0, family=socket.AF_INET6, interface=iface)
    try:
        name = sock.getsockname()
        assert ipaddress.ip_address(name[0].split("%")[0]).is_link_local
        assert name[3] == iface.index, (name, iface.index)
    finally:
        sock.close()


def test_bind_does_not_scope_a_routable_interface_address():
    """Only a link-local address takes a zone; adding one elsewhere would be a
    different bug."""
    candidates = [
        iface
        for iface in netimps.get_interfaces()
        for entries in [[getattr(e, "ip", e) for e in iface.ips]]
        if any(
            a.version == 6 and not a.is_link_local and not a.is_loopback
            for a in entries
        )
    ]
    if not candidates:
        pytest.skip("no routable IPv6 address on this host")
    iface = candidates[0]
    try:
        sock = netimps.bind("", 0, family=socket.AF_INET6, interface=iface)
    except OSError:
        pytest.skip("the routable address is not bindable here")
    try:
        assert sock.getsockname()[3] == 0
    finally:
        sock.close()
