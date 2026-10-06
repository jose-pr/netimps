"""``Interface.is_multicast`` / ``is_point_to_point``, and ``cache=`` through the lookups.

The flags come from the kernel (``IFF_*`` on POSIX, the adapter's flags and type
on Windows), so the live checks take their ground truth from the platform
(``/sys/class/net/<name>/flags`` on Linux, a real group join elsewhere) and only
constants, never decisions, from the code under test. The pure helpers are
asserted exactly. The cache tests count real enumerations through the public
``interface_enumerations()``.
"""

import copy
import math
import pickle
import socket
import struct
import sys

import pytest

import netimps
from netimps import (
    Interface,
    bind,
    get_interfaces,
    interface_enumerations,
    iter_addresses,
    join_group,
    leave_group,
    ping,
)
from netimps._ifaddrs import _fallback, _posix, _windows

LINUX = sys.platform.startswith("linux")

#: Linux's ``IFF_MULTICAST`` and ``IFF_POINTOPOINT``, read from ``/sys/class/net``.
_LINUX_MULTICAST = 0x1000
_LINUX_POINTOPOINT = 0x10


@pytest.fixture(autouse=True)
def _fresh_cache():
    netimps.clear_interface_cache()
    yield
    netimps.clear_interface_cache()


def _native():
    found = get_interfaces()
    if not found or found[0].name == "<unknown>":
        pytest.skip("no native enumeration here")
    return found


# --------------------------------------------------------------------------- #
# The value                                                                    #
# --------------------------------------------------------------------------- #


def test_the_flags_default_to_not_reported():
    iface = Interface("x")
    assert iface.is_multicast is None and iface.is_point_to_point is None


def test_the_flags_are_part_of_equality_the_hash_and_the_repr():
    base = dict(name="tun0", index=3)
    plain = Interface(**base)
    multicast = Interface(**base, is_multicast=True)
    p2p = Interface(**base, is_point_to_point=True)
    assert plain != multicast != p2p and plain != p2p
    assert len({hash(plain), hash(multicast), hash(p2p)}) == 3
    assert Interface(**base, is_multicast=True) == multicast
    scope = dict(vars(netimps))
    for value in (plain, multicast, p2p, Interface(**base, is_multicast=False)):
        assert eval(repr(value), scope) == value
    assert "is_multicast=True" in repr(multicast)
    assert "is_multicast" not in repr(plain)


def test_the_flags_survive_copy_and_pickle():
    iface = Interface("tun0", is_multicast=False, is_point_to_point=True, is_up=True)
    for clone in (copy.deepcopy(iface), pickle.loads(pickle.dumps(iface))):
        assert clone == iface
        assert clone.is_multicast is False and clone.is_point_to_point is True


@pytest.mark.parametrize("name", ["is_multicast", "is_point_to_point"])
@pytest.mark.parametrize("value", ["yes", 1, 0.0])
def test_a_flag_must_be_a_bool_or_none(name, value):
    with pytest.raises(TypeError):
        Interface("x", **{name: value})


# --------------------------------------------------------------------------- #
# The helpers, exactly                                                         #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "platform, flags, expected",
    [
        ("linux", 0x1003, True),  # eth0 as /sys/class/net reports it
        ("linux", 0x9, False),  # lo: no IFF_MULTICAST on Linux
        ("linux", 0x8000, False),  # the BSD bit means nothing on Linux
        ("darwin", 0x8049, True),
        ("darwin", 0x1003, False),  # the Linux bit means nothing on a BSD
        ("freebsd14", 0x8843, True),
        ("sunos5", 0x1000, None),  # no measured value: not guessed
    ],
)
def test_posix_is_multicast_reads_the_platforms_own_bit(
    monkeypatch, platform, flags, expected
):
    monkeypatch.setattr(_posix._sys, "platform", platform)
    assert _posix._posix_is_multicast(flags) is expected


@pytest.mark.parametrize(
    "flags, expected",
    [(0x10, True), (0x10 | 0x1 | 0x40, True), (0x49, False), (0, False)],
)
def test_posix_is_point_to_point_is_iff_pointopoint(flags, expected):
    assert _posix._posix_is_point_to_point(flags) is expected


@pytest.mark.parametrize(
    "flags, expected",
    [(0x1C5, True), (0x181, True), (0x1C5 | 0x10, False), (0x10, False), (0, True)],
)
def test_windows_is_multicast_is_the_absence_of_no_multicast(flags, expected):
    assert _windows._windows_is_multicast(flags) is expected


@pytest.mark.parametrize(
    "if_type, expected",
    [(23, True), (28, True), (131, True), (6, False), (71, False), (24, False)],
)
def test_windows_is_point_to_point_reads_the_adapter_type(if_type, expected):
    """PPP is 23, SLIP 28 and a tunnel 131; Ethernet 6, 802.11 71, loopback 24."""
    assert _windows._windows_is_point_to_point(if_type) is expected


def test_the_degraded_enumeration_does_not_say(no_such_host):
    (iface,) = _fallback._fallback_interfaces(False)
    assert iface.is_multicast is None and iface.is_point_to_point is None


# --------------------------------------------------------------------------- #
# The live host                                                                #
# --------------------------------------------------------------------------- #


def test_loopback_is_never_point_to_point():
    for iface in _native():
        if iface.is_loopback:
            assert iface.is_point_to_point is False


def test_every_flag_is_a_bool_where_the_platform_reports_flags():
    for iface in _native():
        assert isinstance(iface.is_point_to_point, bool), iface.name
        if sys.platform.startswith(("linux", "win32", "darwin", "freebsd")):
            assert isinstance(iface.is_multicast, bool), iface.name


@pytest.mark.skipif(not LINUX, reason="/sys/class/net is Linux's")
def test_the_flags_agree_with_what_the_kernel_publishes():
    checked = 0
    for iface in _native():
        with open("/sys/class/net/%s/flags" % iface.name) as handle:
            flags = int(handle.read(), 16)
        assert iface.is_multicast is bool(flags & _LINUX_MULTICAST), iface.name
        assert iface.is_point_to_point is bool(flags & _LINUX_POINTOPOINT), iface.name
        checked += 1
    assert checked


def _can_join(iface) -> bool:
    """Whether the kernel lets a socket join a group through this adapter."""
    address = iface.primary_ip()
    if address is None:
        return False
    request = struct.pack(
        "4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton(str(address.ip))
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, request)
        except OSError:
            return False
    return True


def test_an_up_adapter_with_a_mac_that_can_join_a_group_reports_multicast():
    """Ground truth is a real ``IP_ADD_MEMBERSHIP`` through the adapter."""
    candidates = [
        i
        for i in _native()
        if i.is_up
        and i.mac is not None
        and not i.is_loopback
        and i.is_point_to_point is False
        and i.ipv4
        and not i.primary_ip().ip.is_link_local
    ]
    joinable = [i for i in candidates if _can_join(i)]
    if not joinable:
        pytest.skip("no up Ethernet-like adapter with an IPv4 address on this host")
    for iface in joinable:
        assert iface.is_multicast is True, iface.name


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows adapter walk")
def test_on_windows_the_flags_follow_the_adapters_own_flags_and_type():
    for iface in get_interfaces(raw=True):
        assert iface.is_multicast is (not iface.raw["flags"] & 0x10)
        assert iface.is_point_to_point is (iface.raw["if_type"] in (23, 28, 131))


# --------------------------------------------------------------------------- #
# cache= through the lookups                                                   #
# --------------------------------------------------------------------------- #


def _name_of_an_adapter_with_ipv4() -> str:
    for iface in _native():
        if iface.ipv4 and iface.name:
            return iface.name
    pytest.skip("no adapter with an IPv4 address")


def test_iter_addresses_default_enumerates_each_time():
    before = interface_enumerations()
    for _ in range(3):
        list(iter_addresses())
    assert interface_enumerations() - before == 3


def test_iter_addresses_cache_enumerates_once():
    before = interface_enumerations()
    runs = [list(iter_addresses(cache=math.inf)) for _ in range(5)]
    assert interface_enumerations() - before == 1
    assert all(run == runs[0] for run in runs)


def test_iter_addresses_cache_is_ignored_for_a_given_enumeration():
    given = get_interfaces()
    before = interface_enumerations()
    list(iter_addresses(given, cache=math.inf))
    assert interface_enumerations() == before


def test_bind_by_interface_with_a_cache_enumerates_once():
    name = _name_of_an_adapter_with_ipv4()
    before = interface_enumerations()
    for _ in range(4):
        bind(interface=name, cache=math.inf).close()
    assert interface_enumerations() - before == 1


def test_bind_by_interface_without_a_cache_enumerates_per_call():
    name = _name_of_an_adapter_with_ipv4()
    before = interface_enumerations()
    for _ in range(3):
        bind(interface=name).close()
    assert interface_enumerations() - before >= 3


def test_bind_by_device_with_a_cache_enumerates_once():
    """Where the platform has no device binding the name is still resolved
    first, from the same cache, before the refusal."""
    name = next(i.name for i in _native() if i.is_loopback)
    before = interface_enumerations()
    for _ in range(4):
        try:
            bind(device=name, cache=math.inf).close()
        except OSError:
            pass  # unsupported here, or refused for lack of privilege
    assert interface_enumerations() - before == 1


def test_join_and_leave_group_with_a_cache_enumerate_once():
    name = _name_of_an_adapter_with_ipv4()
    before = interface_enumerations()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(3):
            for call in (join_group, leave_group):
                try:
                    call(sock, "224.0.0.251", interface=name, cache=math.inf)
                except OSError:
                    pass  # the kernel's answer is not what is under test
    assert interface_enumerations() - before == 1


def test_ping_src_with_a_cache_enumerates_once(fake_program):
    name = _name_of_an_adapter_with_ipv4()
    fake_program("ping", stdout="")
    before = interface_enumerations()
    for _ in range(3):
        ping("127.0.0.1", src=name, cache=math.inf)
    assert interface_enumerations() - before == 1


def test_a_cached_lookup_still_misses_an_unknown_adapter():
    with pytest.raises(ValueError):
        bind(interface="no-such-adapter-x", cache=True)
