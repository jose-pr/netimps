"""Tests for the helpers centralized from the sibling repos.

bind / bind_error_hint / get_interface / UDPEndpoint / Host / retry, plus the
shared interface-spec resolution they all lean on. Loopback only.
"""

import errno
import ipaddress
import os
import socket
import struct
import sys

import pytest

import netimps
from netimps import (
    Host,
    Interface,
    MACAddress,
    UDPEndpoint,
    Backoff,
    backoff_delays,
    bind,
    get_interface,
    iter_interfaces,
    is_local_address,
    retry,
)
from netimps import _iface_spec, _udp

# --------------------------------------------------------------------------- #
# bind                                                                         #
# --------------------------------------------------------------------------- #


def test_bind_datagram_defaults():
    sock = bind("127.0.0.1", 0)
    try:
        host, port = sock.getsockname()
        assert host == "127.0.0.1" and port > 0
        if os.name == "nt":
            # SO_REUSEADDR does NOT mean the same thing here: on Windows it lets
            # another process bind a port that is already live, so the default
            # asks for exclusivity instead. Asserting SO_REUSEADDR on this
            # platform was asserting that the port could be stolen.
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE)
            assert not sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        else:
            # And POSIX gets NEITHER for a datagram socket. This used to assert
            # SO_REUSEADDR, which was asserting that the port could be stolen on
            # Linux too: TIME_WAIT is a TCP concept, so on UDP the option's only
            # remaining effect there is to permit duplicate bindings of live
            # sockets -- measured, the second binder received the datagram.
            assert not sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
    finally:
        sock.close()


def test_bind_does_not_leave_a_listener_stealable():
    """The property the option is there for, asserted directly.

    On Windows a second socket setting SO_REUSEADDR could take a live port out
    from under a `netimps.bind()` listener; a plain stdlib bind was refused.
    This is that reproduction, turned into a regression test.
    """
    server = bind("127.0.0.1", 0, kind=socket.SOCK_STREAM, listen=1)
    try:
        port = server.getsockname()[1]
        thief = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        thief.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            with pytest.raises(OSError):
                thief.bind(("127.0.0.1", port))
        finally:
            thief.close()
    finally:
        server.close()


def test_bind_stream_with_listen():
    sock = bind("127.0.0.1", 0, kind=socket.SOCK_STREAM, listen=5)
    try:
        # A listening socket accepts connections; a merely-bound one does not.
        client = socket.create_connection(sock.getsockname(), timeout=2.0)
        client.close()
    finally:
        sock.close()


def test_bind_sets_broadcast():
    sock = bind("", 0, broadcast=True)
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST)
    finally:
        sock.close()


def test_bind_reuse_port_is_a_noop_where_absent():
    """SO_REUSEPORT does not exist on Windows -- it must not raise there."""
    sock = bind("127.0.0.1", 0, reuse_port=True)
    try:
        option = getattr(socket, "SO_REUSEPORT", None)
        if option is not None:
            assert sock.getsockopt(socket.SOL_SOCKET, option)
    finally:
        sock.close()


def test_bind_applies_extra_options():
    sock = bind(
        "127.0.0.1",
        0,
        options=[(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)],
    )
    try:
        # Kernels may round the value up, so assert it took effect at all.
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) > 0
    finally:
        sock.close()


def test_bind_closes_socket_on_failure():
    """A failed bind must not leak the socket it was configuring."""
    closed = []
    real = socket.socket

    class Tracking(real):
        def close(self):
            closed.append(True)
            super().close()

    original = netimps._sockets._socket.socket
    netimps._sockets._socket.socket = Tracking
    try:
        with pytest.raises(OSError):
            bind("192.0.2.99", 9)  # not a local address
    finally:
        netimps._sockets._socket.socket = original
    assert closed, "socket was not closed after the failed bind"


def test_bind_unknown_interface_raises():
    with pytest.raises(ValueError, match="no interface named"):
        bind(port=0, interface="no-such-nic")


def test_bind_to_interface_uses_its_address():
    loopback = next((i for i in netimps.get_interfaces() if i.is_loopback), None)
    if loopback is None:  # pragma: no cover - host without a loopback entry
        pytest.skip("no loopback interface enumerated on this host")
    sock = bind(port=0, interface=loopback)
    try:
        assert netimps.parse(sock.getsockname()[0]).is_loopback
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# bind_error_hint                                                              #
# --------------------------------------------------------------------------- #


def test_hint_for_permission_denied():
    hint = netimps.bind_error_hint(PermissionError(errno.EACCES, "denied"), 67)
    assert hint and "permission denied" in hint.lower()
    assert "1024" in hint  # the actionable part: privileged port


def test_hint_for_high_port_omits_privileged_note():
    hint = netimps.bind_error_hint(PermissionError(errno.EACCES, "denied"), 8080)
    assert hint and "1024" not in hint


def test_hint_for_address_in_use():
    exc = OSError(errno.EADDRINUSE, "in use")
    hint = netimps.bind_error_hint(exc, 8080)
    assert hint and "already in use" in hint


def test_hint_recognises_windows_error_codes():
    """Windows reports WinError 10013/10048, not the POSIX errnos."""
    in_use = OSError("in use")
    in_use.winerror = 10048
    assert "already in use" in (netimps.bind_error_hint(in_use, 80) or "")


@pytest.mark.parametrize("port", [67, 64514])
def test_wsaeaccess_is_not_a_privilege_problem(port):
    """WSAEACCES means the address is taken, not that you need elevation.

    Windows has no privileged-port concept -- any user may bind port 80 -- so
    reading 10013 as POSIX EACCES sends the reader after an elevation problem
    that cannot exist there. It actually means another socket holds the
    address exclusively, or a firewall or excluded port range refuses it.

    Python maps WSAEACCES to PermissionError with errno EACCES, which is why
    this must be tested before the POSIX branch: reported downstream as
    "permission denied binding port 64514" -- a privilege message about an
    unprivileged port -- and worked around by hand in a consuming package.
    """
    denied = OSError("denied")
    denied.winerror = 10013
    denied.errno = errno.EACCES
    hint = netimps.bind_error_hint(denied, port) or ""

    assert "in use, not privileged" in hint
    assert "1024" not in hint, "the privileged-port advice does not apply on Windows"
    assert "permission denied" not in hint.lower()


def test_posix_eacces_keeps_the_privileged_port_advice():
    """The POSIX reading stays intact -- there the advice is correct."""
    low = netimps.bind_error_hint(PermissionError(errno.EACCES, "denied"), 67) or ""
    assert "permission denied" in low.lower() and "1024" in low

    high = netimps.bind_error_hint(PermissionError(errno.EACCES, "denied"), 8080) or ""
    assert "permission denied" in high.lower() and "1024" not in high


def test_hint_returns_none_for_unrecognised():
    """Unknown failures keep their original message rather than a paraphrase."""
    assert netimps.bind_error_hint(OSError(errno.EPIPE, "broken pipe"), 80) is None
    assert netimps.bind_error_hint(ValueError("not an OSError")) is None


def test_hint_without_a_port():
    hint = netimps.bind_error_hint(OSError(errno.EADDRINUSE, "in use"))
    assert hint and "that port" in hint.lower()


# --------------------------------------------------------------------------- #
# get_interface                                                                #
# --------------------------------------------------------------------------- #


def _lookup_fixtures():
    shared_mac = MACAddress("02:00:00:00:00:01")
    first = Interface(
        "first",
        mac=shared_mac,
        ips=[
            ipaddress.ip_interface("10.0.0.1/24"),
            ipaddress.ip_interface("10.0.0.10/24"),
            ipaddress.ip_interface("2001:db8:1::1/64"),
            ipaddress.ip_interface("fe80::1/64"),
        ],
    )
    second = Interface(
        "second",
        mac=shared_mac,
        ips=[
            ipaddress.ip_interface("10.0.0.2/24"),
            ipaddress.ip_interface("2001:db8:2::1/64"),
        ],
    )
    duplicate_address = Interface(
        "duplicate-address",
        mac=MACAddress("02:00:00:00:00:03"),
        ips=[ipaddress.ip_interface("10.0.0.1/32")],
    )
    return first, second, duplicate_address


def _mock_lookup_interfaces(monkeypatch):
    interfaces = list(_lookup_fixtures())
    calls = []

    def enumerate_interfaces():
        calls.append(True)
        return interfaces

    monkeypatch.setattr(netimps._ifaddrs, "get_interfaces", enumerate_interfaces)
    return interfaces, calls


def test_interfaces_for_interface_does_not_enumerate(monkeypatch):
    iface = Interface("already-resolved")

    def fail_enumeration():
        raise AssertionError("Interface lookup must not enumerate")

    monkeypatch.setattr(netimps._ifaddrs, "get_interfaces", fail_enumeration)
    assert list(iter_interfaces(iface)) == [iface]
    assert get_interface(iface) is iface


def test_interfaces_for_exact_address_and_duplicate_order(monkeypatch):
    interfaces, calls = _mock_lookup_interfaces(monkeypatch)
    first, _, duplicate = interfaces

    assert list(iter_interfaces("10.0.0.1")) == [first, duplicate]
    assert calls == [True]
    calls.clear()
    assert get_interface(ipaddress.ip_address("10.0.0.1")) is first
    assert calls == [True]


def test_interfaces_for_ip_interface_matches_exact_ip_not_subnet(monkeypatch):
    interfaces, _ = _mock_lookup_interfaces(monkeypatch)
    assert list(iter_interfaces(ipaddress.ip_interface("10.0.0.2/8"))) == [
        interfaces[1]
    ]
    assert list(iter_interfaces(ipaddress.ip_interface("10.0.0.99/24"))) == []


def test_interfaces_for_ipv4_network_deduplicates_and_preserves_order(monkeypatch):
    interfaces, calls = _mock_lookup_interfaces(monkeypatch)
    assert list(iter_interfaces(ipaddress.ip_network("10.0.0.0/24"))) == interfaces
    assert calls == [True]

    calls.clear()
    assert list(iter_interfaces("10.0.0.0/24")) == interfaces
    assert calls == [True]


def test_interfaces_for_ipv6_networks(monkeypatch):
    interfaces, _ = _mock_lookup_interfaces(monkeypatch)
    assert list(iter_interfaces(ipaddress.ip_network("2001:db8:1::/64"))) == [
        interfaces[0]
    ]
    assert list(iter_interfaces("2001:db8::/32")) == interfaces[:2]


def test_interfaces_for_mac_forms_and_duplicates(monkeypatch):
    interfaces, _ = _mock_lookup_interfaces(monkeypatch)
    shared = MACAddress("02:00:00:00:00:01")
    assert list(iter_interfaces(shared)) == interfaces[:2]
    assert list(iter_interfaces(str(shared))) == interfaces[:2]
    assert list(iter_interfaces(shared.packed)) == interfaces[:2]


def test_interfaces_for_integer_remains_an_ip_query(monkeypatch):
    _, calls = _mock_lookup_interfaces(monkeypatch)
    shared = MACAddress("02:00:00:00:00:01")
    assert list(iter_interfaces(int(shared))) == []
    assert calls == [True]


def test_interfaces_for_invalid_and_no_match(monkeypatch):
    _, calls = _mock_lookup_interfaces(monkeypatch)
    assert list(iter_interfaces("not-an-address")) == []
    assert list(iter_interfaces(None)) == []
    assert list(iter_interfaces(ipaddress.ip_network("192.0.2.0/24"))) == []
    assert calls == [True]


def test_interface_for_unknown_is_none_when_strict(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    assert get_interface("192.0.2.99") is None


def test_interface_for_unknown_synthesizes_address_and_interface(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    iface = get_interface("192.0.2.99", strict=False)
    assert iface is not None
    assert iface.name == "<unknown>"
    # A host route, matching how degraded enumeration reports itself.
    assert iface.ips[0].network.prefixlen == iface.ips[0].max_prefixlen
    assert iface.ips[0].ip == ipaddress.ip_address("192.0.2.99")

    from_interface = get_interface(
        ipaddress.ip_interface("192.0.2.100/24"), strict=False
    )
    assert from_interface is not None
    assert from_interface.ips[0].ip == ipaddress.ip_address("192.0.2.100")


def test_interface_for_does_not_synthesize_network_or_mac(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    assert get_interface(ipaddress.ip_network("192.0.2.0/24"), strict=False) is None
    assert get_interface(MACAddress("02:00:00:00:00:99"), strict=False) is None


def test_interface_for_garbage_is_none(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    assert get_interface("not-an-address") is None
    assert get_interface(None) is None


# --------------------------------------------------------------------------- #
# is_local_address                                                             #
# --------------------------------------------------------------------------- #


def test_is_local_address_loopback_does_not_enumerate(monkeypatch):
    def fail_enumeration():
        raise AssertionError("loopback must be answered before discovery")

    monkeypatch.setattr(netimps._ifaddrs, "get_interfaces", fail_enumeration)
    assert is_local_address("127.0.0.1")
    assert is_local_address("::1")


def test_is_local_address_requires_assignment_not_scope(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    assert is_local_address("10.0.0.1")
    assert not is_local_address("10.0.1.1")  # private alone is insufficient
    assert is_local_address("fe80::1")
    assert not is_local_address("fe80::2")  # link-local alone is insufficient
    assert not is_local_address("2001:db8:ffff::1")


def test_is_local_address_malformed_input_raises(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    with pytest.raises(ValueError):
        is_local_address("not-an-address")
    with pytest.raises(ValueError):
        is_local_address(None)


# --------------------------------------------------------------------------- #
# shared interface-spec resolution                                             #
# --------------------------------------------------------------------------- #


def test_interface_spec_none_is_none():
    assert _iface_spec.interface_address(None) is None


def test_interface_spec_returns_parsed_addresses():
    """Addresses come back parsed, not as strings -- the package-wide rule.

    Uses loopback rather than an arbitrary literal: under ``strict=True`` a bare
    address must now be one this host actually holds, matching the rule
    ``interface_index`` has always applied. The point of this test is the return
    *type*, so it just needs an address that passes that check.
    """
    result = _iface_spec.interface_address("127.0.0.1")
    assert result == netimps.parse("127.0.0.1")
    assert not isinstance(result, str)


def test_interface_spec_rejects_an_address_no_interface_holds():
    """``strict=True`` means "resolve this to one of mine", for every spec form.

    ``interface_address`` used to accept a foreign address while
    ``interface_index`` rejected it, so the same spec resolved differently
    depending on which family the caller happened to be using.
    """
    with pytest.raises(ValueError, match="no local interface holds address"):
        _iface_spec.interface_address("10.0.0.5", strict=True)
    # strict=False still passes it through: ping(src=) and UDPEndpoint.send()
    # both rely on that, and the OS gives the real error when the bind fails.
    assert _iface_spec.interface_address("10.0.0.5", strict=False) == netimps.parse(
        "10.0.0.5"
    )


def test_interface_spec_rejects_a_non_address_string():
    with pytest.raises(ValueError):
        _iface_spec.interface_address("definitely not an address")


def test_interface_spec_strict_raises_loose_returns_none():
    """The two original callers disagreed; both behaviours are preserved."""
    with pytest.raises(ValueError, match="no interface named"):
        _iface_spec.interface_address("no-such-nic", strict=True)
    assert _iface_spec.interface_address("no-such-nic", strict=False) is None

    unknown_mac = netimps.MACAddress("02:00:00:00:00:99")
    with pytest.raises(ValueError, match="no interface with MAC"):
        _iface_spec.interface_address(unknown_mac, strict=True)
    assert _iface_spec.interface_address(unknown_mac, strict=False) is None


def test_interface_spec_resolves_interface_object():
    loopback = next((i for i in netimps.get_interfaces() if i.is_loopback), None)
    if loopback is None:  # pragma: no cover - host without a loopback entry
        pytest.skip("no loopback interface enumerated on this host")
    resolved = _iface_spec.interface_address(loopback)
    assert resolved.is_loopback


# --------------------------------------------------------------------------- #
# UDPEndpoint                                                                  #
# --------------------------------------------------------------------------- #


#: Both loopbacks, so every endpoint test runs against each address family.
#: The v6 half is the regression: ``IP_PKTINFO`` is silently accepted on an
#: AF_INET6 socket, so a v4-only test suite stays green while v6 reports an
#: arrival interface it never receives.
_LOOPBACKS = [
    pytest.param(socket.AF_INET, "127.0.0.1", id="ipv4"),
    pytest.param(socket.AF_INET6, "::1", id="ipv6"),
]


def _loopback_endpoint(family, host):
    """A bound loopback endpoint, skipping where the family is unavailable."""
    try:
        sock = bind(host, 0, family=family)
    except OSError as exc:  # no IPv6 stack, or no ::1 configured
        pytest.skip("cannot bind %s: %s" % (host, exc))
    endpoint = UDPEndpoint(sock)
    endpoint.socket.settimeout(5.0)
    return endpoint


@pytest.mark.parametrize("family, host", _LOOPBACKS)
def test_udp_endpoint_round_trip(family, host):
    """The flag and the data must agree, for both address families.

    ``has_pktinfo`` is the single thing the docs tell a caller to check,
    so a ``True`` that is followed by an empty ``interface_index`` is worse
    than an honest ``False``. Asserting only ``data``/``sender`` -- which this
    test used to do -- leaves the whole pktinfo path free to be dead.
    """
    with _loopback_endpoint(family, host) as endpoint:
        port = endpoint.socket.getsockname()[1]
        sender = bind(host, 0, family=family)
        try:
            sender.sendto(b"payload", (host, port))
            packet = endpoint.recv(1024)
        finally:
            sender.close()

    assert packet.data == b"payload"
    assert packet.sender[0] == host
    assert packet.control_truncated is False

    # Degrading to False is honest, but it must not become the escape hatch:
    # where the kernel exports this family's option, it has to be used.
    receive_option = _udp._pktinfo_options(family)[1]
    if receive_option is not None and hasattr(socket.socket, "recvmsg"):
        assert endpoint.has_pktinfo
    if sys.platform.startswith("freebsd") and family == socket.AF_INET:
        # FreeBSD's IPv4 carrier is not IP_PKTINFO, so the option table above
        # names nothing for it; the platform delivers the arrival all the same.
        assert endpoint.has_pktinfo

    if not endpoint.has_pktinfo:
        assert packet.interface_index == 0 and packet.interface is None
        return
    assert packet.interface_index != 0
    assert packet.interface is not None
    assert packet.destination is not None and packet.destination.is_loopback


def test_udp_endpoint_reports_truncated_control_data():
    """``MSG_CTRUNC`` must reach the caller, not be dropped with the cmsg.

    The buffer is sized for several messages precisely so this is rare, but
    when it does happen the empty interface fields mean "something was
    discarded", not "the kernel had nothing to say" -- and nothing else
    distinguishes the two.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no IP_PKTINFO on this platform")
        # Smaller than any cmsg header, so the kernel truncates our own.
        endpoint._cmsg_size = 1
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = bind("127.0.0.1", 0)
        try:
            sender.sendto(b"squeezed", ("127.0.0.1", port))
            packet = endpoint.recv(64)
        finally:
            sender.close()

    assert packet.data == b"squeezed"
    assert packet.control_truncated is True
    assert packet.interface_index == 0


def test_udp_endpoint_ancillary_buffer_holds_more_than_one_cmsg():
    """Room for exactly one cmsg loses the pktinfo to any other option.

    Measured on Linux with ``SO_TIMESTAMP`` and ``IP_PKTINFO`` both enabled:
    a one-slot buffer kept the timestamp, discarded the pktinfo and set
    ``MSG_CTRUNC``. The caller owns the raw socket, so a second enabled
    option is ordinary rather than exotic.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no IP_PKTINFO on this platform")
        one = socket.CMSG_SPACE(struct.calcsize(_udp._PKTINFO_V4))
        assert endpoint._cmsg_size >= one * 2


@pytest.mark.parametrize("family, host", _LOOPBACKS)
def test_udp_endpoint_pins_the_source_it_is_given(family, host):
    """``src`` is honoured where the platform can, and ignored where it cannot.

    Both halves matter: a pinned send that never applies the pin is the
    silent wrong answer, and a raise on a platform without ``sendmsg`` would
    break the documented degrade.
    """
    with _loopback_endpoint(family, host) as receiver:
        port = receiver.socket.getsockname()[1]
        with _loopback_endpoint(family, host) as sender:
            assert sender.send(b"pinned", host, port, src=host) == 6
            # The flag may be False (Windows has no sendmsg; macOS has no
            # IP_PKTINFO), but it must never claim a pin it cannot apply.
            assert not sender.has_src_pinning or hasattr(socket.socket, "sendmsg")
        packet = receiver.recv(64)
    assert packet.data == b"pinned"


def test_udp_endpoint_send_rejects_a_source_of_the_wrong_family():
    """Linux *accepts* an IPv6 cmsg on an AF_INET socket and ignores it.

    Measured: ``sendmsg`` returns the byte count, and the pin does nothing.
    So the mismatch has to be caught here -- the kernel will not report it.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as sender:
        if not sender.has_src_pinning:
            pytest.skip("no IPv4 source pinning on this platform")
        with pytest.raises(ValueError, match="IPv6 source"):
            sender.send(b"x", "127.0.0.1", 9, src="::1")


def test_udp_endpoint_send_rejects_an_unresolvable_source():
    """A spec naming no local adapter is a caller error, not a fallback.

    Sending from whatever the routing table picks is exactly the silent
    wrong answer ``src`` exists to prevent.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as sender:
        if not sender.has_src_pinning:
            pytest.skip("no IPv4 source pinning on this platform")
        with pytest.raises(ValueError, match="cannot resolve src"):
            sender.send(b"x", "127.0.0.1", 9, src="no-such-adapter")


def test_udp_endpoint_degrades_without_pktinfo(monkeypatch):
    """No IP_PKTINFO must mean empty interface fields, not a failure."""
    monkeypatch.setattr(_udp, "_IP_PKTINFO", None)
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        assert endpoint.has_pktinfo is False
        # Same constant serves both directions for IPv4, so neither is claimed.
        assert endpoint.has_src_pinning is False
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = bind("127.0.0.1", 0)
        try:
            sender.sendto(b"x", ("127.0.0.1", port))
            packet = endpoint.recv(64)
        finally:
            sender.close()
    assert packet.data == b"x"
    assert packet.interface is None and packet.interface_index == 0
    assert packet.destination is None and packet.control_truncated is False


def test_udp_endpoint_send_falls_back_without_source():
    with UDPEndpoint(bind("127.0.0.1", 0)) as receiver:
        receiver.socket.settimeout(5.0)
        port = receiver.socket.getsockname()[1]
        with UDPEndpoint(bind("127.0.0.1", 0)) as sender:
            assert sender.send(b"hi", "127.0.0.1", port) == 2
        assert receiver.recv(64).data == b"hi"


def test_udp_endpoint_repr_and_close():
    endpoint = UDPEndpoint(bind("127.0.0.1", 0))
    # Both capability flags belong in the repr: they are what a bug report
    # about "interface is always None" needs to carry.
    assert "UDPEndpoint(" in repr(endpoint)
    assert "pktinfo=" in repr(endpoint) and "src_pinning=" in repr(endpoint)
    endpoint.close()


@pytest.mark.parametrize("family, host", _LOOPBACKS)
def test_udp_endpoint_claims_pktinfo_whenever_the_platform_delivers_it(family, host):
    """If a raw socket can get a pktinfo cmsg, the endpoint must not say it cannot.

    This asks the **platform**, not the library. `test_udp_endpoint_round_trip`
    has a guard for the same thing, but it reads
    `_udp._pktinfo_options(family)[1]` -- the function under test -- so when that
    returned None for IPv6 on Windows, the guard switched itself off and the
    round trip passed through its own degraded branch. Measured on a CI runner:
    `UDPEndpoint(bind("::", 0)).has_pktinfo` was False while a raw
    `recvmsg` on the very same socket delivered the cmsg.

    So: establish the ground truth by hand first, then hold the endpoint to it.
    """
    if not netimps.has_recvmsg():
        pytest.skip("no recvmsg on this platform at all")

    # Ground truth: set every pktinfo option this platform exports for the
    # family and see whether a cmsg actually arrives.
    try:
        probe = bind(host, 0, family=family)
    except OSError as exc:
        pytest.skip("cannot bind %s: %s" % (host, exc))
    delivered = False
    try:
        # The *constants* come from `_udp`, the *decision* does not -- that
        # distinction is the whole design of this test. Reading them from
        # `socket` instead gave this check the same blind spot as the code it
        # was meant to police: `socket.IP_PKTINFO` only exists from CPython
        # 3.12, so on 3.9-3.11 it found None, enabled nothing, saw no cmsg and
        # skipped -- passing while v4 pktinfo was broken on every platform.
        if family == socket.AF_INET6:
            candidates = [
                (socket.IPPROTO_IPV6, _udp._IPV6_RECVPKTINFO),
                (socket.IPPROTO_IPV6, _udp._IPV6_PKTINFO),
            ]
        else:
            candidates = [(socket.IPPROTO_IP, _udp._IP_PKTINFO)]
        for level, option in candidates:
            if option is None:
                continue
            try:
                probe.setsockopt(level, option, 1)
            except OSError:
                continue
        port = probe.getsockname()[1]
        peer = socket.socket(family, socket.SOCK_DGRAM)
        try:
            peer.sendto(b"ground-truth", (host, port))
            probe.settimeout(5.0)
            _data, ancdata, _flags, _sender = netimps.recvmsg(
                probe, 512, netimps.CMSG_SPACE(256)
            )
        finally:
            peer.close()
        delivered = any(
            _udp._unpack_pktinfo(lvl, ctype, cdata) is not None
            for lvl, ctype, cdata in ancdata
        )
    except OSError as exc:  # pragma: no cover - a stack without this loopback
        pytest.skip("ground-truth probe failed: %s" % (exc,))
    finally:
        probe.close()

    if not delivered:
        pytest.skip("platform delivers no pktinfo cmsg for family %s" % (family,))

    with _loopback_endpoint(family, host) as endpoint:
        assert endpoint.has_pktinfo, (
            "a raw recvmsg got a pktinfo cmsg for family %s, so UDPEndpoint "
            "must not report has_pktinfo=False" % (family,)
        )


def test_udp_endpoint_dual_stack_reports_a_v4_arrival_as_v4_mapped():
    """`destination` on an AF_INET6 endpoint is v4-mapped on every platform.

    The platforms genuinely disagree about the wire form: Linux and macOS put
    the v4-mapped address in the v6 cmsg, while Windows reports a *plain* v4
    address at level IPPROTO_IP -- and on Windows the same datagram's `sender`
    is already `::ffff:127.0.0.1`, so the two halves contradict each other.
    The documented contract is the mapped form, so this pins the normalisation.
    """
    # IPV6_V6ONLY has to be cleared **before** the bind -- Windows answers
    # WSAEINVAL for a change after it, which is why this builds the socket by
    # hand instead of going through `bind()`.
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", 0))
    except OSError as exc:
        sock.close()
        pytest.skip("no dual-stack :: socket here -- %s" % (exc,))
    with UDPEndpoint(sock) as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no pktinfo on this platform")
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"v4-arrival", ("127.0.0.1", port))
            packet = endpoint.recv(1024)
        except OSError as exc:
            pytest.skip("no dual-stack v4 delivery here: %s" % (exc,))
        finally:
            sender.close()

        assert packet.data == b"v4-arrival"
        if packet.destination is None:
            pytest.skip("this platform reported no arrival address for a v4 arrival")
        assert (
            packet.destination.version == 6
        ), "an AF_INET6 endpoint must report a v6 address, got %r" % (
            packet.destination,
        )
        assert packet.destination == ipaddress.IPv6Address("::ffff:127.0.0.1")


def test_udp_endpoint_reports_a_virtual_ip_as_the_arrival_address():
    """A wildcard socket must say *which* address the datagram was sent to.

    This is the entire reason pktinfo exists: replying from the VIP a client
    addressed, not from whatever the routing table prefers. 127.0.0.2 is a
    convenient stand-in for a VIP on Linux and Windows; macOS assigns only
    127.0.0.1 and rejects it, which the skip records rather than hides.
    """
    with _loopback_endpoint(socket.AF_INET, "0.0.0.0") as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no pktinfo on this platform")
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"to-the-vip", ("127.0.0.2", port))
            packet = endpoint.recv(1024)
        except OSError as exc:
            pytest.skip("127.0.0.2 is not reachable on this host: %s" % (exc,))
        finally:
            sender.close()
        if packet.destination is None:
            pytest.skip("no arrival address reported")
        assert str(packet.destination) == "127.0.0.2", (
            "the wildcard socket reported %r, losing which address the client "
            "actually addressed" % (packet.destination,)
        )


def _force_index_only_spec(monkeypatch):
    """Make any src resolve to an interface index but no address.

    The public API cannot express that state -- every spec it accepts either
    names an address or resolves to one -- so the resolver is faked. What is
    being tested is our own branch, not the resolver.
    """
    from netimps import _iface_spec

    monkeypatch.setattr(_iface_spec, "interface_address", lambda *a, **k: None)
    monkeypatch.setattr(_iface_spec, "interface_index", lambda *a, **k: 1)


@pytest.mark.skipif(os.name != "nt", reason="the zero-address rule is Windows-only")
def test_windows_refuses_an_index_only_source_rather_than_sending_from_zero(
    monkeypatch,
):
    """Windows sends a zero source address literally, so it must refuse instead.

    Measured: a pin of 0.0.0.0 arrives *from* 0.0.0.0, where Linux reads zero as
    "kernel chooses". Silently sending from an unintended address is the exact
    failure `src=` exists to prevent, so this raises rather than degrading.
    """
    _force_index_only_spec(monkeypatch)
    with _loopback_endpoint(socket.AF_INET, "127.0.0.1") as endpoint:
        with pytest.raises(ValueError, match="index alone"):
            endpoint._pktinfo_control("any-spec")


@pytest.mark.skipif(os.name == "nt", reason="the POSIX half of the zero-address rule")
def test_posix_packs_a_zero_source_for_an_index_only_pin(monkeypatch):
    """The counterpart: on POSIX a zero address *is* "kernel chooses".

    Paired with the Windows test deliberately. The two platforms read identical
    bytes in opposite ways, so pinning one without the other would let a future
    change make them agree -- which would be wrong on one of them.
    """
    _force_index_only_spec(monkeypatch)
    with _loopback_endpoint(socket.AF_INET, "127.0.0.1") as endpoint:
        control = endpoint._pktinfo_control("any-spec")
        assert control is not None
        _level, _ctype, data = control
        index, _spec_dst, address = struct.unpack(_udp._PKTINFO_V4, data)
        assert index == 1
        assert address == b"\x00\x00\x00\x00", "a zero address is the POSIX idiom"


# --------------------------------------------------------------------------- #
# Host                                                                         #
# --------------------------------------------------------------------------- #


def test_host_keeps_the_original_text(no_such_host):
    """The whole point: str() is always what was given, even unresolvable."""
    host = Host("db.internal")
    assert str(host) == "db.internal"
    host.ip()  # may fail; must not change the text
    assert str(host) == "db.internal"


def test_host_literal_needs_no_dns(monkeypatch):
    def explode(_name):
        raise AssertionError("a literal must not trigger DNS")

    monkeypatch.setattr(netimps._ip._socket, "gethostbyname", explode)
    host = Host("10.0.0.5")
    assert host.is_address
    assert host.ip() == netimps.parse("10.0.0.5")


def test_host_caches_resolution(monkeypatch):
    calls = []

    def counting(name, *args, **kwargs):
        calls.append(name)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    # getaddrinfo, not gethostbyname: the latter is IPv4-only and no longer
    # called, so stubbing it would have quietly let this reach the real network.
    monkeypatch.setattr(netimps._ip._socket, "getaddrinfo", counting)
    host = Host("example.com")
    assert host.ip() == netimps.parse("93.184.216.34")
    assert host.ip() == netimps.parse("93.184.216.34")
    assert len(calls) == 1, "resolution should be cached"

    host.ip(refresh=True)
    assert len(calls) == 2, "refresh=True must retry"


def test_host_caches_failure_too(monkeypatch):
    calls = []

    def failing(name, *args, **kwargs):
        calls.append(name)
        raise socket.gaierror(socket.EAI_NONAME, "no such host")

    monkeypatch.setattr(netimps._ip._socket, "getaddrinfo", failing)
    host = Host("nope.invalid")
    assert host.ip() is None
    assert host.ip() is None
    assert len(calls) == 1, "a failed lookup should not be repeated by default"


def test_host_equality_and_falsiness():
    assert Host("x") == Host("x")
    assert Host("x") == "x"
    assert Host("x") != Host("y")
    assert not Host("")
    assert Host("x")
    assert Host(Host("nested")).value == "nested"
    assert hash(Host("x")) == hash(Host("x"))


# --------------------------------------------------------------------------- #
# retry / backoff_delays                                                       #
# --------------------------------------------------------------------------- #


def test_retry_returns_on_first_success():
    calls = []
    assert retry(lambda: calls.append(1) or "ok", _sleep=lambda _: None) == "ok"
    assert len(calls) == 1


def test_retry_recovers_after_transient_failures():
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise OSError("transient")
        return "ok"

    assert retry(flaky, attempts=5, _sleep=lambda _: None) == "ok"
    assert len(calls) == 3


def test_retry_reraises_the_last_error_unwrapped():
    """The traceback must still point at the real problem."""

    def always_fails():
        raise OSError("still broken")

    with pytest.raises(OSError, match="still broken"):
        retry(always_fails, attempts=3, _sleep=lambda _: None)


def test_retry_does_not_retry_caller_bugs():
    calls = []

    def bad_call():
        calls.append(1)
        raise ValueError("malformed")

    with pytest.raises(ValueError):
        retry(bad_call, attempts=5, _sleep=lambda _: None)
    assert len(calls) == 1, "a ValueError will fail identically next time"


def test_retry_attempts_counts_total_calls():
    calls = []

    def failing():
        calls.append(1)
        raise OSError("no")

    with pytest.raises(OSError):
        retry(failing, attempts=1, _sleep=lambda _: None)
    assert len(calls) == 1, "attempts=1 means one call and no sleeping"


def test_retry_sleeps_with_growing_delays():
    slept = []

    def failing():
        raise OSError("no")

    with pytest.raises(OSError):
        retry(
            failing,
            attempts=4,
            delay=1.0,
            multiplier=2.0,
            jitter=0,
            _sleep=slept.append,
        )
    assert slept == [1.0, 2.0, 4.0]


def test_retry_reports_each_attempt():
    seen = []

    def failing():
        raise OSError("no")

    with pytest.raises(OSError):
        retry(
            failing,
            attempts=3,
            delay=0.5,
            jitter=0,
            on_retry=lambda n, exc, wait: seen.append((n, wait)),
            _sleep=lambda _: None,
        )
    assert seen == [(1, 0.5), (2, 1.0)]


def test_backoff_delays_are_capped():
    delays = list(
        backoff_delays(attempts=8, delay=1.0, multiplier=10.0, max_delay=5.0, jitter=0)
    )
    assert max(delays) == 5.0
    assert len(delays) == 7  # attempts - 1


def test_backoff_jitter_only_shortens():
    """Jitter must never push a delay past max_delay."""
    delays = list(
        backoff_delays(
            attempts=6,
            delay=4.0,
            multiplier=1.0,
            max_delay=4.0,
            jitter=0.5,
            _random=lambda: 1.0,
        )
    )
    assert all(0 <= d <= 4.0 for d in delays)
    assert all(d == pytest.approx(2.0) for d in delays)


@pytest.mark.parametrize(
    "kwargs",
    [{"attempts": 0}, {"delay": -1}, {"jitter": 1.5}, {"jitter": -0.1}],
)
def test_backoff_rejects_nonsense(kwargs):
    with pytest.raises(ValueError):
        list(backoff_delays(**kwargs))


# --------------------------------------------------------------------------- #
# iter_addresses                                                               #
# --------------------------------------------------------------------------- #


def test_iter_addresses_flattens_without_losing_the_interface():
    pairs = list(netimps.iter_addresses())
    interfaces = netimps.get_interfaces()
    assert len(pairs) == sum(len(i.ips) for i in interfaces)
    for iface, entry in pairs:
        # The full Interface stays reachable -- the flattening loses nothing.
        assert entry in iface.ips
        assert isinstance(iface.name, str)


def test_iter_addresses_family_filter():
    v4 = list(netimps.iter_addresses(family=4))
    v6 = list(netimps.iter_addresses(family=6))
    assert all(entry.version == 4 for _, entry in v4)
    assert all(entry.version == 6 for _, entry in v6)
    assert len(v4) + len(v6) == len(list(netimps.iter_addresses()))


def test_iter_addresses_accepts_a_prepared_enumeration():
    """Callers in a loop should not have to re-enumerate each time."""
    interfaces = netimps.get_interfaces()
    assert list(netimps.iter_addresses(interfaces)) == list(
        netimps.iter_addresses(interfaces)
    )


def test_iter_addresses_rejects_a_bad_family():
    with pytest.raises(ValueError, match="family must be 4, 6 or None"):
        list(netimps.iter_addresses(family=5))


# --------------------------------------------------------------------------- #
# MACAddress subclassing -- a documented guarantee                             #
# --------------------------------------------------------------------------- #


class _WireMAC(netimps.MACAddress):
    """A subclass overriding only __str__, as a caller would."""

    def __str__(self):
        return self.format("-", upper=True)

    def hex(self, *args):
        return self.packed.hex(*args)


def test_mac_subclass_can_change_str_only():
    mac = _WireMAC("aa:bb:cc:dd:ee:ff")
    assert str(mac) == "AA-BB-CC-DD-EE-FF"
    # Everything else is inherited unchanged.
    assert mac.packed == bytes.fromhex("aabbccddeeff")
    assert mac.format() == "aa:bb:cc:dd:ee:ff"
    assert mac.oui == b"\xaa\xbb\xcc"


def test_mac_subclass_keeps_equality_and_hashing():
    """A subclass must interoperate with the base type, or dicts break."""
    base = netimps.MACAddress("aa:bb:cc:dd:ee:ff")
    sub = _WireMAC("AA-BB-CC-DD-EE-FF")
    assert sub == base and base == sub
    assert hash(sub) == hash(base)
    # The pair must collapse to one key, not two.
    assert len({base, sub}) == 1
    assert {base: "x"}[sub] == "x"


def test_mac_subclass_keeps_ordering_and_validation():
    low = _WireMAC("00:00:00:00:00:01")
    high = _WireMAC("ff:ff:ff:ff:ff:ff")
    assert low < high
    assert sorted([high, low]) == [low, high]
    with pytest.raises(ValueError):
        _WireMAC("00-11-22")  # too short


def test_mac_subclass_classmethods_bind_to_the_subclass():
    parsed = _WireMAC.try_parse("aa:bb:cc:dd:ee:ff")
    assert isinstance(parsed, _WireMAC)
    assert str(parsed) == "AA-BB-CC-DD-EE-FF"
    assert _WireMAC.is_valid("aa:bb:cc:dd:ee:ff")
    assert not _WireMAC.is_valid("nope")


def test_mac_subclass_hex_passthrough():
    """.hex() is the one bytes method a caller may need to re-add."""
    assert _WireMAC("aa:bb:cc:dd:ee:ff").hex("-").upper() == "AA-BB-CC-DD-EE-FF"


# --------------------------------------------------------------------------- #
# The two symmetric jitter modes, and the stateful Backoff timer              #
# --------------------------------------------------------------------------- #


def _seeded(seed=42):
    import random

    return random.Random(seed).random


def _old_schedule(attempts, delay, multiplier, max_delay, jitter, rand):
    """Verbatim copy of the pre-change loop, to pin the default schedule."""
    current = delay
    for _ in range(attempts - 1):
        capped = min(current, max_delay)
        if jitter:
            capped -= capped * jitter * rand()
        yield capped
        current *= multiplier


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(attempts=5, delay=0.5, multiplier=2.0, max_delay=30.0, jitter=0.1),
        dict(attempts=8, delay=1.0, multiplier=3.0, max_delay=10.0, jitter=0.5),
        dict(attempts=4, delay=0.25, multiplier=2.0, max_delay=30.0, jitter=0.0),
        dict(attempts=1, delay=1.0, multiplier=2.0, max_delay=5.0, jitter=0.1),
    ],
)
def test_the_default_schedule_is_unchanged(kwargs):
    """Adding the modes must not have moved the default by a float.

    Asserted against a copy of the old loop rather than against recorded
    numbers, so it keeps meaning something if the defaults are ever retuned --
    and including the `jitter=0` case, which must still draw no randomness.
    """
    assert list(backoff_delays(_random=_seeded(), **kwargs)) == list(
        _old_schedule(rand=_seeded(), **kwargs)
    )


def test_jitter_seconds_is_absolute_and_spreads_both_ways():
    """RFC 2131 §4.1: "randomized by the value of a uniform random number
    chosen from the range -1 to +1" -- seconds, not a fraction.

    The default mode can only ever *shorten*, so a DHCPv4 client could not use
    it, so neither DHCP standard could be expressed with it. Both signs
    occurring is the whole assertion; a mean near zero is the second half.
    """
    deltas = [
        value - 10.0
        for value in backoff_delays(
            attempts=401,
            delay=10.0,
            multiplier=1.0,
            max_delay=1000.0,
            jitter_seconds=1.0,
            _random=_seeded(1),
        )
    ]
    assert any(d > 0 for d in deltas), "never longer -- not symmetric"
    assert any(d < 0 for d in deltas), "never shorter"
    assert all(-1.0 <= d <= 1.0 for d in deltas), (min(deltas), max(deltas))
    assert abs(sum(deltas) / len(deltas)) < 0.1


def test_symmetric_makes_the_fractional_jitter_two_sided():
    """RFC 8415 §15: `RT = 2*RTprev + RAND*RTprev`, RAND uniform in [-0.1, +0.1]."""
    fractions = [
        value / 10.0 - 1.0
        for value in backoff_delays(
            attempts=401,
            delay=10.0,
            multiplier=1.0,
            max_delay=1000.0,
            jitter=0.1,
            symmetric=True,
            _random=_seeded(3),
        )
    ]
    assert any(f > 0 for f in fractions)
    assert any(f < 0 for f in fractions)
    assert all(-0.1 <= f <= 0.1 for f in fractions), (min(fractions), max(fractions))
    assert abs(sum(fractions) / len(fractions)) < 0.01


def test_a_symmetric_delay_may_exceed_max_delay_because_the_rfcs_say_so():
    """**The one place this diverges from the default mode's contract.**

    RFC 8415 applies its jitter *after* the cap -- `if RT > MRT: RT = MRT +
    RAND*MRT` -- and RFC 2131 randomises +/-1 s around its 64 s maximum. So in
    the symmetric modes `max_delay` caps the **base**, not the result.

    Clamping instead was the obvious reading, and it is wrong in a way that is
    invisible: measured, the spread *at the cap* became entirely negative with a
    mean of -0.024 rather than ~0, because every positive excursion was trimmed
    back to the ceiling. A backed-off client spends nearly all its time at the
    cap, so that is precisely where the symmetry has to survive -- clamping
    would silently reintroduce the synchronisation the mode is chosen to
    prevent.
    """
    values = list(
        backoff_delays(
            attempts=200,
            delay=64.0,
            multiplier=2.0,
            max_delay=64.0,
            jitter_seconds=1.0,
            _random=_seeded(7),
        )
    )
    assert any(v > 64.0 for v in values), "clamped at the cap -- symmetry lost"
    assert all(v <= 65.0 for v in values), max(values)
    assert all(v >= 0.0 for v in values)


def test_the_default_mode_still_treats_max_delay_as_a_hard_ceiling():
    """The divergence above must not have leaked into the default."""
    values = list(
        backoff_delays(
            attempts=300,
            delay=1.0,
            multiplier=2.0,
            max_delay=5.0,
            jitter=0.1,
            _random=_seeded(11),
        )
    )
    assert all(0.0 <= v <= 5.0 for v in values), (min(values), max(values))


def test_no_mode_can_produce_a_negative_delay():
    """A negative sleep is the failure the clamp at zero exists for."""
    for kwargs in (
        dict(jitter_seconds=100.0),
        dict(jitter=1.0, symmetric=True),
        dict(jitter=1.0),
    ):
        values = list(
            backoff_delays(
                attempts=200,
                delay=0.05,
                multiplier=1.0,
                max_delay=1000.0,
                _random=_seeded(5),
                **kwargs,
            )
        )
        assert all(v >= 0.0 for v in values), (kwargs, min(values))


def test_an_absolute_amplitude_is_capped_at_the_delay():
    """Otherwise a sub-second delay loses its distribution entirely.

    With `delay=0.1` and a requested +/-1 s, an uncapped draw is negative about
    45% of the time and clamping at zero would pile all of that on a single
    value -- neither symmetric nor uniform, which is a silently wrong schedule
    rather than a refused one. Capping the amplitude at the delay keeps it
    both. For RFC 2131's real schedule the cap never engages: it starts at 4 s
    against a 1 s amplitude.
    """
    values = list(
        backoff_delays(
            attempts=201,
            delay=0.1,
            multiplier=1.0,
            max_delay=1000.0,
            jitter_seconds=1.0,
            _random=_seeded(5),
        )
    )
    assert all(0.0 <= v <= 0.2 + 1e-12 for v in values), (min(values), max(values))
    assert sum(1 for v in values if v == 0.0) == 0


def test_jitter_seconds_must_be_non_negative():
    with pytest.raises(ValueError, match="jitter_seconds"):
        list(backoff_delays(jitter_seconds=-1.0))


def test_retry_passes_the_new_modes_through():
    """`retry` shares the schedule, so the modes have to reach it."""
    waits = []
    calls = []

    def flaky():
        calls.append(1)
        raise OSError("nope")

    with pytest.raises(OSError):
        netimps.retry(
            flaky,
            attempts=4,
            delay=10.0,
            multiplier=1.0,
            max_delay=1000.0,
            jitter_seconds=1.0,
            _sleep=waits.append,
            _random=_seeded(1),
        )
    assert len(calls) == 4
    assert all(9.0 <= w <= 11.0 for w in waits), waits


# --- Backoff: the stateful timer ------------------------------------------- #


def test_backoff_grows_on_advance_and_resets_on_progress():
    """The shape `backoff_delays` cannot express, and which every protocol
    client here had hand-rolled: a retransmission timer.

    A retransmission timer doubles to a ceiling on loss and returns to the base
    the moment the peer moves the transfer forward.
    """
    timer = Backoff(delay=1.0, multiplier=2.0, max_delay=8.0)
    assert timer.delay == 1.0
    assert timer.attempt == 0
    assert [timer.advance() for _ in range(5)] == [2.0, 4.0, 8.0, 8.0, 8.0]
    assert timer.attempt == 5
    assert timer.reset() == 1.0
    assert timer.attempt == 0
    assert timer.delay == 1.0


def test_backoff_delay_is_stable_between_advances():
    """Arming a deadline, logging it and comparing against it must see one
    value. A property that re-jittered per read would be a trap for exactly
    the code this exists for.
    """
    timer = Backoff(delay=1.0, jitter=0.5, max_delay=30.0, _random=_seeded())
    first = timer.delay
    # Repeated reads must not re-draw.
    assert [timer.delay for _ in range(10)] == [first] * 10
    timer.advance()
    second = timer.delay
    assert [timer.delay for _ in range(10)] == [second] * 10
    # And the step really moved: the base doubled, so even with jitter the new
    # value cannot still be in the old step's range.
    assert second > first


def test_backoff_never_shrinks_on_loss():
    """A multiplier below 1 would make a session retransmit *faster* the worse
    the link got, which is always a bug. Floored at 1.0."""
    timer = Backoff(delay=1.0, multiplier=0.5, max_delay=8.0)
    assert [timer.delay, timer.advance(), timer.advance()] == [1.0, 1.0, 1.0]


def test_backoff_ceiling_cannot_truncate_the_base():
    """`max_delay` under `delay` would silently shorten the very first wait
    below what the caller asked for, so it is floored at the base."""
    timer = Backoff(delay=4.0, multiplier=2.0, max_delay=1.0)
    assert timer.delay == 4.0
    assert timer.advance() == 4.0


def test_backoff_jitter_is_off_by_default_unlike_backoff_delays():
    """Deliberately the opposite default.

    Jitter desynchronises many clients retrying together; a point-to-point
    session retransmitting to one peer has no herd to avoid, and TFTP and TCP
    both specify plain doubling.
    """
    timer = Backoff(delay=1.0, multiplier=2.0, max_delay=100.0)
    assert [timer.delay, timer.advance(), timer.advance()] == [1.0, 2.0, 4.0]


def test_backoff_accepts_the_symmetric_modes_too():
    """A DHCP client wants the timer *and* the RFC jitter."""
    timer = Backoff(
        delay=4.0,
        multiplier=2.0,
        max_delay=64.0,
        jitter_seconds=1.0,
        _random=_seeded(9),
    )
    seen = [timer.delay] + [timer.advance() for _ in range(6)]
    for value, base in zip(seen, [4, 8, 16, 32, 64, 64, 64]):
        assert abs(value - base) <= 1.0, (value, base)


def test_backoff_rejects_nonsense_arguments():
    with pytest.raises(ValueError, match="delay"):
        Backoff(delay=-1.0)
    with pytest.raises(ValueError, match="jitter"):
        Backoff(jitter=2.0)
    with pytest.raises(ValueError, match="jitter_seconds"):
        Backoff(jitter_seconds=-0.5)


def test_backoff_repr_is_useful_in_a_log():
    timer = Backoff(delay=1.0, multiplier=2.0, max_delay=8.0)
    timer.advance()
    text = repr(timer)
    assert "Backoff(" in text and "attempt=1" in text
