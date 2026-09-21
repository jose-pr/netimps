"""Tests for the helpers centralized from the sibling repos.

bind / bind_error_hint / interface_for / UdpEndpoint / Host / retry, plus the
shared interface-spec resolution they all lean on. Loopback only.
"""

import errno
import ipaddress
import os
import socket
import struct

import pytest

import netimps
from netimps import (
    Host,
    Interface,
    MACAddress,
    UdpEndpoint,
    backoff_delays,
    bind,
    interface_for,
    interfaces_for,
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
        else:
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
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
# interface_for                                                                #
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
    assert list(interfaces_for(iface)) == [iface]
    assert interface_for(iface) is iface


def test_interfaces_for_exact_address_and_duplicate_order(monkeypatch):
    interfaces, calls = _mock_lookup_interfaces(monkeypatch)
    first, _, duplicate = interfaces

    assert list(interfaces_for("10.0.0.1")) == [first, duplicate]
    assert calls == [True]
    calls.clear()
    assert interface_for(ipaddress.ip_address("10.0.0.1")) is first
    assert calls == [True]


def test_interfaces_for_ip_interface_matches_exact_ip_not_subnet(monkeypatch):
    interfaces, _ = _mock_lookup_interfaces(monkeypatch)
    assert list(interfaces_for(ipaddress.ip_interface("10.0.0.2/8"))) == [interfaces[1]]
    assert list(interfaces_for(ipaddress.ip_interface("10.0.0.99/24"))) == []


def test_interfaces_for_ipv4_network_deduplicates_and_preserves_order(monkeypatch):
    interfaces, calls = _mock_lookup_interfaces(monkeypatch)
    assert list(interfaces_for(ipaddress.ip_network("10.0.0.0/24"))) == interfaces
    assert calls == [True]

    calls.clear()
    assert list(interfaces_for("10.0.0.0/24")) == interfaces
    assert calls == [True]


def test_interfaces_for_ipv6_networks(monkeypatch):
    interfaces, _ = _mock_lookup_interfaces(monkeypatch)
    assert list(interfaces_for(ipaddress.ip_network("2001:db8:1::/64"))) == [
        interfaces[0]
    ]
    assert list(interfaces_for("2001:db8::/32")) == interfaces[:2]


def test_interfaces_for_mac_forms_and_duplicates(monkeypatch):
    interfaces, _ = _mock_lookup_interfaces(monkeypatch)
    shared = MACAddress("02:00:00:00:00:01")
    assert list(interfaces_for(shared)) == interfaces[:2]
    assert list(interfaces_for(str(shared))) == interfaces[:2]
    assert list(interfaces_for(shared.packed)) == interfaces[:2]


def test_interfaces_for_integer_remains_an_ip_query(monkeypatch):
    _, calls = _mock_lookup_interfaces(monkeypatch)
    shared = MACAddress("02:00:00:00:00:01")
    assert list(interfaces_for(int(shared))) == []
    assert calls == [True]


def test_interfaces_for_invalid_and_no_match(monkeypatch):
    _, calls = _mock_lookup_interfaces(monkeypatch)
    assert list(interfaces_for("not-an-address")) == []
    assert list(interfaces_for(None)) == []
    assert list(interfaces_for(ipaddress.ip_network("192.0.2.0/24"))) == []
    assert calls == [True]


def test_interface_for_unknown_is_none_when_strict(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    assert interface_for("192.0.2.99") is None


def test_interface_for_unknown_synthesizes_address_and_interface(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    iface = interface_for("192.0.2.99", strict=False)
    assert iface is not None
    assert iface.name == "<unknown>"
    # A host route, matching how degraded enumeration reports itself.
    assert iface.ips[0].network.prefixlen == iface.ips[0].max_prefixlen
    assert iface.ips[0].ip == ipaddress.ip_address("192.0.2.99")

    from_interface = interface_for(
        ipaddress.ip_interface("192.0.2.100/24"), strict=False
    )
    assert from_interface is not None
    assert from_interface.ips[0].ip == ipaddress.ip_address("192.0.2.100")


def test_interface_for_does_not_synthesize_network_or_mac(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    assert interface_for(ipaddress.ip_network("192.0.2.0/24"), strict=False) is None
    assert interface_for(MACAddress("02:00:00:00:00:99"), strict=False) is None


def test_interface_for_garbage_is_none(monkeypatch):
    _mock_lookup_interfaces(monkeypatch)
    assert interface_for("not-an-address") is None
    assert interface_for(None) is None


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
    # strict=False still passes it through: ping(src=) and UdpEndpoint.send()
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
# UdpEndpoint                                                                  #
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
    endpoint = UdpEndpoint(sock)
    endpoint.socket.settimeout(5.0)
    return endpoint


@pytest.mark.parametrize("family, host", _LOOPBACKS)
def test_udp_endpoint_round_trip(family, host):
    """The flag and the data must agree, for both address families.

    ``supports_pktinfo`` is the single thing the docs tell a caller to check,
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
        assert endpoint.supports_pktinfo

    if not endpoint.supports_pktinfo:
        assert packet.interface_index == 0 and packet.interface is None
        return
    assert packet.interface_index != 0
    assert packet.interface is not None
    assert packet.local_address is not None and packet.local_address.is_loopback


def test_udp_endpoint_reports_truncated_control_data():
    """``MSG_CTRUNC`` must reach the caller, not be dropped with the cmsg.

    The buffer is sized for several messages precisely so this is rare, but
    when it does happen the empty interface fields mean "something was
    discarded", not "the kernel had nothing to say" -- and nothing else
    distinguishes the two.
    """
    with UdpEndpoint(bind("127.0.0.1", 0)) as endpoint:
        if not endpoint.supports_pktinfo:
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
    with UdpEndpoint(bind("127.0.0.1", 0)) as endpoint:
        if not endpoint.supports_pktinfo:
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
            assert not sender.supports_src_pinning or hasattr(socket.socket, "sendmsg")
        packet = receiver.recv(64)
    assert packet.data == b"pinned"


def test_udp_endpoint_send_rejects_a_source_of_the_wrong_family():
    """Linux *accepts* an IPv6 cmsg on an AF_INET socket and ignores it.

    Measured: ``sendmsg`` returns the byte count, and the pin does nothing.
    So the mismatch has to be caught here -- the kernel will not report it.
    """
    with UdpEndpoint(bind("127.0.0.1", 0)) as sender:
        if not sender.supports_src_pinning:
            pytest.skip("no IPv4 source pinning on this platform")
        with pytest.raises(ValueError, match="IPv6 source"):
            sender.send(b"x", "127.0.0.1", 9, src="::1")


def test_udp_endpoint_send_rejects_an_unresolvable_source():
    """A spec naming no local adapter is a caller error, not a fallback.

    Sending from whatever the routing table picks is exactly the silent
    wrong answer ``src`` exists to prevent.
    """
    with UdpEndpoint(bind("127.0.0.1", 0)) as sender:
        if not sender.supports_src_pinning:
            pytest.skip("no IPv4 source pinning on this platform")
        with pytest.raises(ValueError, match="cannot resolve src"):
            sender.send(b"x", "127.0.0.1", 9, src="no-such-adapter")


def test_udp_endpoint_degrades_without_pktinfo(monkeypatch):
    """No IP_PKTINFO must mean empty interface fields, not a failure."""
    monkeypatch.setattr(_udp, "_IP_PKTINFO", None)
    with UdpEndpoint(bind("127.0.0.1", 0)) as endpoint:
        assert endpoint.supports_pktinfo is False
        # Same constant serves both directions for IPv4, so neither is claimed.
        assert endpoint.supports_src_pinning is False
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
    assert packet.local_address is None and packet.control_truncated is False


def test_udp_endpoint_send_falls_back_without_source():
    with UdpEndpoint(bind("127.0.0.1", 0)) as receiver:
        receiver.socket.settimeout(5.0)
        port = receiver.socket.getsockname()[1]
        with UdpEndpoint(bind("127.0.0.1", 0)) as sender:
            assert sender.send(b"hi", "127.0.0.1", port) == 2
        assert receiver.recv(64).data == b"hi"


def test_udp_endpoint_repr_and_close():
    endpoint = UdpEndpoint(bind("127.0.0.1", 0))
    # Both capability flags belong in the repr: they are what a bug report
    # about "interface is always None" needs to carry.
    assert "UdpEndpoint(" in repr(endpoint)
    assert "pktinfo=" in repr(endpoint) and "src_pinning=" in repr(endpoint)
    endpoint.close()


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
        raise OSError("no such host")

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
# MACAddress subclassing -- the guarantee pydhcp's migration depends on        #
# --------------------------------------------------------------------------- #


class _WireMAC(netimps.MACAddress):
    """A subclass overriding only __str__, as a consumer would."""

    def __str__(self):
        return self.as_str("-", upper=True)

    def hex(self, *args):
        return self.packed.hex(*args)


def test_mac_subclass_can_change_str_only():
    mac = _WireMAC("aa:bb:cc:dd:ee:ff")
    assert str(mac) == "AA-BB-CC-DD-EE-FF"
    # Everything else is inherited unchanged.
    assert mac.packed == bytes.fromhex("aabbccddeeff")
    assert mac.as_str() == "aa:bb:cc:dd:ee:ff"
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
    """.hex() is the one bytes method a consumer may need to re-add."""
    assert _WireMAC("aa:bb:cc:dd:ee:ff").hex("-").upper() == "AA-BB-CC-DD-EE-FF"
