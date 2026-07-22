"""Tests for the helpers centralized from the sibling repos.

bind / bind_error_hint / interface_for / UdpEndpoint / Host / retry, plus the
shared interface-spec resolution they all lean on. Loopback only.
"""

import errno
import socket

import pytest

import netimps
from netimps import Host, UdpEndpoint, backoff_delays, bind, interface_for, retry
from netimps import _iface_spec, _udp

# --------------------------------------------------------------------------- #
# bind                                                                         #
# --------------------------------------------------------------------------- #


def test_bind_datagram_defaults():
    sock = bind("127.0.0.1", 0)
    try:
        host, port = sock.getsockname()
        assert host == "127.0.0.1" and port > 0
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
    finally:
        sock.close()


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
    denied = OSError("denied")
    denied.winerror = 10013
    assert "permission denied" in (netimps.bind_error_hint(denied, 67) or "").lower()

    in_use = OSError("in use")
    in_use.winerror = 10048
    assert "already in use" in (netimps.bind_error_hint(in_use, 80) or "")


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


def test_interface_for_loopback():
    iface = interface_for("127.0.0.1")
    assert iface is not None and iface.is_loopback


def test_interface_for_unknown_is_none_when_strict():
    assert interface_for("192.0.2.99") is None


def test_interface_for_unknown_synthesizes_when_not_strict():
    iface = interface_for("192.0.2.99", strict=False)
    assert iface is not None
    assert iface.name == "<unknown>"
    # A host route, matching how degraded enumeration reports itself.
    assert iface.ips[0].network.prefixlen == iface.ips[0].max_prefixlen


def test_interface_for_garbage_is_none():
    assert interface_for("not-an-address") is None
    assert interface_for(None) is None


# --------------------------------------------------------------------------- #
# shared interface-spec resolution                                             #
# --------------------------------------------------------------------------- #


def test_interface_spec_none_is_none():
    assert _iface_spec.interface_address(None) is None


def test_interface_spec_returns_parsed_addresses():
    """Addresses come back parsed, not as strings -- the package-wide rule."""
    result = _iface_spec.interface_address("10.0.0.5")
    assert result == netimps.parse("10.0.0.5")
    assert not isinstance(result, str)


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


def test_udp_endpoint_round_trip():
    with UdpEndpoint(bind("127.0.0.1", 0)) as endpoint:
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = bind("127.0.0.1", 0)
        try:
            sender.sendto(b"payload", ("127.0.0.1", port))
            packet = endpoint.recv(1024)
        finally:
            sender.close()
    assert packet.data == b"payload"
    assert packet.sender[0] == "127.0.0.1"


def test_udp_endpoint_degrades_without_pktinfo(monkeypatch):
    """No IP_PKTINFO must mean empty interface fields, not a failure."""
    monkeypatch.setattr(_udp, "_IP_PKTINFO", None)
    with UdpEndpoint(bind("127.0.0.1", 0)) as endpoint:
        assert endpoint.supports_pktinfo is False
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


def test_udp_endpoint_send_falls_back_without_source():
    with UdpEndpoint(bind("127.0.0.1", 0)) as receiver:
        receiver.socket.settimeout(5.0)
        port = receiver.socket.getsockname()[1]
        with UdpEndpoint(bind("127.0.0.1", 0)) as sender:
            assert sender.send(b"hi", "127.0.0.1", port) == 2
        assert receiver.recv(64).data == b"hi"


def test_udp_endpoint_repr_and_close():
    endpoint = UdpEndpoint(bind("127.0.0.1", 0))
    assert "UdpEndpoint(" in repr(endpoint)
    endpoint.close()


# --------------------------------------------------------------------------- #
# Host                                                                         #
# --------------------------------------------------------------------------- #


def test_host_keeps_the_original_text():
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

    def counting(_name):
        calls.append(1)
        return "93.184.216.34"

    monkeypatch.setattr(netimps._ip._socket, "gethostbyname", counting)
    host = Host("example.com")
    assert host.ip() == netimps.parse("93.184.216.34")
    assert host.ip() == netimps.parse("93.184.216.34")
    assert len(calls) == 1, "resolution should be cached"

    host.ip(refresh=True)
    assert len(calls) == 2, "refresh=True must retry"


def test_host_caches_failure_too(monkeypatch):
    calls = []

    def failing(_name):
        calls.append(1)
        raise OSError("no such host")

    monkeypatch.setattr(netimps._ip._socket, "gethostbyname", failing)
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
