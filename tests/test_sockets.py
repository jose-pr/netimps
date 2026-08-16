"""Tests for the socket / route / MTU helpers.

Anything that would touch the real network is either pointed at loopback or
mocked. The few live calls (source-address selection, route lookup) are
assertions about *shape*, never about this host's actual addresses.
"""

import socket

import pytest

import netimps
from netimps import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    Route,
    get_free_port,
    get_route,
    get_source_ip,
    tcp_check,
    wait_for_port,
)
from netimps import _sockets

# --------------------------------------------------------------------------- #
# get_source_ip                                                                #
# --------------------------------------------------------------------------- #


def test_get_source_ip_for_loopback_is_loopback():
    """Routing to 127.0.0.1 must come from a loopback address."""
    source = get_source_ip("127.0.0.1")
    assert source is not None
    assert source.is_loopback


def test_get_source_ip_returns_an_address_object():
    source = get_source_ip()
    # None is legitimate on a host with no route at all.
    if source is not None:
        assert isinstance(source, (netimps.IPv4Address, netimps.IPv6Address))


def test_get_source_ip_sends_no_packets(monkeypatch):
    """The UDP-connect trick must never call send/sendto."""
    real_socket = socket.socket

    class NoSend(real_socket):
        def send(self, *a, **k):  # pragma: no cover - must not run
            raise AssertionError("get_source_ip must not send")

        def sendto(self, *a, **k):  # pragma: no cover - must not run
            raise AssertionError("get_source_ip must not send")

    monkeypatch.setattr(_sockets._socket, "socket", NoSend)
    assert get_source_ip("127.0.0.1") is not None


def test_get_source_ip_unroutable_is_none(monkeypatch):
    def refuse(*a, **k):
        raise OSError("network unreachable")

    monkeypatch.setattr(_sockets._socket.socket, "connect", refuse)
    assert get_source_ip("203.0.113.1") is None


# --------------------------------------------------------------------------- #
# get_free_port                                                                    #
# --------------------------------------------------------------------------- #


def test_free_port_is_bindable():
    port = get_free_port()
    assert 1 <= port <= 65535
    # The whole point: the port must actually be usable afterwards.
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
    finally:
        sock.close()


def test_free_port_varies():
    """Consecutive calls should not hand out the same port."""
    ports = {get_free_port() for _ in range(5)}
    assert len(ports) > 1


# --------------------------------------------------------------------------- #
# tcp_check / wait_for_port                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture
def listening_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    yield server.getsockname()[1]
    server.close()


def test_tcp_check_open_port(listening_port):
    assert tcp_check("127.0.0.1", listening_port, timeout=2.0) is True


def test_tcp_check_closed_port():
    port = get_free_port()  # nothing listening there
    assert tcp_check("127.0.0.1", port, timeout=1.0) is False


@pytest.mark.parametrize(
    "host, port",
    [
        ("no-such-host-xyz.invalid", 80),  # unresolvable
        ("127.0.0.1", 0),  # invalid port
    ],
)
def test_tcp_check_never_raises(host, port):
    assert tcp_check(host, port, timeout=1.0) is False


def test_wait_for_port_returns_immediately_when_open(listening_port):
    assert wait_for_port("127.0.0.1", listening_port, timeout=5.0) is True


def test_wait_for_port_times_out():
    import time

    port = get_free_port()
    start = time.monotonic()
    assert wait_for_port("127.0.0.1", port, timeout=0.6, interval=0.05) is False
    # Must honour the deadline rather than running to some internal default.
    assert time.monotonic() - start < 4.0


def test_wait_for_port_respects_deadline_with_slow_connects(monkeypatch):
    """A blocking connect must not let the call overrun its timeout."""
    import time

    def slow(host, port, timeout=None):
        time.sleep(min(timeout or 0.2, 0.2))
        return False

    monkeypatch.setattr(_sockets, "tcp_check", slow)
    start = time.monotonic()
    assert wait_for_port("127.0.0.1", 9, timeout=0.5) is False
    assert time.monotonic() - start < 3.0


# --------------------------------------------------------------------------- #
# AddressLike: dst accepts address objects and interfaces, rejects networks   #
# --------------------------------------------------------------------------- #


def test_tcp_check_accepts_interface_and_address_objects(listening_port):
    assert tcp_check(IPv4Interface("127.0.0.1/8"), listening_port, timeout=2.0) is True
    assert tcp_check(IPv4Address("127.0.0.1"), listening_port, timeout=2.0) is True


def test_tcp_check_rejects_network():
    """A caller bug in the argument itself still raises -- not a reachability result."""
    with pytest.raises(TypeError, match="not a network"):
        tcp_check(IPv4Network("127.0.0.0/8"), 80)


def test_wait_for_port_accepts_interface_object(listening_port):
    assert (
        wait_for_port(IPv4Interface("127.0.0.1/8"), listening_port, timeout=5.0) is True
    )


def test_get_source_ip_accepts_interface_object():
    source = get_source_ip(IPv4Interface("127.0.0.1/8"))
    assert source is not None
    assert source.is_loopback


# --------------------------------------------------------------------------- #
# get_route / Route                                                            #
# --------------------------------------------------------------------------- #


def test_route_to_loopback_is_on_link():
    route = get_route("127.0.0.1")
    assert route.on_link
    assert route.gateway is None


def test_get_route_accepts_interface_object():
    route = get_route(IPv4Interface("127.0.0.1/8"))
    assert route.on_link
    assert route.gateway is None


def test_route_shape():
    route = get_route("8.8.8.8")
    assert isinstance(route, Route)
    assert route.dst is not None
    if route.src is not None:
        assert isinstance(route.src, (netimps.IPv4Address, netimps.IPv6Address))
    assert isinstance(route.interface_index, int)


def test_route_never_raises_for_bad_destination():
    route = get_route("no-such-host-xyz.invalid")
    assert isinstance(route, Route)


def test_route_on_link_is_derived_from_gateway():
    assert Route(dst="x", gateway=None).on_link is True
    assert Route(dst="x", gateway=netimps.parse("10.0.0.1")).on_link is False


def test_route_equality_and_repr():
    a = Route(dst=netimps.parse("8.8.8.8"), src=netimps.parse("10.0.0.5"))
    b = Route(dst=netimps.parse("8.8.8.8"), src=netimps.parse("10.0.0.5"))
    assert a == b
    assert a != Route(dst=netimps.parse("1.1.1.1"))
    assert a != "not a route"
    assert "8.8.8.8" in repr(a)


# --------------------------------------------------------------------------- #
# hop_count                                                                    #
# --------------------------------------------------------------------------- #


def test_hop_count_raises_without_privileges_when_fallback_disabled(monkeypatch):
    """The documented privilege contract, with the traceroute path refused."""

    def no_raw(family, kind, proto=0, *a, **k):
        if kind == socket.SOCK_RAW:
            raise PermissionError("not permitted")
        return socket.socket(family, kind, proto)

    monkeypatch.setattr(_sockets._socket, "socket", no_raw)
    with pytest.raises(PermissionError, match="raw socket"):
        netimps.hop_count("127.0.0.1", allow_traceroute=False)


def test_hop_count_falls_back_to_traceroute(monkeypatch):
    """Without a raw socket, the system tool is used instead of failing."""

    def no_raw(family, kind, proto=0, *a, **k):
        if kind == socket.SOCK_RAW:
            raise PermissionError("not permitted")
        return socket.socket(family, kind, proto)

    monkeypatch.setattr(_sockets._socket, "socket", no_raw)
    monkeypatch.setattr(
        _sockets, "_hop_count_traceroute", lambda target, hops, timeout: 7
    )
    assert netimps.hop_count("127.0.0.1") == 7


def test_hop_count_unresolvable_is_none(monkeypatch):
    def fail(_name):
        raise OSError("no such host")

    monkeypatch.setattr(_sockets._socket, "gethostbyname", fail)
    assert netimps.hop_count("nope.invalid") is None


def test_hop_count_accepts_interface_object(monkeypatch):
    """The .ip must reach gethostbyname, not "127.0.0.1/8" as a whole string."""
    seen = []

    def fake_gethostbyname(name):
        seen.append(name)
        return name

    def no_raw(family, kind, proto=0, *a, **k):
        if kind == socket.SOCK_RAW:
            raise PermissionError("not permitted")
        return socket.socket(family, kind, proto)

    monkeypatch.setattr(_sockets._socket, "gethostbyname", fake_gethostbyname)
    monkeypatch.setattr(_sockets._socket, "socket", no_raw)
    monkeypatch.setattr(
        _sockets, "_hop_count_traceroute", lambda target, hops, timeout: 1
    )
    netimps.hop_count(IPv4Interface("127.0.0.1/8"), allow_traceroute=True)
    assert seen == ["127.0.0.1"]


def test_traceroute_parser_reads_hop_number(monkeypatch):
    """Only the hop number and destination address are read, never the prose."""
    output = (
        "\nTracing route to 8.8.8.8 over a maximum of 30 hops\n\n"
        "  1     5 ms     2 ms     4 ms  192.0.2.1 \n"
        "  2     *        *        *     Request timed out.\n"
        "  3     9 ms     7 ms    11 ms  8.8.8.8 \n\n"
        "Trace complete.\n"
    )

    class Result:
        stdout = output

    monkeypatch.setattr(_sockets, "_subprocess_run", lambda *a, **k: Result())
    assert _sockets._hop_count_traceroute("8.8.8.8", 30, 1.0) == 3


def test_traceroute_parser_localised_prose_is_ignored(monkeypatch):
    """A non-English traceroute must still parse -- no prose matching."""
    output = (
        "  1     5 ms     2 ms     4 ms  192.0.2.1 \n"
        "  2     *        *        *     Expiration du delai d'attente.\n"
        "  3     9 ms     7 ms    11 ms  1.1.1.1 \n"
    )

    class Result:
        stdout = output

    monkeypatch.setattr(_sockets, "_subprocess_run", lambda *a, **k: Result())
    assert _sockets._hop_count_traceroute("1.1.1.1", 30, 1.0) == 3


def test_traceroute_parser_missing_binary_is_none(monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError("traceroute not installed")

    monkeypatch.setattr(_sockets, "_subprocess_run", missing)
    assert _sockets._hop_count_traceroute("8.8.8.8", 30, 1.0) is None


def test_traceroute_parser_no_match_is_none(monkeypatch):
    class Result:
        stdout = "  1     5 ms  192.0.2.1 \n  2     *  Request timed out.\n"

    monkeypatch.setattr(_sockets, "_subprocess_run", lambda *a, **k: Result())
    assert _sockets._hop_count_traceroute("8.8.8.8", 30, 1.0) is None


# --------------------------------------------------------------------------- #
# ICMP reply classification                                                    #
# --------------------------------------------------------------------------- #


def test_is_icmp_reply_skips_variable_ip_header():
    # IHL=5 -> 20-byte header, then ICMP type 11 (time exceeded).
    assert _sockets._is_icmp_reply(b"\x45" + b"\x00" * 19 + b"\x0b")
    # IHL=6 -> 24-byte header; the type must be read at the right offset.
    assert _sockets._is_icmp_reply(b"\x46" + b"\x00" * 23 + b"\x00")
    # Type 8 is an echo *request*, not a reply to our probe.
    assert not _sockets._is_icmp_reply(b"\x45" + b"\x00" * 19 + b"\x08")


def test_is_icmp_reply_rejects_short_packets():
    assert not _sockets._is_icmp_reply(b"")
    assert not _sockets._is_icmp_reply(b"\x45" * 5)


# --------------------------------------------------------------------------- #
# MTU: get_pmtu (lookup) and discover_mtu (measurement)                       #
# --------------------------------------------------------------------------- #


def test_get_pmtu_returns_none_without_ip_mtu(monkeypatch):
    """Windows has no IP_MTU; the documented answer is None, not a guess."""
    monkeypatch.delattr(_sockets._socket, "IP_MTU", raising=False)
    assert netimps.get_pmtu("127.0.0.1") is None


def test_get_pmtu_shape():
    """A lookup, so None is a perfectly normal answer."""
    result = netimps.get_pmtu("127.0.0.1")
    assert result is None or (isinstance(result, int) and result > 0)


def test_get_pmtu_accepts_interface_object():
    """Must not raise -- IPv4Interface used to stringify with its /prefix intact."""
    result = netimps.get_pmtu(IPv4Interface("127.0.0.1/8"))
    assert result is None or (isinstance(result, int) and result > 0)


def test_get_pmtu_sends_nothing(monkeypatch):
    """It is a lookup, not a measurement -- no packets leave."""
    calls = []
    real = _sockets._socket.socket

    class NoSend(real):
        def send(self, *a, **k):  # pragma: no cover - must not run
            calls.append("send")
            raise AssertionError("get_pmtu must not send")

        def sendto(self, *a, **k):  # pragma: no cover - must not run
            calls.append("sendto")
            raise AssertionError("get_pmtu must not send")

    monkeypatch.setattr(_sockets._socket, "socket", NoSend)
    netimps.get_pmtu("127.0.0.1")
    assert not calls


def test_discover_mtu_probe_false_delegates_to_get_pmtu(monkeypatch):
    """probe=False is exactly get_pmtu -- and must not ping."""
    monkeypatch.setattr(_sockets, "get_pmtu", lambda dst, port=80: 1400)
    monkeypatch.setattr(
        netimps, "ping", lambda *a, **k: pytest.fail("probe=False must not ping")
    )
    assert netimps.discover_mtu("10.0.0.1", probe=False) == 1400


def test_discover_mtu_ignores_the_kernel_by_default(monkeypatch):
    """The default measures the real path rather than trusting a cached guess.

    Verified on a real host where the two genuinely disagreed: the local link
    was 9000 and get_pmtu returned None, while probing found the true 1500.
    """
    monkeypatch.setattr(
        _sockets, "get_pmtu", lambda *a, **k: pytest.fail("default must probe")
    )
    monkeypatch.setattr(netimps, "ping", _fake_ping(1500))
    assert netimps.discover_mtu("10.0.0.1") == 1500


# --------------------------------------------------------------------------- #
# discover_mtu                                                                 #
# --------------------------------------------------------------------------- #


def _fake_ping(limit):
    """A ping that succeeds only when the wire packet fits within `limit`."""

    def ping(dst, size=None, dont_fragment=False, timeout=None, src=None):
        assert dont_fragment, "the probe must set DF or it measures nothing"
        return netimps.PingResult((size or 0) + 28 <= limit, dst)

    return ping


def test_discover_mtu_finds_the_boundary(monkeypatch):
    monkeypatch.setattr(netimps._sockets, "ping", _fake_ping(1500), raising=False)
    monkeypatch.setattr(netimps, "ping", _fake_ping(1500))
    assert netimps.discover_mtu("10.0.0.1") == 1500


def test_discover_mtu_accepts_interface_object(monkeypatch):
    """The .ip is what gets pinged -- not "10.0.0.1/24" as a whole string."""
    seen = []

    def fake_ping(dst, size=None, dont_fragment=False, timeout=None, src=None):
        seen.append(dst)
        return netimps.PingResult((size or 0) + 28 <= 1500, dst)

    monkeypatch.setattr(netimps._sockets, "ping", fake_ping, raising=False)
    monkeypatch.setattr(netimps, "ping", fake_ping)
    assert netimps.discover_mtu(IPv4Interface("10.0.0.1/24")) == 1500
    assert all(d == "10.0.0.1" for d in seen)


@pytest.mark.parametrize("limit", [576, 1280, 1420, 1500, 9000])
def test_discover_mtu_across_common_values(monkeypatch, limit):
    monkeypatch.setattr(netimps, "ping", _fake_ping(limit))
    assert netimps.discover_mtu("10.0.0.1") == limit


def test_discover_mtu_returns_none_when_nothing_answers(monkeypatch):
    """A firewalled host must not read as a tiny MTU."""
    monkeypatch.setattr(netimps, "ping", lambda *a, **k: netimps.PingResult(False, "x"))
    assert netimps.discover_mtu("10.0.0.1") is None


def test_discover_mtu_short_circuits_at_the_ceiling(monkeypatch):
    """If the ceiling survives there is nothing to search for."""
    calls = []

    def ping(dst, size=None, **kwargs):
        calls.append(size)
        return netimps.PingResult(True, dst)

    monkeypatch.setattr(netimps, "ping", ping)
    assert netimps.discover_mtu("10.0.0.1", low=576, high=9000) == 9000
    assert len(calls) == 2, "one probe at the floor, one at the ceiling"


def test_discover_mtu_result_includes_headers(monkeypatch):
    """The answer is comparable with Interface.mtu, so it counts headers.

    A binary search necessarily probes *above* the boundary to bracket it, so
    the assertion is about the largest **surviving** payload, not the largest
    attempted one.
    """
    survived = []

    def ping(dst, size=None, **kwargs):
        ok = (size or 0) + 28 <= 1500
        if ok:
            survived.append(size)
        return netimps.PingResult(ok, dst)

    monkeypatch.setattr(netimps, "ping", ping)
    result = netimps.discover_mtu("10.0.0.1")
    assert result == 1500
    # The reported MTU is the largest surviving payload plus the 28-byte
    # IPv4 + ICMP overhead.
    assert max(survived) + 28 == result


# --------------------------------------------------------------------------- #
# ping methods / MTU by protocol                                               #
# --------------------------------------------------------------------------- #


def test_ip_header_bytes_by_family():
    """Every wire-size sum depends on this; v6 headers are 20 bytes bigger."""
    assert _sockets._ip_header_bytes("8.8.8.8") == 20
    assert _sockets._ip_header_bytes("2001:db8::1") == 40
    # TCP adds 20 on top of whichever.
    assert _sockets._tcp_header_overhead("8.8.8.8") == 40
    assert _sockets._tcp_header_overhead("2001:db8::1") == 60


def test_ip_header_bytes_falls_back_to_v4():
    """An unresolvable name assumes IPv4: under-reporting an MTU is safer."""
    assert _sockets._ip_header_bytes("no-such-host-xyz.invalid") == 20


def test_discover_mtu_rejects_unknown_method():
    with pytest.raises(ValueError, match="must be 'icmp', 'udp' or 'tcp'"):
        netimps.discover_mtu("10.0.0.1", method="sctp")


def test_discover_mtu_tcp_uses_mss_plus_headers(monkeypatch):
    """TCP cannot probe, so it derives the MTU from the negotiated MSS."""
    monkeypatch.setattr(_sockets, "get_tcp_mss", lambda *a, **k: 1400)
    assert netimps.discover_mtu("8.8.8.8", port=443, method="tcp") == 1440
    # IPv6 adds 20 more header bytes.
    assert netimps.discover_mtu("2001:db8::1", port=443, method="tcp") == 1460


def test_discover_mtu_tcp_none_when_mss_unavailable(monkeypatch):
    monkeypatch.setattr(_sockets, "get_tcp_mss", lambda *a, **k: None)
    assert netimps.discover_mtu("8.8.8.8", port=443, method="tcp") is None


def test_get_tcp_mss_shape():
    """Against a real local listener, so no external dependency."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        mss = netimps.get_tcp_mss("127.0.0.1", port, timeout=2.0)
        assert mss is None or (isinstance(mss, int) and mss > 0)
    finally:
        server.close()


def test_get_tcp_mss_unreachable_is_none():
    assert (
        netimps.get_tcp_mss("127.0.0.1", netimps.get_free_port(), timeout=1.0) is None
    )


def test_get_tcp_mss_accepts_interface_object():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        mss = netimps.get_tcp_mss(IPv4Interface("127.0.0.1/8"), port, timeout=2.0)
        assert mss is None or (isinstance(mss, int) and mss > 0)
    finally:
        server.close()


def test_ping_rejects_unknown_method():
    with pytest.raises(ValueError, match="must be 'icmp', 'tcp' or 'udp'"):
        netimps.ping("10.0.0.1", method="sctp", port=1)


def test_ping_tcp_and_udp_require_a_port():
    for method in ("tcp", "udp"):
        with pytest.raises(ValueError, match="needs a port"):
            netimps.ping("10.0.0.1", method=method)


def test_ping_tcp_measures_a_real_handshake():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        result = netimps.ping("127.0.0.1", method="tcp", port=port, timeout=2.0)
        assert result.ok
        assert result.rtt_ms is not None and result.rtt_ms >= 0
    finally:
        server.close()


def test_ping_tcp_unreachable_is_falsy():
    result = netimps.ping("192.0.2.99", method="tcp", port=9, timeout=1.0)
    assert not result


def test_tcp_check_and_ping_tcp_ask_different_questions():
    """A refused port: the service is down, but the host answered.

    tcp_check is service-liveness, ping(method="tcp") is host-liveness. On
    platforms that surface the RST as ConnectionRefusedError they disagree
    here, which is the whole reason both exist.
    """
    from netimps._ping import _tcp_ping

    port = netimps.get_free_port()
    assert netimps.tcp_check("127.0.0.1", port, timeout=1.0) is False
    ok, rtt, note = _tcp_ping("127.0.0.1", port, 1.0)
    if note == "refused":  # pragma: no branch - platform dependent
        assert ok, "a refusal proves the host is alive"
        assert rtt is not None


# --------------------------------------------------------------------------- #
# ping(method="tcp"/"udp"): address family and the UDP liveness signal          #
# --------------------------------------------------------------------------- #


@pytest.fixture
def v6_loopback():
    """A listening IPv6 loopback socket, or a skip on a v4-only host."""
    try:
        server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server.bind(("::1", 0))
        server.listen(1)
    except OSError:  # pragma: no cover - env dependent
        pytest.skip("no IPv6 loopback on this host")
    try:
        yield server.getsockname()[1]
    finally:
        server.close()


def test_ping_tcp_reaches_an_ipv6_destination(v6_loopback):
    """A v6 destination must not read as unreachable.

    The regression: `_tcp_ping` opened an AF_INET socket unconditionally, so
    connecting to a v6 address raised OSError inside `connect` and the probe
    reported "unreachable" -- a wrong *falsy answer*, not an error.
    """
    result = netimps.ping("::1", method="tcp", port=v6_loopback, timeout=2.0)
    assert result.ok
    assert result.rtt_ms is not None


def test_ping_tcp_probe_family_follows_the_destination(monkeypatch, v6_loopback):
    """Pinned deterministically: the probe socket is AF_INET6 for a v6 dst."""
    families = []
    real_socket = socket.socket

    def recording(family, *args, **kwargs):
        families.append(family)
        return real_socket(family, *args, **kwargs)

    monkeypatch.setattr(netimps._ping._socket, "socket", recording)
    netimps.ping("::1", method="tcp", port=v6_loopback, timeout=2.0)
    assert families == [socket.AF_INET6]


def test_ping_tcp_honours_ipv6_flag_for_a_hostname(monkeypatch):
    """`ipv6=` is not ICMP-only -- it selects the tcp/udp probe family too."""
    seen = {}

    def fake_getaddrinfo(host, port, family=0, type=0, *args, **kwargs):
        seen["family"] = family
        raise OSError("resolution blocked in tests")

    monkeypatch.setattr(netimps._ping._socket, "getaddrinfo", fake_getaddrinfo)
    netimps.ping("host.invalid", method="tcp", port=80, ipv6=True)
    assert seen["family"] == socket.AF_INET6
    netimps.ping("host.invalid", method="tcp", port=80, ipv6=False)
    assert seen["family"] == socket.AF_INET
    netimps.ping("host.invalid", method="tcp", port=80)
    assert seen["family"] == socket.AF_UNSPEC


def test_udp_ping_connects_before_sending(monkeypatch):
    """The probe socket must be connected, and that is not a stylistic choice.

    POSIX delivers asynchronous ICMP errors only to a *connected* UDP socket,
    so the previous `sendto`/`recvfrom` pair never saw the port-unreachable
    that the documented contract treats as proof of liveness -- it just timed
    out, making `method="udp"` under-report on Linux/macOS while looking
    correct on Windows.
    """
    from netimps._ping import _udp_ping

    order = []

    class Recording:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            order.append("connect")

        def send(self, payload):
            order.append("send")
            return len(payload)

        def recv(self, size):
            order.append("recv")
            raise ConnectionRefusedError("ICMP port unreachable")

        def sendto(self, payload, address):  # pragma: no cover - must not run
            order.append("sendto")

        def close(self):
            pass

    monkeypatch.setattr(netimps._ping._socket, "socket", lambda *a, **k: Recording())
    ok, rtt, note = _udp_ping("127.0.0.1", 9, 1.0)
    assert order == ["connect", "send", "recv"]
    assert ok and note == "port-unreachable"


def test_udp_ping_treats_connection_reset_as_liveness_too(monkeypatch):
    """Windows spells the same ICMP error ECONNRESET; both must count."""
    from netimps._ping import _udp_ping

    class Resetting:
        def settimeout(self, timeout):
            pass

        def connect(self, address):
            pass

        def send(self, payload):
            return len(payload)

        def recv(self, size):
            raise ConnectionResetError("WSAECONNRESET")

        def close(self):
            pass

    monkeypatch.setattr(netimps._ping._socket, "socket", lambda *a, **k: Resetting())
    ok, _rtt, note = _udp_ping("127.0.0.1", 9, 1.0)
    assert ok and note == "port-unreachable"


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_ping_udp_closed_loopback_port_proves_liveness(host):
    """The real thing, unprivileged: nothing listening, host obviously up.

    Skipped rather than failed when the platform declines to deliver the
    ICMP error (macOS rate-limits them, and a host firewall can drop them) --
    that is an environment fact. The connected-socket *mechanism* is asserted
    deterministically by the tests above, which need no traffic at all.
    """
    if host == "::1":
        try:
            probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            probe.close()
        except OSError:  # pragma: no cover - env dependent
            pytest.skip("no IPv6 on this host")

    port = netimps.get_free_port()
    result = netimps.ping(host, method="udp", port=port, timeout=2.0)
    if not result:  # pragma: no cover - env dependent
        pytest.skip("this host does not deliver ICMP port-unreachable to us")
    assert result.rtt_ms is not None


def test_discover_mtu_forwards_ping_kwargs(monkeypatch):
    """ipv6/tries and friends reach ping rather than being dropped."""
    seen = []

    def ping(dst, size=None, dont_fragment=False, timeout=None, src=None, **kw):
        seen.append(kw)
        return netimps.PingResult((size or 0) + 28 <= 1500, dst)

    monkeypatch.setattr(netimps, "ping", ping)
    netimps.discover_mtu("10.0.0.1", tries=3, ipv6=False)
    assert seen and all(k == {"tries": 3, "ipv6": False} for k in seen)


@pytest.mark.parametrize("owned", ["size", "dont_fragment"])
def test_discover_mtu_rejects_search_owned_kwargs(owned):
    """Overriding what the search varies would silently break the result."""
    with pytest.raises(TypeError, match="sets"):
        netimps.discover_mtu("10.0.0.1", **{owned: 1})
