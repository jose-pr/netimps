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
from netimps._sockets import (
    _bind,
    _connect,
    _hops,
    _mtu,
    _nexthop,
    _pmtu,
    _route,
)

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

    monkeypatch.setattr(_connect._socket, "socket", NoSend)
    assert get_source_ip("127.0.0.1") is not None


def test_get_source_ip_unroutable_is_none(monkeypatch):
    def refuse(*a, **k):
        raise OSError("network unreachable")

    monkeypatch.setattr(_connect._socket.socket, "connect", refuse)
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
def test_tcp_check_never_raises(host, port, no_such_host):
    assert tcp_check(host, port, timeout=1.0) is False


def test_wait_for_port_returns_immediately_when_open(listening_port):
    assert wait_for_port("127.0.0.1", listening_port, deadline=5.0) is True


def test_wait_for_port_times_out():
    import time

    port = get_free_port()
    start = time.monotonic()
    assert wait_for_port("127.0.0.1", port, deadline=0.6, interval=0.05) is False
    # Must honour the deadline rather than running to some internal default.
    assert time.monotonic() - start < 4.0


def test_wait_for_port_ends_at_deadline_not_at_timeout():
    """``deadline`` bounds the whole wait and ``timeout`` one attempt; the two
    were once the other way round, so a caller's ``timeout=30`` meant a wait of
    30 seconds on a closed port. With a long ``timeout`` and a short
    ``deadline`` the call has to return at the deadline."""
    import time

    port = get_free_port()
    start = time.monotonic()
    assert wait_for_port("127.0.0.1", port, deadline=0.4, timeout=30.0) is False
    assert 0.3 < time.monotonic() - start < 3.0


def test_wait_for_port_respects_deadline_with_slow_connects(monkeypatch):
    """A blocking connect must not let the call overrun its deadline.

    The previous version of this test capped its own stub at
    ``min(timeout, 0.2)``, so no connect ever blocked past the deadline and
    the assertion held no matter what the code did. This stub sleeps the
    *whole* timeout it is handed, which is what a real blocking connect does.
    """
    import time

    handed = []

    def slow(host, port, timeout=None):
        handed.append(timeout)
        time.sleep(timeout or 0)
        return False

    monkeypatch.setattr(_connect, "tcp_check", slow)
    start = time.monotonic()
    assert wait_for_port("127.0.0.1", 9, deadline=0.5, interval=0.05) is False
    elapsed = time.monotonic() - start
    # One attempt of slack, not one per address the name resolves to.
    assert elapsed < 0.5 + max(handed) + 0.5
    assert all(t <= 1.0 for t in handed), "per-try timeout must be clamped"


# --------------------------------------------------------------------------- #
# HostLike: dst accepts address objects and interfaces, rejects networks   #
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
        wait_for_port(IPv4Interface("127.0.0.1/8"), listening_port, deadline=5.0)
        is True
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


def test_route_never_raises_for_bad_destination(no_such_host):
    route = get_route("no-such-host-xyz.invalid")
    assert isinstance(route, Route)


def test_route_on_link_is_three_state():
    """ "No gateway" and "we never looked" are different answers.

    The old ``on_link = gateway is None`` reported a confident ``True`` for
    every destination whose next hop could not be looked up -- measured on
    macOS, where ``get_route('1.1.1.1')`` claimed on-link from a
    192.168.64.3/24 host. ``None`` is falsy, so ``if route.on_link:`` still
    takes the safe branch.
    """
    assert Route(dst="x", gateway=None).on_link is None
    assert not Route(dst="x", gateway=None).on_link
    assert Route(dst="x", gateway=None, on_link=True).on_link is True
    assert Route(dst="x", gateway=netimps.parse("10.0.0.1")).on_link is False
    # A gateway is proof on its own and overrides a contradicting flag.
    assert (
        Route(dst="x", gateway=netimps.parse("10.0.0.1"), on_link=True).on_link is False
    )


def test_route_equality_and_repr():
    a = Route(dst=netimps.parse("8.8.8.8"), src=netimps.parse("10.0.0.5"))
    b = Route(dst=netimps.parse("8.8.8.8"), src=netimps.parse("10.0.0.5"))
    assert a == b
    assert a != Route(dst=netimps.parse("1.1.1.1"))
    assert a != "not a route"
    assert "8.8.8.8" in repr(a)
    # An unknown on_link is not the same route as a known on-link one.
    assert a != Route(
        dst=netimps.parse("8.8.8.8"), src=netimps.parse("10.0.0.5"), on_link=True
    )


def test_route_is_hashable():
    """Defining __eq__ without __hash__ made Route unusable in a set at all."""
    a = Route(dst=netimps.parse("8.8.8.8"), src=netimps.parse("10.0.0.5"))
    b = Route(dst=netimps.parse("8.8.8.8"), src=netimps.parse("10.0.0.5"))
    assert hash(a) == hash(b)
    assert len({a, b}) == 1
    assert len({a, Route(dst=netimps.parse("1.1.1.1"))}) == 2


# --------------------------------------------------------------------------- #
# count_hops                                                                    #
# --------------------------------------------------------------------------- #


def test_hop_count_raises_without_privileges_when_fallback_disabled(monkeypatch):
    """The documented privilege contract, with the traceroute path refused."""

    def no_raw(family, kind, proto=0, *a, **k):
        if kind == socket.SOCK_RAW:
            raise PermissionError("not permitted")
        return socket.socket(family, kind, proto)

    monkeypatch.setattr(_hops._socket, "socket", no_raw)
    with pytest.raises(PermissionError, match="raw socket"):
        netimps.count_hops("127.0.0.1", allow_traceroute=False)


def _no_raw(family, kind, proto=0, *a, **k):
    if kind == socket.SOCK_RAW:
        raise PermissionError("not permitted")
    return socket.socket(family, kind, proto)


def test_hop_count_falls_back_to_traceroute(monkeypatch):
    """Without a raw socket, the system tool is used instead of failing."""
    monkeypatch.setattr(_hops._socket, "socket", _no_raw)
    monkeypatch.setattr(
        _hops, "_hop_count_traceroute", lambda target, hops, timeout, ipv6=False: 7
    )
    assert netimps.count_hops("127.0.0.1") == 7


def test_hop_count_unresolvable_is_none(monkeypatch):
    def fail(*a, **k):
        raise OSError("no such host")

    monkeypatch.setattr(netimps._ping._probe._socket, "getaddrinfo", fail)
    assert netimps.count_hops("nope.invalid") is None


def test_hop_count_accepts_interface_object(monkeypatch):
    """The .ip must reach the resolver, not "127.0.0.1/8" as a whole string."""
    seen = []
    real = socket.getaddrinfo

    def recording(host, port, family=0, kind=0, *a, **k):
        seen.append(host)
        return real(host, port, family, kind, *a, **k)

    monkeypatch.setattr(netimps._ping._probe._socket, "getaddrinfo", recording)
    monkeypatch.setattr(_hops._socket, "socket", _no_raw)
    monkeypatch.setattr(
        _hops, "_hop_count_traceroute", lambda target, hops, timeout, ipv6=False: 1
    )
    netimps.count_hops(IPv4Interface("127.0.0.1/8"), allow_traceroute=True)
    assert seen == ["127.0.0.1"]


def test_hop_count_resolves_with_getaddrinfo_not_gethostbyname(monkeypatch):
    """The v4-only lookup is gone: an AAAA-only name must still be probed.

    `gethostbyname` cannot return a v6 address at all, so a v6 destination
    used to leave count_hops returning None -- indistinguishable from "the
    host never answered". The repo's own AGENTS.md records this lesson; it
    had been applied in _ping.py and nowhere else.
    """

    def explode(_name):  # pragma: no cover - must not run
        raise AssertionError("gethostbyname is IPv4-only and must not be used")

    monkeypatch.setattr(_hops._socket, "gethostbyname", explode)
    monkeypatch.setattr(_hops._socket, "socket", _no_raw)

    seen = {}

    def fake_traceroute(target, hops, timeout, ipv6=False):
        seen["target"], seen["ipv6"] = target, ipv6
        return 3

    monkeypatch.setattr(_hops, "_hop_count_traceroute", fake_traceroute)
    assert netimps.count_hops("::1") == 3
    assert seen == {"target": "::1", "ipv6": True}


def test_hop_count_v6_probe_uses_the_v6_options(monkeypatch):
    """A v6 target gets an ICMPv6 raw socket and a hop limit, not IP_TTL.

    IP_TTL on an AF_INET6 socket raises rather than limiting anything, so
    without this the probe loop silently sent nothing.
    """
    families = []
    options = []

    class Recording:
        def __init__(self, family, kind, proto=0):
            families.append((family, kind, proto))

        def setsockopt(self, level, option, value):
            options.append((level, option, value))

        def sendto(self, payload, address):
            raise OSError("probe not actually sent in tests")

        def connect(self, address):
            raise OSError("no source lookup in tests")

        def settimeout(self, timeout):
            pass

        def bind(self, address):
            pass

        def recvfrom(self, size):
            raise socket.timeout()

        def close(self):
            pass

    monkeypatch.setattr(_hops._socket, "socket", Recording)
    monkeypatch.setattr(
        _hops,
        "_hop_count_traceroute",
        lambda target, hops, timeout, ipv6=False: None,
    )
    assert netimps.count_hops("::1", max_hops=1) is None
    assert families[0] == (socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    assert (socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 1) in options


def _traceroute_program(fake_program, **kwargs):
    """A fake of the binary `_hop_count_traceroute` runs on this platform."""
    return fake_program("tracert" if _hops._IS_WINDOWS else "traceroute", **kwargs)


def test_traceroute_parser_reads_hop_number(fake_program):
    """Only the hop number and destination address are read, never the prose."""
    output = (
        "\nTracing route to 8.8.8.8 over a maximum of 30 hops\n\n"
        "  1     5 ms     2 ms     4 ms  192.0.2.1 \n"
        "  2     *        *        *     Request timed out.\n"
        "  3     9 ms     7 ms    11 ms  8.8.8.8 \n\n"
        "Trace complete.\n"
    )
    _traceroute_program(fake_program, stdout=output)
    assert _hops._hop_count_traceroute("8.8.8.8", 30, 1.0) == 3


def test_traceroute_parser_localised_prose_is_ignored(fake_program):
    """A non-English traceroute must still parse -- no prose matching."""
    output = (
        "  1     5 ms     2 ms     4 ms  192.0.2.1 \n"
        "  2     *        *        *     Expiration du delai d'attente.\n"
        "  3     9 ms     7 ms    11 ms  1.1.1.1 \n"
    )
    _traceroute_program(fake_program, stdout=output)
    assert _hops._hop_count_traceroute("1.1.1.1", 30, 1.0) == 3


def test_traceroute_parser_missing_binary_is_none(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert _hops._hop_count_traceroute("8.8.8.8", 30, 1.0) is None


def test_traceroute_parser_no_match_is_none(fake_program):
    _traceroute_program(
        fake_program,
        stdout="  1     5 ms  192.0.2.1 \n  2     *  Request timed out.\n",
    )
    assert _hops._hop_count_traceroute("8.8.8.8", 30, 1.0) is None


def test_traceroute_failing_exit_status_is_none(fake_program):
    """A non-zero exit means the output is not a trace, even if it names the target.

    A usage message that echoes the destination would otherwise be read as a
    hop line.
    """
    _traceroute_program(
        fake_program,
        stdout="  3     9 ms     7 ms    11 ms  8.8.8.8 \n",
        returncode=2,
    )
    assert _hops._hop_count_traceroute("8.8.8.8", 30, 1.0) is None


# --------------------------------------------------------------------------- #
# ICMP reply classification                                                    #
# --------------------------------------------------------------------------- #


def test_is_icmp_reply_skips_variable_ip_header():
    # IHL=5 -> 20-byte header, then ICMP type 11 (time exceeded).
    assert _hops._is_icmp_reply(b"\x45" + b"\x00" * 19 + b"\x0b")
    # IHL=6 -> 24-byte header; the type must be read at the right offset.
    assert _hops._is_icmp_reply(b"\x46" + b"\x00" * 23 + b"\x00")
    # Type 8 is an echo *request*, not a reply to our probe.
    assert not _hops._is_icmp_reply(b"\x45" + b"\x00" * 19 + b"\x08")


def test_is_icmp_reply_rejects_short_packets():
    assert not _hops._is_icmp_reply(b"")
    assert not _hops._is_icmp_reply(b"\x45" * 5)


# --------------------------------------------------------------------------- #
# MTU: get_pmtu (lookup) and discover_mtu (measurement)                       #
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not _pmtu._IS_LINUX, reason="IP_MTU is a Linux socket option")
@pytest.mark.parametrize("dst", ["127.0.0.1", "::1"])
def test_get_pmtu_answers_on_linux(dst):
    """The positive assertion, on the one platform that must answer it.

    This replaces a test that asserted ``None`` after deleting an attribute
    ``socket`` never had -- so it passed against dead code and pinned the bug.
    CPython exports neither ``IP_MTU`` nor ``IP_MTU_DISCOVER`` on *any*
    platform, Linux included, so the old ``getattr`` guard returned before the
    socket was created and every line after it was unreachable. Loopback has a
    known, offline, deterministic MTU, which is exactly what the vacuous
    "None or a positive int" assertions could never catch.
    """
    if dst == "::1":
        try:
            socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
        except OSError:  # pragma: no cover - env dependent
            pytest.skip("no IPv6 on this host")
    result = netimps.get_pmtu(dst)
    assert isinstance(result, int) and result >= 1280


@pytest.mark.skipif(
    _pmtu._IS_LINUX, reason="Linux is the platform that does have IP_MTU"
)
def test_get_pmtu_is_none_where_the_option_does_not_exist():
    """Windows and BSD expose no cached path MTU; None is the right answer.

    Documented at length in get_pmtu's docstring: Windows' MIB_IPFORWARDROW
    reads 0 for dwForwardMtu and MIB_IPFORWARD_ROW2 dropped the field, so
    probing with discover_mtu is the only route to a *path* MTU there.
    """
    assert netimps.get_pmtu("127.0.0.1") is None


def test_get_pmtu_rejects_an_out_of_range_port():
    with pytest.raises(ValueError, match="out of range"):
        netimps.get_pmtu("127.0.0.1", 65536)


def test_get_pmtu_accepts_interface_object():
    """Must not raise -- IPv4Interface used to stringify with its /prefix intact."""
    result = netimps.get_pmtu(IPv4Interface("127.0.0.1/8"))
    assert result is None or (isinstance(result, int) and result > 0)


def test_get_pmtu_sends_nothing(monkeypatch):
    """It is a lookup, not a measurement -- no packets leave."""
    calls = []
    real = _pmtu._socket.socket

    class NoSend(real):
        def send(self, *a, **k):  # pragma: no cover - must not run
            calls.append("send")
            raise AssertionError("get_pmtu must not send")

        def sendto(self, *a, **k):  # pragma: no cover - must not run
            calls.append("sendto")
            raise AssertionError("get_pmtu must not send")

    monkeypatch.setattr(_pmtu._socket, "socket", NoSend)
    netimps.get_pmtu("127.0.0.1")
    assert not calls


def test_discover_mtu_probe_false_delegates_to_get_pmtu(monkeypatch):
    """probe=False is exactly get_pmtu -- and must not ping."""
    monkeypatch.setattr(_mtu, "get_pmtu", lambda dst, port=80, ipv6=None: 1400)
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
        _mtu, "get_pmtu", lambda *a, **k: pytest.fail("default must probe")
    )
    monkeypatch.setattr(_mtu, "ping", _fake_ping(1500))
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
    monkeypatch.setattr(_mtu, "ping", _fake_ping(1500), raising=False)
    monkeypatch.setattr(_mtu, "ping", _fake_ping(1500))
    assert netimps.discover_mtu("10.0.0.1") == 1500


def test_discover_mtu_accepts_interface_object(monkeypatch):
    """The .ip is what gets pinged -- not "10.0.0.1/24" as a whole string."""
    seen = []

    def fake_ping(dst, size=None, dont_fragment=False, timeout=None, src=None):
        seen.append(dst)
        return netimps.PingResult((size or 0) + 28 <= 1500, dst)

    monkeypatch.setattr(_mtu, "ping", fake_ping, raising=False)
    monkeypatch.setattr(_mtu, "ping", fake_ping)
    assert netimps.discover_mtu(IPv4Interface("10.0.0.1/24")) == 1500
    assert all(d == "10.0.0.1" for d in seen)


@pytest.mark.parametrize("limit", [576, 1280, 1420, 1500, 9000])
def test_discover_mtu_across_common_values(monkeypatch, limit):
    monkeypatch.setattr(_mtu, "ping", _fake_ping(limit))
    assert netimps.discover_mtu("10.0.0.1") == limit


def test_discover_mtu_returns_none_when_nothing_answers(monkeypatch):
    """A firewalled host must not read as a tiny MTU."""
    monkeypatch.setattr(_mtu, "ping", lambda *a, **k: netimps.PingResult(False, "x"))
    assert netimps.discover_mtu("10.0.0.1") is None


def test_discover_mtu_short_circuits_at_the_ceiling(monkeypatch):
    """If the ceiling survives there is nothing to search for."""
    calls = []

    def ping(dst, size=None, **kwargs):
        calls.append(size)
        return netimps.PingResult(True, dst)

    monkeypatch.setattr(_mtu, "ping", ping)
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

    monkeypatch.setattr(_mtu, "ping", ping)
    result = netimps.discover_mtu("10.0.0.1")
    assert result == 1500
    # The reported MTU is the largest surviving payload plus the 28-byte
    # IPv4 + ICMP overhead.
    assert max(survived) + 28 == result


# --------------------------------------------------------------------------- #
# ping methods / MTU by protocol                                               #
# --------------------------------------------------------------------------- #


def test_discover_mtu_rejects_unknown_method():
    with pytest.raises(ValueError, match="must be 'icmp', 'udp' or 'tcp'"):
        netimps.discover_mtu("10.0.0.1", method="sctp")


def test_discover_mtu_tcp_uses_mss_plus_headers(monkeypatch):
    """TCP cannot probe, so it derives the MTU from the negotiated MSS."""
    monkeypatch.setattr(_mtu, "_tcp_mss", lambda *a, **k: (1400, socket.AF_INET))
    assert netimps.discover_mtu("8.8.8.8", port=443, method="tcp") == 1440
    # IPv6 adds 20 more header bytes.
    monkeypatch.setattr(_mtu, "_tcp_mss", lambda *a, **k: (1400, socket.AF_INET6))
    assert netimps.discover_mtu("2001:db8::1", port=443, method="tcp") == 1460


def test_discover_mtu_tcp_none_when_mss_unavailable(monkeypatch):
    monkeypatch.setattr(_mtu, "_tcp_mss", lambda *a, **k: None)
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
        assert result.rtt is not None and result.rtt >= 0
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
    from netimps._ping._probe import _tcp_ping

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
    assert result.rtt is not None


def test_ping_tcp_probe_family_follows_the_destination(monkeypatch, v6_loopback):
    """Pinned deterministically: the probe socket is AF_INET6 for a v6 dst."""
    families = []
    real_socket = socket.socket

    def recording(family, *args, **kwargs):
        families.append(family)
        return real_socket(family, *args, **kwargs)

    monkeypatch.setattr(netimps._ping._probe._socket, "socket", recording)
    netimps.ping("::1", method="tcp", port=v6_loopback, timeout=2.0)
    assert families == [socket.AF_INET6]


def test_ping_tcp_honours_ipv6_flag_for_a_hostname(monkeypatch):
    """`ipv6=` is not ICMP-only -- it selects the tcp/udp probe family too."""
    seen = {}

    def fake_getaddrinfo(host, port, family=0, type=0, *args, **kwargs):
        seen["family"] = family
        raise OSError("resolution blocked in tests")

    monkeypatch.setattr(netimps._ping._probe._socket, "getaddrinfo", fake_getaddrinfo)
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
    from netimps._ping._probe import _udp_ping

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

    monkeypatch.setattr(
        netimps._ping._probe._socket, "socket", lambda *a, **k: Recording()
    )
    ok, rtt, note = _udp_ping("127.0.0.1", 9, 1.0)
    assert order == ["connect", "send", "recv"]
    assert ok and note == "port-unreachable"


def test_udp_ping_treats_connection_reset_as_liveness_too(monkeypatch):
    """Windows spells the same ICMP error ECONNRESET; both must count."""
    from netimps._ping._probe import _udp_ping

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

    monkeypatch.setattr(
        netimps._ping._probe._socket, "socket", lambda *a, **k: Resetting()
    )
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
    assert result.rtt is not None


def test_discover_mtu_forwards_ping_kwargs(monkeypatch):
    """ipv6/tries and friends reach ping rather than being dropped."""
    seen = []

    def ping(dst, size=None, dont_fragment=False, timeout=None, src=None, **kw):
        seen.append(kw)
        return netimps.PingResult((size or 0) + 28 <= 1500, dst)

    monkeypatch.setattr(_mtu, "ping", ping)
    netimps.discover_mtu("10.0.0.1", tries=3, ipv6=False)
    assert seen and all(k == {"tries": 3, "ipv6": False} for k in seen)


@pytest.mark.parametrize("owned", ["size", "dont_fragment"])
def test_discover_mtu_rejects_search_owned_kwargs(owned):
    """Overriding what the search varies would silently break the result."""
    with pytest.raises(TypeError, match="unexpected keyword"):
        netimps.discover_mtu("10.0.0.1", **{owned: 1})


# --------------------------------------------------------------------------- #
# bind: SO_REUSEADDR means something else on Windows                           #
# --------------------------------------------------------------------------- #


def test_bind_default_does_not_allow_a_port_takeover():
    """A second process must not be able to steal a bound listener.

    Reproduced on Windows 11: ``SO_REUSEADDR`` there lets *any* process bind
    an ``addr:port`` another socket is already listening on, and the later
    binder can win subsequent connections. ``bind()`` set it unconditionally,
    so its own listeners were takeable while a plain stdlib bind was refused.
    On POSIX the second bind must fail too, for the ordinary reason.
    """
    server = netimps.bind("127.0.0.1", 0, kind=socket.SOCK_STREAM, listen=5)
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


def _recording_socket(monkeypatch):
    """Patch the module's socket factory and return the options it is given."""
    applied = []
    real = socket.socket

    class Recording(real):
        def setsockopt(self, level, option, value):
            applied.append((level, option, value))
            return real.setsockopt(self, level, option, value)

    monkeypatch.setattr(_bind._socket, "socket", Recording)
    return applied


def test_bind_sets_exclusiveaddruse_on_windows_and_nothing_for_posix_udp(monkeypatch):
    """One flag, three outcomes -- because one option would not be one meaning.

    Updated twice over, and the old version of this test encoded both defects it
    is now pinned against:

    - **Windows** gets `SO_EXCLUSIVEADDRUSE` for *either* value of
      `reuse_address`. It used to be set only for `True`, which left
      `reuse_address=False` setting nothing -- and nothing is the unsafe state
      there, since a more specific `SO_REUSEADDR` bind can then take a wildcard
      holder's traffic.
    - **POSIX datagram** sockets get **neither**. `TIME_WAIT` is a TCP concept, so
      `SO_REUSEADDR` on a UDP socket only permits duplicate bindings of live
      sockets -- measured on Linux, the second binder received the datagram.
    """
    applied = _recording_socket(monkeypatch)
    netimps.bind("127.0.0.1", 0).close()

    exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
    if exclusive is not None:
        assert (socket.SOL_SOCKET, exclusive, 1) in applied
        assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) not in applied
    else:
        # POSIX, and the default kind is SOCK_DGRAM: neither option belongs.
        assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) not in applied


def test_bind_sets_exclusiveaddruse_on_windows_whatever_reuse_address_says(monkeypatch):
    """The inverted-safety case: `False` must not mean "set nothing" on Windows."""
    exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
    if exclusive is None:
        pytest.skip("SO_EXCLUSIVEADDRUSE is Windows-only")
    for reuse in (False, True):
        applied = _recording_socket(monkeypatch)
        netimps.bind("127.0.0.1", 0, reuse_address=reuse).close()
        assert (
            socket.SOL_SOCKET,
            exclusive,
            1,
        ) in applied, "reuse_address=%r left the socket non-exclusive" % (reuse,)


def test_bind_still_sets_reuseaddr_for_a_posix_stream_socket(monkeypatch):
    """The legitimate use survives: restarting a TCP server over `TIME_WAIT`."""
    if getattr(socket, "SO_EXCLUSIVEADDRUSE", None) is not None:
        pytest.skip("Windows takes the exclusive path instead")
    applied = _recording_socket(monkeypatch)
    netimps.bind("127.0.0.1", 0, kind=socket.SOCK_STREAM).close()
    assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) in applied


def test_bind_takeover_is_an_explicit_opt_in(monkeypatch):
    """The literal SO_REUSEADDR is still reachable, under a name that says so."""
    applied = _recording_socket(monkeypatch)
    netimps.bind("127.0.0.1", 0, allow_address_takeover=True).close()
    assert (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) in applied


# --------------------------------------------------------------------------- #
# tcp_check: port validation, timeout floor, one overall deadline              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("port", [65536, -1, 131072])
def test_tcp_check_rejects_an_out_of_range_port(port):
    """The socket layer masks to 16 bits and answers about a *different* port.

    Measured: with a listener on 50287, ``tcp_check(host, 50287 + 65536)``
    returned True. ``base + offset`` in a loop is the obvious way to generate
    that, and nothing indicated the question had changed.
    """
    with pytest.raises(ValueError, match="out of range"):
        tcp_check("127.0.0.1", port)


def test_tcp_check_rejects_a_non_integer_port():
    with pytest.raises(TypeError, match="must be an int"):
        tcp_check("127.0.0.1", "80")


def test_tcp_check_with_zero_timeout_still_sees_an_open_port(listening_port):
    """``settimeout(0)`` is non-blocking, not "fail fast".

    It made ``connect`` raise BlockingIOError immediately, which read as
    "closed" -- so ``scan_ports(timeout=0)`` reported every port on every host
    closed. The value is floored, matching ping's existing round-up.
    """
    assert tcp_check("127.0.0.1", listening_port, timeout=0) is True


def test_tcp_check_resolves_once_and_shares_one_deadline(monkeypatch):
    """A name with N addresses must not cost N x timeout.

    ``socket.create_connection`` applies the timeout *per resolved address*,
    inside its own loop, after an unbounded getaddrinfo -- so the documented
    per-call bound was false by a factor of N, and with it wait_for_port's
    "cannot overrun by more than one attempt".
    """
    import time

    addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 9)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.2", 9)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.3", 9)),
    ]
    lookups = []

    def fake_getaddrinfo(host, port, *a, **k):
        lookups.append(host)
        return addresses

    timeouts = []

    class Blocking:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, timeout):
            timeouts.append(timeout)
            self._timeout = timeout

        def connect(self, address):
            time.sleep(self._timeout)
            raise socket.timeout("blocked for the whole budget")

        def close(self):
            pass

    monkeypatch.setattr(_connect._socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(_connect._socket, "socket", Blocking)

    start = time.monotonic()
    assert tcp_check("many.example", 9, timeout=0.3) is False
    elapsed = time.monotonic() - start

    assert lookups == ["many.example"], "resolve once, not once per address"
    assert elapsed < 0.3 * len(addresses), "the budget is shared, not per address"
    assert sum(timeouts) <= 0.3 + 0.01


def test_wait_for_port_rejects_an_out_of_range_port():
    with pytest.raises(ValueError, match="out of range"):
        wait_for_port("127.0.0.1", 70000, deadline=0.1)


# --------------------------------------------------------------------------- #
# get_source_ip: the family comes from the resolver, not from a substring test #
# --------------------------------------------------------------------------- #


def test_get_source_ip_family_follows_the_resolver(monkeypatch):
    """``":" in dst`` is not an address-family test -- no hostname has a colon.

    Every hostname was therefore probed as IPv4, so a v6-only name answered
    None and a dual-stack one returned the v4 source even when traffic would
    leave over v6.
    """
    families = []
    real = socket.socket

    def recording(family, kind, *a, **k):
        families.append(family)
        return real(family, kind, *a, **k)

    monkeypatch.setattr(_connect._socket, "socket", recording)
    monkeypatch.setattr(
        netimps._ping._probe._socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET6, socket.SOCK_DGRAM, 17, "", ("::1", 80, 0, 0))
        ],
    )
    source = get_source_ip("v6only.example")
    assert families == [socket.AF_INET6]
    assert source is None or source.version == 6


def test_get_source_ip_honours_an_explicit_ipv6_flag(monkeypatch):
    seen = {}

    def fake_getaddrinfo(host, port, family=0, kind=0, *a, **k):
        seen["family"] = family
        return []

    monkeypatch.setattr(netimps._ping._probe._socket, "getaddrinfo", fake_getaddrinfo)
    assert get_source_ip("host.invalid", ipv6=True) is None
    assert seen["family"] == socket.AF_INET6
    assert get_source_ip("host.invalid", ipv6=False) is None
    assert seen["family"] == socket.AF_INET
    assert get_source_ip("host.invalid") is None
    assert seen["family"] == socket.AF_UNSPEC


def test_get_source_ip_for_v6_loopback(v6_loopback):
    source = get_source_ip("::1")
    assert source is not None and source.is_loopback and source.version == 6


# --------------------------------------------------------------------------- #
# Zone-qualified IPv6 in the membership lookups                                #
# --------------------------------------------------------------------------- #


def _link_local_v6():
    for iface in netimps.get_interfaces():
        for entry in iface.ips:
            if entry.version == 6 and entry.ip.is_link_local:
                return iface, entry.ip
    return None, None


def test_zone_qualified_address_is_still_local():
    """``fe80::1%15`` is the form every OS tool emits, and it matched nothing.

    ``getsockname()``, ``getaddrinfo``, ``ip addr`` and ``ipconfig`` all report
    the zone, and it is *required* to use a link-local address at all -- yet
    adding it made the library deny the address was local.
    """
    iface, address = _link_local_v6()
    if address is None:  # pragma: no cover - env dependent
        pytest.skip("no link-local IPv6 address on this host")

    bare = str(address)
    assert netimps.is_local_address(bare) is True
    assert netimps.get_interface(bare) is not None

    forms = ["%s%%%s" % (bare, iface.name)]
    if iface.index:
        forms.append("%s%%%d" % (bare, iface.index))
    for form in forms:
        assert netimps.is_local_address(form) is True, form
        assert netimps.get_interface(form) is not None, form
        assert list(netimps.iter_interfaces(form)), form


def test_zone_that_names_another_adapter_does_not_match():
    """A zone is extra information, so a contradicting one is a real miss."""
    _iface, address = _link_local_v6()
    if address is None:  # pragma: no cover - env dependent
        pytest.skip("no link-local IPv6 address on this host")
    impossible = "%s%%%d" % (address, 999999)
    assert netimps.is_local_address(impossible) is False
    assert netimps.get_interface(impossible) is None


def test_zone_is_stripped_for_the_synthetic_interface():
    """strict=False builds a host route, which must not carry the zone."""
    built = netimps.get_interface("fe80::dead:beef%1", strict=False)
    assert built is not None and built.name == "<unknown>"
    assert [str(entry) for entry in built.ips] == ["fe80::dead:beef/128"]


# --------------------------------------------------------------------------- #
# Next-hop parsers, offline                                                    #
# --------------------------------------------------------------------------- #


#: Captured from WSL2 (`cat /proc/net/ipv6_route`). No header line, big-endian
#: hex nibbles, and note the `::/0` entry on `lo` with RTF_UP clear and
#: RTF_REJECT set -- an unreachable route that a flag-blind longest-prefix
#: match would report as "every global v6 destination is on-link via lo".
_IPV6_ROUTE_TABLE = (
    "fe800000000000000000000000000000 40 "
    "00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
    "00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n"
    "00000000000000000000000000000001 80 "
    "00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000000 00000003 00000000 80200001 lo\n"
    "20010db8000000000000000000000000 20 "
    "00000000000000000000000000000000 00 "
    "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
)


def test_ipv6_route_table_finds_the_gateway():
    hop = _nexthop._parse_ipv6_route_table(_IPV6_ROUTE_TABLE, "2001:db8::5")
    assert hop is not None
    assert hop[0] == "fe80::1"


def test_ipv6_route_table_reports_on_link_for_loopback():
    hop = _nexthop._parse_ipv6_route_table(_IPV6_ROUTE_TABLE, "::1")
    assert hop is not None and hop[0] is None


def test_ipv6_route_table_skips_the_reject_default():
    """RTF_UP clear + RTF_REJECT set is "unreachable", not "on-link via lo"."""
    assert (
        _nexthop._parse_ipv6_route_table(_IPV6_ROUTE_TABLE, "2606:4700::1111") is None
    )


def test_ipv6_route_table_prefers_the_longest_prefix():
    hop = _nexthop._parse_ipv6_route_table(_IPV6_ROUTE_TABLE, "fe80::abcd")
    assert hop is not None and hop[0] is None  # on-link via the /64, not the /32


#: macOS `route -n get 1.1.1.1`, numeric so nothing depends on reverse DNS.
_ROUTE_GET_VIA_GATEWAY = (
    "   route to: 1.1.1.1\n"
    "destination: default\n"
    "       mask: default\n"
    "    gateway: 192.168.64.1\n"
    "  interface: en0\n"
    "      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n"
)

#: The on-link shape: BSD writes `link#N` where there is no router.
_ROUTE_GET_ON_LINK = (
    "   route to: 192.168.64.5\n"
    "destination: 192.168.64.0\n"
    "       mask: 255.255.255.0\n"
    "    gateway: link#4\n"
    "  interface: en0\n"
)


def test_route_get_output_reads_the_gateway():
    hop = _nexthop._parse_route_get_output(_ROUTE_GET_VIA_GATEWAY)
    assert hop is not None and hop[0] == "192.168.64.1"


def test_route_get_output_treats_a_link_gateway_as_on_link():
    """`link#4` is not an address; it is BSD for "no router involved"."""
    hop = _nexthop._parse_route_get_output(_ROUTE_GET_ON_LINK)
    assert hop is not None and hop[0] is None


def test_route_get_output_unmatched_is_unknown():
    assert (
        _nexthop._parse_route_get_output("route: writing to routing socket\n") is None
    )


def test_route_reports_unknown_rather_than_on_link(monkeypatch):
    """Where the lookup cannot be made, on_link is None -- not a cheerful True.

    This is the macOS case: no /proc, so nothing was read, and `gateway is
    None` then claimed "no router involved" for a destination two subnets
    away.
    """
    monkeypatch.setattr(_route, "_windows_next_hop", lambda dst, ipv6=False: None)
    monkeypatch.setattr(_route, "_posix_next_hop", lambda dst, ipv6=False: None)
    monkeypatch.setattr(_route, "_bsd_next_hop", lambda dst, ipv6=False: None)
    route = get_route("1.1.1.1")
    assert route.gateway is None
    assert route.on_link is None
    assert not route.on_link  # the safe branch still reads the same


def test_route_v6_destination_reaches_the_next_hop_lookup(monkeypatch):
    """The `version == 4` gate made every v6 destination read as on-link."""
    seen = {}

    def record(dst, ipv6=False):
        seen["dst"], seen["ipv6"] = dst, ipv6
        return ("fe80::1", 7)

    for name in ("_windows_next_hop", "_posix_next_hop", "_bsd_next_hop"):
        monkeypatch.setattr(_route, name, record)
    route = get_route("2001:db8::5")
    assert seen == {"dst": "2001:db8::5", "ipv6": True}
    assert route.on_link is False
    assert route.interface_index == 7


# --------------------------------------------------------------------------- #
# discover_mtu: the don't-fragment bit is what makes the search mean anything  #
# --------------------------------------------------------------------------- #


def test_dont_fragment_is_settable_for_both_families():
    """If this fails the UDP search cannot answer, and must say so."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:  # pragma: no cover - env dependent
            continue
        try:
            assert _pmtu._set_dont_fragment(sock, family) is True
        finally:
            sock.close()


def test_discover_mtu_udp_returns_none_when_df_cannot_be_set(monkeypatch):
    """Without DF every probe survives and the search returns its ceiling.

    Measured: no DF option was set on any platform, so oversized datagrams
    were fragmented locally, reassembled by the peer and answered -- making
    `discover_mtu(method="udp")` report `high` (9000 by default) everywhere.
    """
    monkeypatch.setattr(_mtu, "_set_dont_fragment", lambda sock, family: False)
    assert netimps.discover_mtu("127.0.0.1", port=9, method="udp", timeout=0.1) is None


def test_discover_mtu_udp_probe_family_follows_the_destination(monkeypatch):
    """AF_INET was hardcoded, so every v6 destination failed inside sendto."""
    families = []

    class Recording:
        def __init__(self, family, kind, *a, **k):
            families.append(family)

        def settimeout(self, timeout):
            pass

        def setsockopt(self, level, option, value):
            pass

        def sendto(self, payload, address):
            raise OSError("not sent in tests")

        def recvfrom(self, size):  # pragma: no cover - never reached
            raise AssertionError

        def close(self):
            pass

    monkeypatch.setattr(_mtu._socket, "socket", Recording)
    assert netimps.discover_mtu("::1", port=9, method="udp", timeout=0.1) is None
    assert families and set(families) == {socket.AF_INET6}


def test_discover_mtu_icmp_declines_when_df_is_unavailable(monkeypatch):
    """BSD's ping6 has no DF flag, so the honest answer is None, not a number."""
    monkeypatch.setattr(_mtu, "supports_dont_fragment", lambda *a, **k: False)
    monkeypatch.setattr(
        netimps, "ping", lambda *a, **k: pytest.fail("must not probe without DF")
    )
    assert netimps.discover_mtu("10.0.0.1") is None


def test_is_icmp_reply_reads_a_v6_packet_without_an_ip_header():
    """Raw IPv6 sockets deliver the ICMPv6 message, not the whole datagram.

    And the type numbers are not the v4 ones: 3 is "time exceeded" in v6 and
    "destination unreachable" in v4, so the tables cannot be shared.
    """
    assert _hops._is_icmp_reply(b"\x03\x00\x00\x00", ipv6=True)  # time exceeded
    assert _hops._is_icmp_reply(b"\x01\x00", ipv6=True)  # unreachable
    assert _hops._is_icmp_reply(b"\x81\x00", ipv6=True)  # echo reply
    assert not _hops._is_icmp_reply(b"\x80\x00", ipv6=True)  # echo *request*
    assert not _hops._is_icmp_reply(b"", ipv6=True)


def test_bsd_next_hop_answers_loopback_without_spawning(fake_program):
    """Loopback is on-link by definition -- no process, no parsing risk.

    The `route -n get` output shape for a *host* route is the one thing here
    that could not be measured locally, and loopback is the case that must be
    right on every platform, so it never reaches the parser.
    """
    fake = fake_program("route")
    assert _nexthop._bsd_next_hop("127.0.0.1") == (None, 0)
    assert _nexthop._bsd_next_hop("::1", ipv6=True) == (None, 0)
    assert fake.calls == []


def test_program_helpers_never_read_the_callers_stdin(fake_program):
    """A library that inherits stdin can swallow its caller's input."""
    route = fake_program("route", stdout="  interface: en0\n")
    traceroute = _traceroute_program(fake_program)
    _nexthop._bsd_next_hop("1.1.1.1")
    _hops._hop_count_traceroute("1.1.1.1", 5, 1.0)
    assert route.stdin_lengths == [0]
    assert traceroute.stdin_lengths == [0]


# --------------------------------------------------------------------------- #
# SO_REUSEADDR passed the stdlib way through options=                         #
# --------------------------------------------------------------------------- #


def test_so_reuseaddr_in_options_is_honoured_not_refused():
    """A regression against the previous release.

    Once `bind()` started setting `SO_EXCLUSIVEADDRUSE` for *both* values of
    `reuse_address`, Windows began refusing an `SO_REUSEADDR` that arrived
    through `options=` -- the two cannot coexist on one socket, and it reports
    only `WSAEINVAL`, naming neither. Measured on Windows 11 ARM64: this exact
    call raised "[WinError 10022] An invalid argument was supplied" with no
    hint, and it had worked on 0.3.1.

    An explicit nonzero `SO_REUSEADDR` in `options=` is the caller asking for
    takeover in so many words, so it is now treated as
    `allow_address_takeover=True` rather than fought with.
    """
    sock = netimps.bind(
        "127.0.0.1",
        0,
        reuse_address=False,
        options=[(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)],
    )
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
    finally:
        sock.close()


def test_a_zero_valued_reuseaddr_in_options_is_not_a_takeover_request():
    """`SO_REUSEADDR, 0` is explicitly asking for it to be *off*.

    Reading any mention of the option as "takeover wanted" would turn an
    explicit opt-*out* into an opt-in, so the value is what counts.
    """
    sock = netimps.bind(
        "127.0.0.1",
        0,
        options=[(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)],
    )
    try:
        assert not sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # The safe default must still be in force on Windows.
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE)
    finally:
        sock.close()


def test_other_options_still_reach_the_socket_unchanged():
    """The scan must not have become a filter: `options=` is still applied."""
    sock = netimps.bind(
        "127.0.0.1",
        0,
        options=[netimps.SocketOption(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)],
    )
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST)
    finally:
        sock.close()


@pytest.mark.skipif(
    not hasattr(socket, "SO_EXCLUSIVEADDRUSE"), reason="WSAEINVAL is Windows-only"
)
def test_bind_error_hint_explains_wsaeinval():
    """A bare 10022 is undiagnosable, which is why it gets a sentence.

    The hint has to name the conflict and the spelling that avoids it; the
    error itself says only "invalid argument".
    """
    exc = OSError(22, "An invalid argument was supplied")
    exc.winerror = 10022
    hint = netimps.bind_error_hint(exc)
    assert hint is not None
    assert "allow_address_takeover" in hint
    assert "SO_EXCLUSIVEADDRUSE" in hint


# --------------------------------------------------------------------------- #
# discover_mtu: one resolution, the probed family, the interface ceiling       #
# --------------------------------------------------------------------------- #


#: The functions themselves, for the tests of them: the fixture below replaces
#: the module attributes for every test in this file.
_real_icmp_packet_limit = _mtu._icmp_packet_limit
_real_udp_packet_limit = _mtu._udp_packet_limit


@pytest.fixture(autouse=True)
def no_path_cap(monkeypatch):
    """Make the outgoing-interface ceiling unknown, so a fake ping decides.

    The limits of the probe tools are taken out as well: on macOS the real
    ``sysctl`` answers 8192 and would cap every faked path above it.
    """
    monkeypatch.setattr(_mtu, "_outgoing_path", lambda *a, **k: (None, False))
    monkeypatch.setattr(_mtu, "_icmp_packet_limit", lambda overhead: 65535)
    monkeypatch.setattr(_mtu, "_udp_packet_limit", lambda overhead: 65535)


def _dual_stack_name(monkeypatch, v4="127.0.0.1", v6="::1"):
    """``dual.test`` resolves to both families, IPv6 first, honouring the family."""
    real = socket.getaddrinfo

    def getaddrinfo(host, port, family=0, *args, **kwargs):
        if host != "dual.test":
            return real(host, port, family, *args, **kwargs)
        kind = args[0] if args else socket.SOCK_STREAM
        found = []
        if family in (0, socket.AF_INET6):
            found.append((socket.AF_INET6, kind, 0, "", (v6, port or 0, 0, 0)))
        if family in (0, socket.AF_INET):
            found.append((socket.AF_INET, kind, 0, "", (v4, port or 0)))
        return found

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def test_discover_mtu_overhead_follows_the_family_that_was_probed(
    monkeypatch, no_path_cap
):
    """A name resolving to IPv6 first, probed as IPv4, takes IPv4's 28 bytes.

    The overhead came from a second resolution that ignored ``ipv6=``: the
    wire packet was 1480 bytes and the answer was 1500.
    """
    _dual_stack_name(monkeypatch)
    seen = []

    def ping(dst, size=None, dont_fragment=False, timeout=None, src=None, **kw):
        seen.append((dst, size))
        return netimps.PingResult((size or 0) + 28 <= 1480, dst)

    monkeypatch.setattr(_mtu, "ping", ping)
    assert netimps.discover_mtu("dual.test", ipv6=False, high=1500) == 1480
    assert {dst for dst, _ in seen} == {"127.0.0.1"}


def test_discover_mtu_resolves_the_name_once(monkeypatch, no_path_cap):
    _dual_stack_name(monkeypatch)
    lookups = []
    inner = socket.getaddrinfo

    def counting(host, *args, **kwargs):
        lookups.append(host)
        return inner(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", counting)
    monkeypatch.setattr(
        _mtu,
        "ping",
        lambda dst, size=None, **kw: netimps.PingResult((size or 0) + 28 <= 1500, dst),
    )
    assert netimps.discover_mtu("dual.test", ipv6=False) == 1500
    assert lookups.count("dual.test") == 1


def test_get_tcp_mss_takes_ipv6_and_refuses_the_other_family(monkeypatch):
    """With an IPv4-only listener, ``ipv6=True`` is an unreachable destination."""
    _dual_stack_name(monkeypatch)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    try:
        port = server.getsockname()[1]
        assert netimps.get_tcp_mss("dual.test", port, timeout=2.0, ipv6=True) is None
        assert (
            netimps.discover_mtu(
                "dual.test", method="tcp", port=port, timeout=2.0, ipv6=True
            )
            is None
        )
        mss = netimps.get_tcp_mss("dual.test", port, timeout=2.0, ipv6=False)
        assert mss is None or mss > 0
        if mss is not None:
            assert (
                netimps.discover_mtu(
                    "dual.test", method="tcp", port=port, timeout=2.0, ipv6=False
                )
                == mss + 40
            )
    finally:
        server.close()


def test_discover_mtu_tcp_overhead_is_the_connected_familys(monkeypatch):
    monkeypatch.setattr(_mtu, "_tcp_mss", lambda *a, **k: (1400, socket.AF_INET6))
    assert netimps.discover_mtu("dual.test", method="tcp", port=443) == 1460
    monkeypatch.setattr(_mtu, "_tcp_mss", lambda *a, **k: (1400, socket.AF_INET))
    assert netimps.discover_mtu("dual.test", method="tcp", port=443) == 1440


def _wire_ping(limit, seen):
    def ping(dst, size=None, dont_fragment=False, timeout=None, src=None, **kw):
        seen.append((size or 0) + 28)
        return netimps.PingResult((size or 0) + 28 <= limit, dst)

    return ping


def test_discover_mtu_continues_past_high_up_to_the_interface_mtu(monkeypatch):
    """A path that carries ``high`` is searched on, up to the first hop's MTU.

    Returning ``high`` after one probe reported 9000 for a 65535 loopback.
    """
    seen = []
    monkeypatch.setattr(_mtu, "_outgoing_path", lambda *a, **k: (20000, False))
    monkeypatch.setattr(_mtu, "ping", _wire_ping(12345, seen))
    assert netimps.discover_mtu("10.0.0.1", high=9000) == 12345
    assert max(seen) <= 20000


def test_discover_mtu_probes_nothing_above_the_interface_mtu(monkeypatch):
    seen = []
    monkeypatch.setattr(_mtu, "_outgoing_path", lambda *a, **k: (1500, False))
    monkeypatch.setattr(_mtu, "ping", _wire_ping(10**6, seen))
    assert netimps.discover_mtu("10.0.0.1", high=9000) == 1500
    assert max(seen) == 1500


def test_discover_mtu_answers_the_interface_mtu_when_the_path_carries_it(monkeypatch):
    seen = []
    monkeypatch.setattr(_mtu, "_outgoing_path", lambda *a, **k: (65535, False))
    monkeypatch.setattr(_mtu, "_icmp_packet_limit", lambda overhead: 10**6)
    monkeypatch.setattr(_mtu, "ping", _wire_ping(10**6, seen))
    assert netimps.discover_mtu("10.0.0.1", high=20000) == 65535


def test_discover_mtu_with_an_unknown_first_hop_is_at_least_high(
    monkeypatch, no_path_cap
):
    """No interface MTU to cap at: ``high`` is the documented floor of the answer."""
    seen = []
    monkeypatch.setattr(_mtu, "ping", _wire_ping(10**6, seen))
    assert netimps.discover_mtu("10.0.0.1", high=1500) == 1500
    assert max(seen) == 1500


def test_a_local_destination_bounded_by_the_probe_tool_is_the_interface_mtu(
    monkeypatch,
):
    """The platform ping cannot send past its limit, and a local path has no
    other hop to narrow it: the loopback MTU is the answer."""
    seen = []
    monkeypatch.setattr(_mtu, "_outgoing_path", lambda *a, **k: (65536, True))
    monkeypatch.setattr(_mtu, "_icmp_packet_limit", lambda overhead: 65535)
    monkeypatch.setattr(_mtu, "ping", _wire_ping(65535, seen))
    assert netimps.discover_mtu("127.0.0.1") == 65536
    assert max(seen) == 65535


def test_a_remote_path_bounded_by_the_probe_tool_falls_back_to_udp(monkeypatch):
    """macOS ping stops at ``net.inet.raw.maxdgram``; UDP has no such limit."""
    seen = []
    monkeypatch.setattr(_mtu, "_outgoing_path", lambda *a, **k: (16384, False))
    monkeypatch.setattr(_mtu, "_icmp_packet_limit", lambda overhead: 8192)
    monkeypatch.setattr(_mtu, "ping", _wire_ping(10**6, seen))
    asked = []

    def udp(*args, **kwargs):
        asked.append(args)
        return 9000

    monkeypatch.setattr(_mtu, "_discover_mtu_udp", udp)
    assert netimps.discover_mtu("10.0.0.1") == 9000
    assert max(seen) == 8192 and asked
    monkeypatch.setattr(_mtu, "_discover_mtu_udp", lambda *a, **k: None)
    assert netimps.discover_mtu("10.0.0.1") == 8192


def test_the_bsd_probe_limit_text_is_parsed():
    assert _mtu._parse_sysctl_int("8192\n") == 8192
    assert _mtu._parse_sysctl_int("net.inet.raw.maxdgram: 9216\n") == 9216
    assert _mtu._parse_sysctl_int("") is None
    assert _mtu._parse_sysctl_int("nope") is None


def test_the_bsd_icmp_limit_is_the_sysctl_value(fake_program, monkeypatch):
    fake = fake_program("sysctl", stdout="8192\n")
    monkeypatch.setattr(_mtu, "_IS_WINDOWS", False)
    monkeypatch.setattr(_mtu, "_IS_LINUX", False)
    assert _real_icmp_packet_limit(28) == 8192
    assert fake.argv[-2:] == ["-n", "net.inet.raw.maxdgram"]


def test_the_bsd_icmp_limit_without_sysctl_is_the_ip_maximum(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("sysctl")

    monkeypatch.setattr(_mtu, "_IS_WINDOWS", False)
    monkeypatch.setattr(_mtu, "_IS_LINUX", False)
    monkeypatch.setattr(_mtu._proc, "run", missing)
    assert _real_icmp_packet_limit(28) == 65535


def test_the_bsd_udp_limit_is_the_sysctl_payload_plus_the_headers(
    fake_program, monkeypatch
):
    fake = fake_program("sysctl", stdout="9216\n")
    monkeypatch.setattr(_mtu, "_IS_WINDOWS", False)
    monkeypatch.setattr(_mtu, "_IS_LINUX", False)
    assert _real_udp_packet_limit(28) == 9244
    assert fake.argv[-2:] == ["-n", "net.inet.udp.maxdgram"]


def test_a_local_udp_search_that_ends_at_the_socket_limit_is_the_loopback_mtu(
    monkeypatch,
):
    """Measured on macOS 15: the udp method stopped at 9244 on a 16384 loopback."""
    seen = []

    def udp_search(survives, low, high, first_hop, limit, local):
        seen.append((first_hop, limit, local))
        return _real_search_mtu(
            lambda size: size <= limit, low, high, first_hop, limit, local
        )

    _real_search_mtu = _mtu._search_mtu
    monkeypatch.setattr(_mtu, "_outgoing_path", lambda *a, **k: (16384, True))
    monkeypatch.setattr(_mtu, "_udp_packet_limit", lambda overhead: 9244)
    monkeypatch.setattr(_mtu, "_set_dont_fragment", lambda sock, family: True)
    monkeypatch.setattr(_mtu, "_search_mtu", udp_search)
    assert netimps.discover_mtu("127.0.0.1", method="udp", port=9) == 16384
    assert seen == [(16384, 9244, True)]


def test_a_literal_of_the_other_family_has_no_target():
    """macOS answers an IPv4 literal asked for as IPv6 with its mapped form."""
    from netimps import _ping

    assert _ping._probe_targets("127.0.0.1", 9, True, socket.SOCK_STREAM) == []
    assert _ping._probe_targets("::1", 9, False, socket.SOCK_STREAM) == []
    assert _ping._probe_targets("127.0.0.1", 9, False, socket.SOCK_STREAM)


def test_the_windows_ping_limit_is_65500_payload_bytes(monkeypatch):
    monkeypatch.setattr(_mtu, "_IS_WINDOWS", True)
    assert _real_icmp_packet_limit(28) == 65528
    assert _real_icmp_packet_limit(48) == 65535


# --------------------------------------------------------------------------- #
# bind options, port sharing, free ports, destinations, waiting, local hosts   #
# --------------------------------------------------------------------------- #


def test_bind_honours_a_one_shot_options_iterable():
    """``options`` is an ``Iterable``: a generator is read once, not twice.

    A scan for an address-takeover request used up the generator, so the
    option was never applied.
    """
    wanted = ((socket.SOL_SOCKET, socket.SO_BROADCAST, 1) for _ in range(1))
    sock = netimps.bind("127.0.0.1", 0, options=wanted)
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) != 0
    finally:
        sock.close()


def test_bind_reuse_port_shares_a_udp_port_on_every_platform():
    """Windows has no ``SO_REUSEPORT``; the flag takes its address-sharing path."""
    first = netimps.bind("127.0.0.1", 0, reuse_port=True)
    try:
        port = first.getsockname()[1]
        second = netimps.bind("127.0.0.1", port, reuse_port=True)
        second.close()
    finally:
        first.close()


def test_bind_without_reuse_port_stays_exclusive():
    first = netimps.bind("127.0.0.1", 0)
    try:
        port = first.getsockname()[1]
        with pytest.raises(netimps.AddressInUseError):
            netimps.bind("127.0.0.1", port)
    finally:
        first.close()


@pytest.mark.skipif(
    not hasattr(socket, "SO_EXCLUSIVEADDRUSE"), reason="the Windows stream rule"
)
def test_bind_reuse_port_leaves_a_stream_socket_exclusive_on_windows():
    first = netimps.bind("127.0.0.1", 0, kind=socket.SOCK_STREAM, reuse_port=True)
    try:
        port = first.getsockname()[1]
        with pytest.raises(netimps.AddressInUseError):
            netimps.bind("127.0.0.1", port, kind=socket.SOCK_STREAM, reuse_port=True)
    finally:
        first.close()


def _has_ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", 0))
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _has_ipv6_loopback(), reason="no IPv6 loopback")
def test_get_free_port_follows_the_address_family_like_bind():
    port = get_free_port("::1")
    assert 0 < port < 65536
    assert get_free_port(netimps.IPv6Address("::1")) > 0
    assert get_free_port(family=socket.AF_INET6, src="::1") > 0


def test_get_free_port_accepts_a_host_and_an_interface():
    assert get_free_port(netimps.IPv4Address("127.0.0.1")) > 0
    assert get_free_port(IPv4Interface("127.0.0.1/8")) > 0
    assert get_free_port(netimps.Host("127.0.0.1")) > 0


@pytest.mark.parametrize(
    "call",
    [
        lambda: netimps.tcp_check(None, 80),
        lambda: netimps.wait_for_port(None, 80, deadline=0.1),
        lambda: netimps.get_source_ip(None),
        lambda: netimps.get_route(None),
        lambda: netimps.ping(None),
        lambda: netimps.resolve(None),
        lambda: netimps.scan_ports(None, [80]),
        lambda: netimps.count_hops(None),
        lambda: netimps.discover_mtu(None),
        lambda: netimps.get_pmtu(None),
        lambda: netimps.get_tcp_mss(None, 80),
        lambda: netimps.bind(None),
        lambda: netimps.tcp_check(5, 80),
        lambda: netimps.tcp_check(b"127.0.0.1", 80),
    ],
)
def test_a_destination_that_is_not_a_host_raises_type_error(monkeypatch, call):
    """``None`` was read as the host named ``"None"``: a plausible answer, wrong."""
    asked = []

    def refuse(host, *args, **kwargs):
        asked.append(host)
        raise socket.gaierror("not asked in this test")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    with pytest.raises(TypeError):
        call()
    assert asked == []


def test_host_still_takes_none():
    assert str(netimps.Host(None)) == ""


class _Clock:
    """A clock that only moves when ``sleep`` is called."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def test_wait_for_port_never_waits_less_than_its_interval(monkeypatch):
    """The back-off cap was a flat second, shortening an interval above it."""
    clock = _Clock()
    monkeypatch.setattr(_connect, "_time", clock)
    monkeypatch.setattr(_connect, "tcp_check", lambda *a, **k: False)
    assert netimps.wait_for_port("h", 80, deadline=20, interval=5.0) is False
    assert clock.sleeps[:3] == [5.0, 5.0, 5.0]
    assert min(clock.sleeps[:-1]) >= 5.0


def test_wait_for_port_still_backs_off_to_one_second(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(_connect, "_time", clock)
    monkeypatch.setattr(_connect, "tcp_check", lambda *a, **k: False)
    netimps.wait_for_port("h", 80, deadline=10, interval=0.1)
    assert clock.sleeps[0] == 0.1
    assert max(clock.sleeps) == 1.0


@pytest.mark.parametrize(
    "spelling", ["127.1", "2130706433", "0x7f.0.0.1", "0177.0.0.1"]
)
def test_is_local_host_reads_the_spellings_the_socket_layer_sends_to_loopback(
    spelling,
):
    """``inet_aton`` text is a literal: each of these is ``127.0.0.1``."""
    assert netimps.is_local_host(spelling) is True


def test_is_local_host_does_not_widen_to_a_remote_short_form():
    assert netimps.is_local_host("8.8") is False
    assert netimps.is_local_host("example.com") is False


def test_one_timeout_floor_serves_a_scan_and_a_check():
    """The scan floored to 1 ms and ``tcp_check`` again to 50 ms."""
    from netimps import _scan

    assert _scan._checked_timeout(0) == 0
    assert _connect._connect_timeout(_scan._checked_timeout(0)) == _connect._MIN_TIMEOUT
    with pytest.raises(ValueError):
        _scan._checked_timeout(-1)
