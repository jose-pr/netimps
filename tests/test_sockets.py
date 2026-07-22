"""Tests for the socket / route / MTU helpers.

Anything that would touch the real network is either pointed at loopback or
mocked. The few live calls (source-address selection, route lookup) are
assertions about *shape*, never about this host's actual addresses.
"""

import socket

import pytest

import netimps
from netimps import (
    Route,
    free_port,
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
# free_port                                                                    #
# --------------------------------------------------------------------------- #


def test_free_port_is_bindable():
    port = free_port()
    assert 1 <= port <= 65535
    # The whole point: the port must actually be usable afterwards.
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
    finally:
        sock.close()


def test_free_port_varies():
    """Consecutive calls should not hand out the same port."""
    ports = {free_port() for _ in range(5)}
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
    port = free_port()  # nothing listening there
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

    port = free_port()
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
# get_route / Route                                                            #
# --------------------------------------------------------------------------- #


def test_route_to_loopback_is_on_link():
    route = get_route("127.0.0.1")
    assert route.on_link
    assert route.gateway is None


def test_route_shape():
    route = get_route("8.8.8.8")
    assert isinstance(route, Route)
    assert route.dest is not None
    if route.source is not None:
        assert isinstance(route.source, (netimps.IPv4Address, netimps.IPv6Address))
    assert isinstance(route.interface_index, int)


def test_route_never_raises_for_bad_destination():
    route = get_route("no-such-host-xyz.invalid")
    assert isinstance(route, Route)


def test_route_on_link_is_derived_from_gateway():
    assert Route(dest="x", gateway=None).on_link is True
    assert Route(dest="x", gateway=netimps.parse("10.0.0.1")).on_link is False


def test_route_equality_and_repr():
    a = Route(dest=netimps.parse("8.8.8.8"), source=netimps.parse("10.0.0.5"))
    b = Route(dest=netimps.parse("8.8.8.8"), source=netimps.parse("10.0.0.5"))
    assert a == b
    assert a != Route(dest=netimps.parse("1.1.1.1"))
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
# path_mtu                                                                     #
# --------------------------------------------------------------------------- #


def test_path_mtu_returns_none_without_ip_mtu(monkeypatch):
    """Windows has no IP_MTU; the documented answer is None, not a guess."""
    monkeypatch.delattr(_sockets._socket, "IP_MTU", raising=False)
    assert netimps.path_mtu("127.0.0.1") is None


def test_path_mtu_shape():
    result = netimps.path_mtu("127.0.0.1")
    assert result is None or (isinstance(result, int) and result > 0)
