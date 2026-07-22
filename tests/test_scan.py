"""Tests for port/host scanning and multicast helpers.

Everything is pointed at loopback -- these never scan anything external.
"""

import socket

import pytest

import netimps
from netimps import PORT_RANGES, is_multicast, scan_hosts, scan_ports


@pytest.fixture
def listener():
    """A real listening socket on loopback, yielding its port."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    yield server.getsockname()[1]
    server.close()


# --------------------------------------------------------------------------- #
# scan_ports                                                                   #
# --------------------------------------------------------------------------- #


def test_scan_ports_finds_a_listener(listener):
    closed = netimps.get_free_port()
    result = scan_ports("127.0.0.1", [listener, closed], timeout=1.0)
    assert listener in result
    assert closed not in result


def test_scan_ports_returns_sorted(listener):
    extra = socket.socket()
    extra.bind(("127.0.0.1", 0))
    extra.listen(1)
    try:
        second = extra.getsockname()[1]
        result = scan_ports("127.0.0.1", [second, listener], timeout=1.0)
        assert result == sorted(result)
        assert {listener, second} <= set(result)
    finally:
        extra.close()


def test_scan_ports_accepts_named_range():
    result = scan_ports("127.0.0.1", "common", timeout=0.2)
    assert isinstance(result, list)
    assert all(p in PORT_RANGES["common"] for p in result)


def test_scan_ports_accepts_single_int_and_range(listener):
    assert scan_ports("127.0.0.1", listener, timeout=1.0) == [listener]
    result = scan_ports("127.0.0.1", range(listener, listener + 2), timeout=1.0)
    assert listener in result


def test_scan_ports_unknown_named_range():
    with pytest.raises(ValueError, match="unknown port range or scheme"):
        scan_ports("127.0.0.1", "nonsense")


def test_ports_accept_scheme_names():
    """A scheme name resolves through get_default_port."""
    from netimps._scan import _resolve_ports

    assert _resolve_ports("https") == (443,)
    assert _resolve_ports("ssh") == (22,)
    assert _resolve_ports("socks5") == (1080,)  # absent from /etc/services
    assert _resolve_ports("8080") == (8080,)  # numeric string
    assert _resolve_ports(["ssh", 8080, "443"]) == (22, 8080, 443)


def test_range_name_wins_over_scheme_name():
    """A caller writing 'common' means the set, not some scheme."""
    from netimps._scan import _resolve_ports

    assert len(_resolve_ports("common")) > 1
    assert _resolve_ports("common") == PORT_RANGES["common"]


def test_unresolvable_port_in_list_raises():
    from netimps._scan import _resolve_ports

    with pytest.raises(ValueError, match="cannot resolve"):
        _resolve_ports([80, "definitely-not-a-scheme"])


def test_scan_hosts_accepts_scheme_name(listener):
    """port= takes a scheme name, same as scan_ports."""
    result = scan_hosts("127.0.0.1/32", port=listener, timeout=1.0)
    assert result  # sanity: the numeric form still works
    # A scheme name must not raise, whatever it finds.
    assert isinstance(scan_hosts("127.0.0.1/32", port="https", timeout=0.3), list)


def test_scan_ports_empty_is_empty():
    assert scan_ports("127.0.0.1", []) == []


def test_scan_ports_closed_host_is_empty():
    """An unreachable host yields nothing rather than raising."""
    assert scan_ports("127.0.0.1", [netimps.get_free_port()], timeout=0.3) == []


def test_port_ranges_are_sane():
    assert PORT_RANGES["well-known"][0] == 1
    assert PORT_RANGES["well-known"][-1] == 1023
    assert len(PORT_RANGES["all"]) == 65535
    assert 443 in PORT_RANGES["common"] and 22 in PORT_RANGES["common"]
    # 'common' must be a genuine shortcut, not a near-full sweep.
    assert len(PORT_RANGES["common"]) < 100


# --------------------------------------------------------------------------- #
# scan_hosts                                                                   #
# --------------------------------------------------------------------------- #


def test_scan_hosts_finds_loopback(listener):
    result = scan_hosts("127.0.0.1/32", port=listener, timeout=1.0)
    assert result
    address, ports = result[0]
    assert str(address) == "127.0.0.1"
    assert ports == [listener]


def test_scan_hosts_skips_hosts_with_nothing_open():
    assert scan_hosts("127.0.0.1/32", port=netimps.get_free_port(), timeout=0.3) == []


@pytest.mark.parametrize("network", ["10.0.0.0/8", "0.0.0.0/0", "172.16.0.0/12"])
def test_scan_hosts_refuses_huge_networks(network):
    """A /8 sweep is 16M hosts -- a mistake, not an intention."""
    with pytest.raises(ValueError, match="scan a /16 or smaller"):
        scan_hosts(network, port=80)


def test_scan_hosts_refuses_huge_ipv6():
    with pytest.raises(ValueError, match="too large"):
        scan_hosts("2001:db8::/64", port=80)


def test_scan_hosts_rejects_port_and_ports_together():
    with pytest.raises(ValueError, match="either port or ports"):
        scan_hosts("127.0.0.1/32", port=80, ports=[80, 443])


def test_scan_hosts_results_are_sorted(listener):
    result = scan_hosts("127.0.0.0/30", port=listener, timeout=0.5)
    addresses = [address for address, _ in result]
    assert addresses == sorted(addresses)


# --------------------------------------------------------------------------- #
# multicast                                                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "address, expected",
    [
        ("224.0.0.251", True),  # mDNS
        ("239.1.2.3", True),
        ("ff02::fb", True),
        ("10.0.0.1", False),
        ("127.0.0.1", False),
        ("garbage", False),
        ("", False),
        (None, False),
    ],
)
def test_is_multicast(address, expected):
    assert is_multicast(address) is expected


def test_multicast_socket_round_trip():
    """A datagram sent to the group comes back on the joined socket.

    Skipped rather than failed when nothing arrives: a host firewall dropping
    inbound multicast is common (verified on a firewalld host, where plain
    stdlib multicast fails identically), and that is an environment fact, not
    a defect in the socket setup. The configuration itself is asserted by the
    surrounding tests, which do not need traffic to flow.
    """
    group, port = "239.7.7.42", 55571
    source = netimps.get_source_ip()
    if source is None:  # pragma: no cover - host without a route
        pytest.skip("no routable source address")

    receiver = netimps.multicast_socket(group, port, interface=str(source))
    try:
        receiver.settimeout(5.0)
        sender = netimps.multicast_socket(interface=str(source), bind=False)
        try:
            try:
                sender.sendto(b"payload", (group, port))
                data, _ = receiver.recvfrom(1024)
            except (socket.timeout, OSError):  # pragma: no cover - env dependent
                # Either the send had no multicast route (macOS CI runners
                # report ENETUNREACH here) or the datagram was filtered.
                pytest.skip("multicast is unavailable on this host")
            assert data == b"payload"
        finally:
            sender.close()
    finally:
        receiver.close()


def test_multicast_socket_rejects_non_group():
    for bad in ("10.0.0.1", "127.0.0.1", "garbage"):
        with pytest.raises(ValueError, match="not a multicast group"):
            netimps.multicast_socket(bad, 0)


def test_multicast_socket_unknown_interface_name():
    with pytest.raises(ValueError, match="no interface named"):
        netimps.multicast_socket("239.7.7.43", 0, interface="no-such-nic")


def test_multicast_socket_unknown_mac():
    with pytest.raises(ValueError, match="no interface with MAC"):
        netimps.multicast_socket(
            "239.7.7.44", 0, interface=netimps.MACAddress("02:00:00:00:00:99")
        )


def test_multicast_send_only_socket_can_send():
    """bind=False is the send-side configuration: usable, but claims no port.

    Asserting on getsockname() would be wrong -- an unbound socket has no name
    on Windows and raises there -- so this checks the property that matters:
    it can transmit. A host with no multicast route (macOS CI runners) raises
    ENETUNREACH on the send, which is an environment fact rather than a defect
    in the socket setup.
    """
    sock = netimps.multicast_socket(bind=False)
    try:
        try:
            assert sock.sendto(b"x", ("239.7.7.46", 55572)) == 1
        except OSError:  # pragma: no cover - env dependent
            pytest.skip("no multicast route on this host")
    finally:
        sock.close()


def test_join_group_rejects_non_group():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(ValueError, match="not a multicast group"):
            netimps.join_group(sock, "10.0.0.1")
        with pytest.raises(ValueError, match="not a multicast group"):
            netimps.leave_group(sock, "10.0.0.1")
    finally:
        sock.close()


def test_multicast_socket_closes_on_failure(monkeypatch):
    """A failed join must not leak the socket it was configuring."""
    closed = []
    real_socket = socket.socket

    class Tracking(real_socket):
        def close(self):
            closed.append(True)
            super().close()

    monkeypatch.setattr(netimps._multicast._socket, "socket", Tracking)
    with pytest.raises(ValueError):
        netimps.multicast_socket("239.7.7.45", 0, interface="no-such-nic")
    assert closed, "socket was not closed after the failure"
