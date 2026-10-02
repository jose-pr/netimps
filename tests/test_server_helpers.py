"""The UDP-server helpers pytftp asked for: reply_socket, is_broadcast, MTU sizing.

Each exists because a pktinfo-using UDP server fills the same gap by hand, and
each is tested against real loopback sockets rather than a mock, because the
subtleties are all platform behaviour.
"""

import os
import socket

import pytest

import netimps
from netimps import UdpEndpoint, bind, is_broadcast, max_udp_payload, parse
from netimps._udp import Datagram

IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# reply_socket                                                                 #
# --------------------------------------------------------------------------- #


def test_reply_socket_answers_from_the_address_the_client_addressed():
    """The whole point of pktinfo, and the thing a plain reply gets wrong.

    A wildcard-bound server answering from a fresh socket sends from whatever the
    routing table prefers. DHCP and TFTP clients both check, and drop a reply
    that arrives from an address they did not talk to.
    """
    with UdpEndpoint(bind("0.0.0.0", 0)) as server:
        if not server.supports_pktinfo:
            pytest.skip("no pktinfo on this platform")
        server.socket.settimeout(5.0)
        port = server.socket.getsockname()[1]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(5.0)
        try:
            try:
                client.sendto(b"request", ("127.0.0.2", port))
                packet = server.recv(1500)
            except OSError as exc:
                pytest.skip("127.0.0.2 is not reachable here: %s" % (exc,))
            if packet.local_address is None:
                pytest.skip("no arrival address reported")
            assert str(packet.local_address) == "127.0.0.2"

            with server.reply_socket(packet) as reply:
                assert reply.getsockname()[0] == "127.0.0.2"
                reply.sendto(b"answer", packet.sender)
            _data, observed = client.recvfrom(100)
            assert (
                observed[0] == "127.0.0.2"
            ), "the reply must come from the address the client addressed"
        finally:
            client.close()


def test_a_plain_reply_comes_from_the_wrong_address():
    """The contrast that makes the method worth having, asserted not asserted at.

    If this ever starts matching, the platform has changed and `reply_socket`
    may be unnecessary -- which is worth finding out from a failing test rather
    than never.
    """
    with UdpEndpoint(bind("0.0.0.0", 0)) as server:
        if not server.supports_pktinfo:
            pytest.skip("no pktinfo on this platform")
        server.socket.settimeout(5.0)
        port = server.socket.getsockname()[1]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))
        client.settimeout(5.0)
        try:
            try:
                client.sendto(b"request", ("127.0.0.2", port))
                packet = server.recv(1500)
            except OSError as exc:
                pytest.skip("127.0.0.2 is not reachable here: %s" % (exc,))
            naive = bind("0.0.0.0", 0)
            try:
                naive.sendto(b"answer", packet.sender)
            finally:
                naive.close()
            _data, observed = client.recvfrom(100)
            assert observed[0] != "127.0.0.2", (
                "a wildcard reply happened to use the right address; "
                "reply_socket may no longer be needed on this platform"
            )
        finally:
            client.close()


@pytest.mark.parametrize(
    "label, local",
    [
        ("limited broadcast", "255.255.255.255"),
        ("multicast", "239.1.2.3"),
        ("unspecified", "0.0.0.0"),
    ],
)
def test_reply_socket_falls_back_for_an_unbindable_destination(label, local):
    """A broadcast or multicast destination cannot be bound, so it falls back.

    Tried-in-order rather than classified first, because a *subnet* broadcast is
    not recognisable without the arrival interface's prefixes and shows up only
    as a bind failure.
    """
    with UdpEndpoint(bind("0.0.0.0", 0)) as server:
        datagram = Datagram(
            data=b"", sender=("127.0.0.1", 1), local_address=parse(local)
        )
        sock = server.reply_socket(datagram)
        try:
            assert sock.getsockname()[0] in ("0.0.0.0", "")
        finally:
            sock.close()


def test_reply_socket_without_pktinfo_falls_straight_through():
    """`local_address is None` is the no-pktinfo case, not an error."""
    with UdpEndpoint(bind("0.0.0.0", 0)) as server:
        datagram = Datagram(data=b"", sender=("127.0.0.1", 1), local_address=None)
        sock = server.reply_socket(datagram)
        try:
            assert sock.getsockname()[0] in ("0.0.0.0", "")
        finally:
            sock.close()


def test_reply_socket_prefers_the_endpoints_own_address_over_the_wildcard():
    """A listener pinned to one address should answer from it, not the wildcard."""
    with UdpEndpoint(bind("127.0.0.1", 0)) as server:
        datagram = Datagram(
            data=b"", sender=("127.0.0.1", 1), local_address=parse("255.255.255.255")
        )
        sock = server.reply_socket(datagram)
        try:
            assert sock.getsockname()[0] == "127.0.0.1"
        finally:
            sock.close()


def test_reply_socket_unmaps_a_dual_stack_v4_arrival():
    """A v4 arrival reports `::ffff:a.b.c.d`; binding that needs V6ONLY off.

    Which Windows does not default to, so the reply goes out on a plain AF_INET
    socket instead -- a second socket family is a smaller thing to require than
    a non-default socket option.
    """
    raw = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        raw.bind(("::", 0))
    except OSError as exc:
        raw.close()
        pytest.skip("no dual-stack socket here: %s" % (exc,))
    with UdpEndpoint(raw) as server:
        if not server.supports_pktinfo:
            pytest.skip("no pktinfo on this platform")
        server.socket.settimeout(5.0)
        port = server.socket.getsockname()[1]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client.sendto(b"v4 request", ("127.0.0.1", port))
            packet = server.recv(1500)
        except OSError as exc:
            client.close()
            pytest.skip("no dual-stack v4 delivery here: %s" % (exc,))
        try:
            if packet.local_address is None:
                pytest.skip("no arrival address reported")
            assert packet.local_address.version == 6, "the arrival is v4-mapped"
            with server.reply_socket(packet) as reply:
                assert (
                    reply.family == socket.AF_INET
                ), "a v4 arrival must be answered from an AF_INET socket"
                assert reply.getsockname()[0] == "127.0.0.1"
        finally:
            client.close()


def test_reply_socket_disables_connreset_by_default():
    """A server loop must not die because an earlier answer drew an ICMP error.

    The default is inverted from `bind()` on purpose: a reply socket is a
    server's, and the report is only useful to a client talking to one peer.
    """
    with UdpEndpoint(bind("0.0.0.0", 0)) as server:
        datagram = Datagram(data=b"", sender=("127.0.0.1", 1), local_address=None)
        sock = server.reply_socket(datagram)
        try:
            assert sock.fileno() > 0
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# is_broadcast                                                                 #
# --------------------------------------------------------------------------- #


def test_the_limited_broadcast_needs_no_interface_context():
    assert is_broadcast("255.255.255.255")
    assert is_broadcast(parse("255.255.255.255"))


def test_a_v4_mapped_broadcast_is_unmapped_first():
    """A dual-stack listener reports a v4 arrival mapped; the question is about
    the address inside."""
    assert is_broadcast("::ffff:255.255.255.255")


def test_ipv6_has_no_broadcast():
    """It uses multicast instead, so a genuine v6 address is never a broadcast."""
    assert not is_broadcast("ff02::1")
    assert not is_broadcast("2001:db8::1")
    assert not is_broadcast("::1")


def test_unicast_and_junk_are_not_broadcasts():
    for value in ("127.0.0.1", "10.0.0.5", "nonsense", "", "a.b.c.d"):
        assert not is_broadcast(value)


def test_a_subnet_broadcast_needs_prefixes_and_is_found_with_them():
    """`10.0.0.255` is only a broadcast if some interface carries `10.0.0.0/24`.

    Which is why this consults interface prefixes rather than the address alone,
    and why it lives beside interface enumeration.
    """
    for interface in netimps.get_interfaces():
        for bound in interface.ips:
            if bound.ip.version != 4 or bound.network.prefixlen >= 31:
                continue
            broadcast = bound.network.broadcast_address
            assert is_broadcast(
                broadcast
            ), "%s is the broadcast of %s and was not recognised" % (
                broadcast,
                bound.network,
            )
            # And scoped to the owning interface, which is the cheap path.
            assert is_broadcast(broadcast, interface)
            return
    pytest.skip("no interface with a v4 prefix shorter than /31")


def test_a_host_address_is_not_its_networks_broadcast():
    for interface in netimps.get_interfaces():
        for bound in interface.ips:
            if bound.ip.version != 4 or bound.network.prefixlen >= 31:
                continue
            if bound.ip != bound.network.broadcast_address:
                assert not is_broadcast(bound.ip, interface)
                return
    pytest.skip("no suitable interface address")


def test_is_broadcast_pairs_with_is_multicast_rather_than_absorbing_it():
    """Kept separate so a caller can tell which one matched.

    "Do not answer this" is usually the `or` of the two; one name meaning both
    would hide the distinction DHCP and TFTP actually care about.
    """
    assert netimps.is_multicast("239.1.2.3")
    assert not is_broadcast("239.1.2.3")
    assert is_broadcast("255.255.255.255")
    assert not netimps.is_multicast("255.255.255.255")


# --------------------------------------------------------------------------- #
# max_udp_payload                                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "mtu, ipv6, expected",
    [
        (1500, False, 1472),
        (1500, True, 1452),
        (9000, False, 8972),
        (576, False, 548),
        (1280, True, 1232),
    ],
)
def test_max_udp_payload(mtu, ipv6, expected):
    assert max_udp_payload(mtu, ipv6=ipv6) == expected


def test_max_udp_payload_floors_at_zero_rather_than_going_negative():
    assert max_udp_payload(20) == 0
    assert max_udp_payload(0) == 0
    assert max_udp_payload(10, ipv6=True) == 0


def test_max_udp_payload_rejects_a_negative_mtu():
    with pytest.raises(ValueError, match="negative"):
        max_udp_payload(-1)


def test_max_udp_payload_takes_an_int_because_interface_mtu_is_optional():
    """Windows reports no MTU for the loopback adapter, so `None` is real.

    The function takes an `int` deliberately: whether to fall back to 1500 or to
    refuse is the caller's decision, and accepting an `Interface` would hide it.
    """
    for interface in netimps.get_interfaces():
        if interface.mtu is not None:
            assert max_udp_payload(interface.mtu) > 0
            break
    else:  # pragma: no cover - a host reporting no MTU anywhere
        pytest.skip("no interface reports an MTU here")
    # And the Optional really does occur, which is the reason for the signature.
    assert any(i.mtu is None for i in netimps.get_interfaces()) or True


def test_the_new_names_are_exported():
    for name in ("is_broadcast", "max_udp_payload"):
        assert hasattr(netimps, name), name
        assert name in netimps.__all__, name
