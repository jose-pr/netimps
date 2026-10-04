"""What a UDP server used to work out for itself around ``UDPEndpoint.recv``.

Each test pins the difference from the hand-rolled version: a fake one-address
``Interface`` built per send to dodge an enumeration, ``WSAEMSGSIZE`` handled
around every receive, a ``local_address`` that was really the destination and a
unicast/broadcast/multicast triage written beside it, and a receive loop that
survives an error.
"""

import asyncio
import ipaddress
import socket
import time

import pytest

import netimps
from netimps import (
    Datagram,
    Interface,
    UDPEndpoint,
    bind,
    interface_enumerations,
    is_unicast,
)


def _closed_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


# --------------------------------------------------------------------------- #
# 1c -- send(src=<address>) does not enumerate                                 #
# --------------------------------------------------------------------------- #


def test_an_address_src_is_used_as_given_and_enumerates_nothing():
    """The caller built a one-address ``Interface`` per send to avoid this.

    Resolving an address to its adapter walked every interface on each send:
    1.29 ms against 0.04 ms for an ``Interface``.
    """
    with (
        UDPEndpoint(bind("127.0.0.1", 0)) as sender,
        UDPEndpoint(bind("127.0.0.1", 0)) as receiver,
    ):
        if not sender.has_src_pinning:
            pytest.skip("this host cannot pin a source address")
        before = interface_enumerations()
        sender.send(
            b"hello", "127.0.0.1", receiver.socket.getsockname()[1], src="127.0.0.1"
        )
        sender.send(
            b"again",
            "127.0.0.1",
            receiver.socket.getsockname()[1],
            src=ipaddress.IPv4Address("127.0.0.1"),
        )
        assert interface_enumerations() == before
        receiver.socket.settimeout(2)
        first = receiver.recv(resolve_interface=False)
        assert first.data == b"hello"
        assert first.sender[0] == "127.0.0.1"


def test_a_name_src_still_resolves_to_an_adapter():
    """Only an address is taken as given; a name is looked up as before."""
    loopback = next((i for i in netimps.get_interfaces() if i.is_loopback), None)
    if loopback is None or not loopback.ipv4:
        pytest.skip("no loopback adapter with an IPv4 address")
    with (
        UDPEndpoint(bind("127.0.0.1", 0)) as sender,
        UDPEndpoint(bind("127.0.0.1", 0)) as receiver,
    ):
        if not sender.has_src_pinning:
            pytest.skip("this host cannot pin a source address")
        before = interface_enumerations()
        sender.send(
            b"x", "127.0.0.1", receiver.socket.getsockname()[1], src=loopback.name
        )
        assert interface_enumerations() > before


# --------------------------------------------------------------------------- #
# 1d -- an oversized datagram is reported, not raised                          #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("pktinfo", [True, False])
def test_a_datagram_larger_than_bufsize_is_returned_truncated(pktinfo):
    """Windows raises ``WSAEMSGSIZE`` (10040) from a bare ``recvfrom`` here.

    A server wrapped every receive in a handler for it; ``recv`` must return
    the leading part with ``truncated=True`` on the pktinfo path and on the
    path that has none, which is where a hand-rolled ``recvfrom`` lives.
    """
    receiver = UDPEndpoint(bind("127.0.0.1", 0), pktinfo=pktinfo)
    sender = bind("127.0.0.1", 0)
    try:
        receiver.socket.settimeout(2)
        sender.sendto(b"z" * 1200, receiver.socket.getsockname())
        datagram = receiver.recv(576)
        assert len(datagram.data) == 576
        assert datagram.truncated is True
        sender.sendto(b"short", receiver.socket.getsockname())
        assert receiver.recv(576).truncated is False
    finally:
        receiver.close()
        sender.close()


# --------------------------------------------------------------------------- #
# 1e -- destination, is_unicast                                                #
# --------------------------------------------------------------------------- #


def test_the_destination_field_replaces_local_address():
    """The old name hid that this is where the datagram was sent *to*."""
    assert "destination" in Datagram._fields
    assert "local_address" not in Datagram._fields
    assert not hasattr(Datagram(b"", ("127.0.0.1", 1)), "local_address")


@pytest.mark.parametrize(
    "address, expected",
    [
        ("10.0.0.5", True),
        ("127.0.0.1", True),
        ("::1", True),
        ("2001:db8::1", True),
        ("fe80::1%1", True),
        ("255.255.255.255", False),
        ("224.0.0.251", False),
        ("239.1.2.3", False),
        ("ff02::fb", False),
        ("0.0.0.0", False),
        ("::", False),
        ("::ffff:224.0.0.1", False),
        ("::ffff:255.255.255.255", False),
        ("::ffff:10.0.0.5", True),
        ("not an address", False),
    ],
)
def test_is_unicast_is_not_broadcast_multicast_or_the_wildcard(address, expected):
    """A server wrote ``not (is_broadcast(a) or is_multicast(a) or wildcard)``."""
    assert is_unicast(address) is expected


def test_is_unicast_judges_a_subnet_broadcast_by_the_given_interface():
    iface = Interface(
        name="probe0", index=999, ips=[ipaddress.IPv4Interface("10.9.8.5/24")]
    )
    before = interface_enumerations()
    assert is_unicast("10.9.8.255", iface) is False
    assert is_unicast("10.9.8.5", iface) is True
    assert is_unicast("10.9.8.6", iface) is True
    assert interface_enumerations() == before, "the given interface must not enumerate"


def test_datagram_is_unicast_follows_its_destination_and_interface():
    iface = Interface(
        name="probe0", index=999, ips=[ipaddress.IPv4Interface("10.9.8.5/24")]
    )

    def make(destination, interface=None):
        return Datagram(
            b"",
            ("10.9.8.9", 68),
            destination=(
                None if destination is None else ipaddress.ip_address(destination)
            ),
            interface=interface,
        )

    assert make("10.9.8.5", iface).is_unicast is True
    assert make("10.9.8.255", iface).is_unicast is False
    assert make("255.255.255.255").is_unicast is False
    assert make("224.0.0.251").is_unicast is False
    assert make(None).is_unicast is None, "unknown, not a guess"


def test_a_received_datagram_reports_its_destination_as_unicast():
    with UDPEndpoint(bind("127.0.0.1", 0)) as receiver:
        if not receiver.has_pktinfo:
            pytest.skip("this host cannot report the arrival address")
        sender = bind("127.0.0.1", 0)
        try:
            receiver.socket.settimeout(2)
            sender.sendto(b"x", receiver.socket.getsockname())
            datagram = receiver.recv()
        finally:
            sender.close()
        assert str(datagram.destination) == "127.0.0.1"
        assert datagram.is_unicast is True


# --------------------------------------------------------------------------- #
# 2h -- datagrams(on_error=)                                                   #
# --------------------------------------------------------------------------- #


def _endpoint_with_a_pending_receive_error():
    """A connected UDP socket that has an ICMP error queued, and the peer to follow.

    Connected, because POSIX reports an asynchronous ICMP error only there;
    ``connreset=True`` because ``bind()`` turns the Windows report off.
    Returns ``(endpoint, peer)``; the peer holds the port that refused, and a
    datagram from it is the one that must arrive *after* the error.
    """
    port = _closed_udp_port()
    sock = bind("127.0.0.1", 0, connreset=True)
    sock.connect(("127.0.0.1", port))
    sock.send(b"ping")
    time.sleep(0.3)
    peer = bind("127.0.0.1", port)
    peer.sendto(b"after", sock.getsockname())
    return UDPEndpoint(sock), peer


def _run(coroutine):
    return asyncio.run(asyncio.wait_for(coroutine, 5))


def test_datagrams_stops_at_the_first_error_by_default():
    """The loop that swallows errors is how a dead server looks healthy."""
    endpoint, peer = _endpoint_with_a_pending_receive_error()

    async def collect():
        got = []
        async with endpoint:
            async for packet in endpoint.datagrams():
                got.append(packet.data)
        return got

    try:
        with pytest.raises(OSError):
            _run(collect())
    finally:
        peer.close()


def test_on_error_returning_true_yields_the_datagram_after_a_failed_receive():
    """pydhcp and pytftp each wrote an ``arecv`` loop with a try/except around it."""
    endpoint, peer = _endpoint_with_a_pending_receive_error()
    seen = []

    def on_error(exc):
        seen.append(exc)
        return True

    async def first():
        async with endpoint:
            async for packet in endpoint.datagrams(on_error=on_error):
                return packet.data

    try:
        assert _run(first()) == b"after"
    finally:
        peer.close()
    assert len(seen) == 1 and isinstance(seen[0], OSError)


def test_on_error_returning_false_stops_with_that_error():
    endpoint, peer = _endpoint_with_a_pending_receive_error()
    seen = []

    def on_error(exc):
        seen.append(exc)
        return False

    async def collect():
        async with endpoint:
            async for _packet in endpoint.datagrams(on_error=on_error):
                pass

    try:
        with pytest.raises(OSError) as caught:
            _run(collect())
    finally:
        peer.close()
    assert seen == [caught.value]


def test_a_closed_endpoint_ends_the_loop_without_calling_on_error():
    """The error a close causes is the loop's end, not a failure to report."""
    calls = []
    endpoint = UDPEndpoint(bind("127.0.0.1", 0))
    endpoint.close()

    async def serve():
        return [
            packet
            async for packet in endpoint.datagrams(
                on_error=lambda exc: calls.append(exc) or True
            )
        ]

    assert _run(serve()) == []
    assert calls == []
