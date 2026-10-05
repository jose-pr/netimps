"""IPv4 arrival data and source pinning where the carrier is not ``IP_PKTINFO``.

FreeBSD reports an IPv4 datagram's destination and interface through
``IP_RECVDSTADDR`` and ``IP_RECVIF`` and pins a source with a control message of
the same number as the first. The decoding and the message building are pure and
run everywhere; the endpoint's use of them is exercised here with the platform
switch turned on and the kernel's answer supplied; the last two tests run only
on a FreeBSD host, against the real kernel.
"""

import ipaddress
import socket
import struct
import sys

import pytest

from netimps import Interface, UDPEndpoint, bind, has_pktinfo

# Private: the receive path's private seams.
from netimps._udp import _endpoint, _freebsd

ON_FREEBSD = sys.platform.startswith("freebsd")


def _sockaddr_dl(index=3, name=b"lo0", family=18):
    """The 56 bytes FreeBSD 16.0 delivered for ``IP_RECVIF`` on ``lo0``."""
    data = bytearray(56)
    data[0] = 56
    data[1] = family
    data[2:4] = struct.pack("=H", index)
    data[5] = len(name)
    data[8 : 8 + len(name)] = name
    return bytes(data)


def test_sockaddr_dl_gives_the_index_and_the_name():
    assert _freebsd.parse_sockaddr_dl(_sockaddr_dl()) == (3, "lo0")
    assert _freebsd.parse_sockaddr_dl(_sockaddr_dl(index=258, name=b"em0")) == (
        258,
        "em0",
    )


def test_a_sockaddr_dl_that_is_short_foreign_or_cut_is_absent():
    assert _freebsd.parse_sockaddr_dl(b"") is None
    assert _freebsd.parse_sockaddr_dl(_sockaddr_dl()[:6]) is None
    assert _freebsd.parse_sockaddr_dl(_sockaddr_dl(family=2)) is None
    cut = bytearray(_sockaddr_dl())
    cut[5] = 200  # the name claims more bytes than the structure holds
    assert _freebsd.parse_sockaddr_dl(bytes(cut)) is None


def test_decode_arrival_reads_each_message_for_its_own_fact():
    ip = socket.IPPROTO_IP
    assert _freebsd.decode_arrival(ip, 7, b"\x7f\x00\x00\x01") == (
        0,
        ipaddress.IPv4Address("127.0.0.1"),
    )
    assert _freebsd.decode_arrival(ip, 20, _sockaddr_dl(index=5)) == (5, None)
    assert _freebsd.decode_arrival(ip, 7, b"\x7f\x00") is None
    assert _freebsd.decode_arrival(ip, 20, b"\x01") is None
    assert _freebsd.decode_arrival(ip, 8, b"\x7f\x00\x00\x01") is None
    assert _freebsd.decode_arrival(socket.IPPROTO_IPV6, 7, b"\x00" * 4) is None


def test_the_source_message_is_the_address_at_ip_level():
    control = _freebsd.source_control(ipaddress.IPv4Address("10.1.2.3"))
    assert control == (socket.IPPROTO_IP, 7, bytes([10, 1, 2, 3]))


def test_only_a_wildcard_bound_socket_can_pin():
    with bind("0.0.0.0", 0) as wildcard, bind("127.0.0.1", 0) as bound:
        assert _freebsd.can_pin(wildcard) is True
        assert _freebsd.can_pin(bound) is False
    assert _freebsd.can_pin(wildcard) is False  # closed: nothing to ask


@pytest.fixture
def freebsd_v4(monkeypatch):
    """The FreeBSD branch on, and the kernel's acceptance of the options assumed."""
    monkeypatch.setattr(_freebsd, "IS_FREEBSD", True)
    monkeypatch.setattr(_freebsd, "enable_receive", lambda sock: True)


def test_the_flags_follow_what_the_platform_can_do(freebsd_v4):
    with UDPEndpoint(bind("0.0.0.0", 0)) as wildcard:
        assert wildcard.has_pktinfo is True
        assert wildcard.has_src_pinning is True
    with UDPEndpoint(bind("127.0.0.1", 0)) as bound:
        assert bound.has_pktinfo is True
        # errno 22 from the kernel for a socket bound to one address
        assert bound.has_src_pinning is False


def test_a_refused_receive_option_leaves_pktinfo_false(monkeypatch):
    monkeypatch.setattr(_freebsd, "IS_FREEBSD", True)
    monkeypatch.setattr(_freebsd, "enable_receive", lambda sock: False)
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        assert endpoint.has_pktinfo is False


@pytest.mark.parametrize("order", ["address first", "interface first"])
def test_recv_combines_the_two_messages(freebsd_v4, monkeypatch, order):
    ip = socket.IPPROTO_IP
    messages = [(ip, 7, b"\x7f\x00\x00\x01"), (ip, 20, _sockaddr_dl(index=3))]
    if order == "interface first":
        messages.reverse()
    monkeypatch.setattr(
        _endpoint,
        "_recvmsg",
        lambda sock, bufsize, ancbufsize: (b"x", messages, 0, ("127.0.0.1", 9)),
    )
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        packet = endpoint.recv(resolve_interface=False)
    assert packet.destination == ipaddress.IPv4Address("127.0.0.1")
    assert packet.interface_index == 3


def test_recv_without_the_interface_message_still_reports_the_address(
    freebsd_v4, monkeypatch
):
    messages = [(socket.IPPROTO_IP, 7, b"\x0a\x00\x00\x05")]
    monkeypatch.setattr(
        _endpoint,
        "_recvmsg",
        lambda sock, bufsize, ancbufsize: (b"x", messages, 0, ("10.0.0.9", 9)),
    )
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        packet = endpoint.recv(resolve_interface=False)
    assert packet.destination == ipaddress.IPv4Address("10.0.0.5")
    assert packet.interface_index == 0


def test_an_address_is_pinned_by_the_source_message(freebsd_v4):
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        expected = (socket.IPPROTO_IP, 7, bytes([10, 1, 2, 3]))
        assert endpoint._pktinfo_control("10.1.2.3") == expected


def test_a_zero_source_sends_no_message(freebsd_v4):
    """The kernel refuses a zero source (errno 22), so none is sent.

    Linux and macOS read a zero address as "kernel chooses"; leaving the
    message out asks FreeBSD for the same thing.
    """
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        assert endpoint._pktinfo_control("0.0.0.0") is None


def test_an_interface_is_pinned_by_its_ipv4_address(freebsd_v4):
    spec = Interface(
        name="em0",
        index=2,
        ips=[
            ipaddress.IPv6Interface("fe80::1/64"),
            ipaddress.IPv4Interface("10.1.2.3/24"),
        ],
    )
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        assert endpoint._pktinfo_control(spec) == (
            socket.IPPROTO_IP,
            7,
            bytes([10, 1, 2, 3]),
        )


def test_an_interface_without_an_ipv4_address_cannot_be_pinned(freebsd_v4):
    spec = Interface(name="em0", index=2, ips=[ipaddress.IPv6Interface("fe80::1/64")])
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        with pytest.raises(ValueError, match="IPv4"):
            endpoint._pktinfo_control(spec)


def test_an_ipv6_source_on_an_ipv4_endpoint_is_refused(freebsd_v4):
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        with pytest.raises(ValueError, match="IPv6 source"):
            endpoint._pktinfo_control("::1")


@pytest.mark.skipif(not ON_FREEBSD, reason="the kernel half needs FreeBSD")
def test_freebsd_reports_the_ipv4_arrival_of_a_wildcard_endpoint():
    assert has_pktinfo(socket.AF_INET) is True
    with UDPEndpoint(bind("0.0.0.0", 0)) as endpoint:
        endpoint.socket.settimeout(5)
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            peer.sendto(b"x", ("127.0.0.1", endpoint.socket.getsockname()[1]))
            packet = endpoint.recv()
        finally:
            peer.close()
    assert endpoint.has_pktinfo
    assert packet.destination == ipaddress.IPv4Address("127.0.0.1")
    assert packet.interface_index != 0


@pytest.mark.skipif(not ON_FREEBSD, reason="the kernel half needs FreeBSD")
def test_freebsd_pins_the_source_only_where_the_kernel_allows_it():
    peer = bind("127.0.0.1", 0)
    peer.settimeout(5)
    try:
        port = peer.getsockname()[1]
        with UDPEndpoint(bind("0.0.0.0", 0)) as wildcard:
            assert wildcard.has_src_pinning is True
            wildcard.send(b"x", "127.0.0.1", port, src="127.0.0.1")
            assert peer.recvfrom(10)[1][0] == "127.0.0.1"
        with UDPEndpoint(bind("127.0.0.1", 0)) as bound:
            assert bound.has_src_pinning is False
            bound.send(b"x", "127.0.0.1", port, src="127.0.0.1")
            assert peer.recvfrom(10)[0] == b"x"
    finally:
        peer.close()
