"""Tests for the gaps the 2026-10-03 consumer sweep found.

Each one exists because a consuming project hand-rolled it and got something
wrong, so the test pins the *difference* from the hand-rolled version rather
than just the happy path.
"""

import ipaddress
import os
import socket

import pytest

import netimps
from netimps import (
    FQDN,
    MACAddress,
    SocketOption,
    UDPEndpoint,
    bind,
    disable_connreset,
    is_wildcard,
    join_host,
    split_host,
    set_buffer_size,
    unmap,
)

IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# A -- Datagram.truncated: the silent payload loss                             #
# --------------------------------------------------------------------------- #


def test_a_short_bufsize_reports_truncation_rather_than_losing_it_silently():
    """A datagram larger than ``bufsize`` must say so.

    The consequence of not reporting it, measured: with
    ``max_packet_size=576`` a 1102-octet datagram arrived cut to 576 and the
    decoder was handed a message whose option stream stops mid-option. The
    flag was always there in ``msg_flags``; it was simply dropped.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"x" * 1102, ("127.0.0.1", port))
            packet = endpoint.recv(576)
        finally:
            sender.close()
        assert len(packet.data) == 576
        assert packet.truncated is True, "MSG_TRUNC must reach the caller"
        # The two truncation flags answer different questions.
        assert packet.control_truncated is False


def test_a_datagram_that_fits_is_not_marked_truncated():
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"fits", ("127.0.0.1", port))
            packet = endpoint.recv(1500)
        finally:
            sender.close()
        assert packet.data == b"fits"
        assert packet.truncated is False


def test_a_truncation_is_reported_even_without_pktinfo():
    """Losing the interface must not also lose the truncation signal.

    The degraded path goes through ``recvmsg`` with a zero-length control
    buffer rather than ``recvfrom``, precisely because ``recvfrom`` cannot
    report ``MSG_TRUNC`` and silent data loss is worse than a missing
    interface.
    """
    with UDPEndpoint(bind("127.0.0.1", 0), pktinfo=False) as endpoint:
        assert not endpoint.has_pktinfo
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"y" * 900, ("127.0.0.1", port))
            packet = endpoint.recv(300)
        finally:
            sender.close()
        assert len(packet.data) == 300
        if not netimps.has_recvmsg():  # pragma: no cover - no such platform now
            pytest.skip("no recvmsg here, so recvfrom cannot report truncation")
        assert packet.truncated is True
        # Still no interface information -- that part is the documented degrade.
        assert packet.interface_index == 0 and packet.interface is None


# --------------------------------------------------------------------------- #
# C -- join_host, the inverse of split_host                                #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host, port, expected",
    [
        ("example.com", 8080, "example.com:8080"),
        ("10.0.0.5", 8080, "10.0.0.5:8080"),
        ("::1", 8080, "[::1]:8080"),
        ("fe80::1%eth0", 80, "[fe80::1%eth0]:80"),
        ("2001:db8::1", 53, "[2001:db8::1]:53"),
        ("::1", None, "::1"),
        ("example.com", None, "example.com"),
        ("10.0.0.5", None, "10.0.0.5"),
        ("[::1]", 443, "[::1]:443"),
        ("0.0.0.0", 0, "0.0.0.0:0"),
    ],
)
def test_join_host_brackets_only_an_ipv6_literal(host, port, expected):
    assert join_host(host, port) == expected


@pytest.mark.parametrize(
    "host, port",
    [
        ("example.com", 8080),
        ("10.0.0.5", 8080),
        ("::1", 8080),
        ("fe80::1%eth0", 80),
        ("2001:db8::1", 53),
        ("::1", None),
        ("example.com", None),
        ("0.0.0.0", 0),
    ],
)
def test_join_host_round_trips_through_normalize_host(host, port):
    """The law that makes the pair trustworthy, in both directions.

    This is why a port-less IPv6 comes back *unbracketed*: with no port there
    is nothing to disambiguate, and `split_host` returns the bare form.
    """
    assert split_host(join_host(host, port)) == (host, port)


def test_join_host_accepts_the_types_a_caller_already_has():
    assert join_host(ipaddress.IPv4Address("1.2.3.4"), 53) == "1.2.3.4:53"
    assert join_host(ipaddress.IPv6Address("2001:db8::1"), 53) == "[2001:db8::1]:53"
    assert join_host(FQDN("www.example.com"), 443) == "www.example.com:443"
    # An interface carries a prefix; a socket address wants only the address.
    assert join_host(ipaddress.IPv4Interface("10.0.0.5/24"), 69) == "10.0.0.5:69"
    assert (
        join_host(ipaddress.IPv6Interface("2001:db8::1/64"), 69) == "[2001:db8::1]:69"
    )


def test_join_host_never_brackets_a_name():
    """Brackets in a URI authority mean "the inside is an address".

    Bracketing a hostname would produce something no resolver accepts, however
    many colons someone has managed to put in it.
    """
    assert join_host("example.com", 80) == "example.com:80"
    assert "[" not in join_host(FQDN("a.b.c.example.com"), 80)


@pytest.mark.parametrize(
    "host, port, match",
    [
        ("", 80, "must not be empty"),
        ("example.com", 99999, "0-65535"),
        ("example.com", -1, "0-65535"),
        ("[::1", 80, "mismatched brackets"),
        ("::1]", 80, "mismatched brackets"),
        ("[notanaddress]", 80, "not an IPv6 address"),
    ],
)
def test_join_host_rejects_bad_input(host, port, match):
    """A mismatched bracket must raise, not fall through.

    `"[::1"` is not an IPv6 literal, so without the check it would emerge
    unbracketed as `"[::1:80"` -- garbage the caller cannot detect.
    `split_host` rejects the same input, and the pair has to agree.
    """
    with pytest.raises(ValueError, match=match):
        join_host(host, port)


def test_join_host_rejects_none():
    with pytest.raises(TypeError):
        join_host(None, 80)


# --------------------------------------------------------------------------- #
# D3 -- unmap                                                                  #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value, expected",
    [
        ("::ffff:10.0.0.5", "10.0.0.5"),
        ("10.0.0.5", "10.0.0.5"),
        ("2001:db8::1", "2001:db8::1"),
        ("::1", "::1"),
        ("::", "::"),
    ],
)
def test_unmap_collapses_a_mapped_address_and_passes_the_rest_through(value, expected):
    assert str(unmap(value)) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("::FFFF:10.0.0.5", "10.0.0.5"),
        ("::ffff:0:1", "0.0.0.1"),
        ("0:0:0:0:0:ffff:0a00:0005", "10.0.0.5"),
    ],
)
def test_unmap_sees_through_spellings_a_string_test_misses(value, expected):
    """The reason this is not `startswith("::ffff:")` plus a slice.

    All three of these *are* mapped addresses. The string test -- which is what
    a consuming project had -- leaves every one of them untouched: wrong case,
    no dot, expanded form. One address has many spellings and only the parsed
    form sees through them.
    """
    assert str(unmap(value)) == expected
    naive = value[7:] if value.startswith("::ffff:") and "." in value else value
    assert str(unmap(value)) != naive, "the string test would have been right here"


def test_unmap_accepts_parsed_addresses_and_rejects_non_addresses():
    assert unmap(ipaddress.IPv6Address("::ffff:1.2.3.4")) == ipaddress.IPv4Address(
        "1.2.3.4"
    )
    assert unmap(ipaddress.IPv4Address("1.2.3.4")) == ipaddress.IPv4Address("1.2.3.4")
    with pytest.raises(ValueError):
        unmap("example.com")


def test_unmap_is_the_inverse_of_the_dual_stack_mapping():
    """`UDPEndpoint` maps a v4 arrival up; this maps it back down."""
    assert str(unmap("::ffff:127.0.0.1")) == "127.0.0.1"


# --------------------------------------------------------------------------- #
# D4 -- is_wildcard                                                            #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value, expected",
    [
        ("", True),
        (None, True),
        ("0.0.0.0", True),
        ("::", True),
        ("::0", True),
        ("0000:0000:0000:0000:0000:0000:0000:0000", True),
        ("0.0.0.0%eth0", True),
        ("127.0.0.1", False),
        ("::1", False),
        ("example.com", False),
        ("garbage", False),
        ("10.0.0.5", False),
    ],
)
def test_is_wildcard(value, expected):
    assert is_wildcard(value) is expected


def test_is_wildcard_accepts_parsed_addresses_and_never_raises():
    assert is_wildcard(ipaddress.IPv4Address("0.0.0.0")) is True
    assert is_wildcard(ipaddress.IPv6Address("::")) is True
    assert is_wildcard(ipaddress.IPv4Address("1.2.3.4")) is False
    # Junk is simply not a wildcard, so this stays usable in a branch.
    for junk in ("...", "999.999.999.999", "[::1", "a b c"):
        assert is_wildcard(junk) is False


def test_is_wildcard_agrees_with_what_bind_treats_as_the_wildcard():
    """`bind("")` is documented as the wildcard, so `is_wildcard("")` must agree."""
    sock = bind("", 0)
    try:
        assert is_wildcard("")
        assert is_wildcard(sock.getsockname()[0])
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# D1 -- disable_connreset                                                      #
# --------------------------------------------------------------------------- #


def test_disable_connreset_reports_whether_it_changed_anything():
    """True only on Windows, where there is something to change."""
    sock = bind("127.0.0.1", 0)
    try:
        assert disable_connreset(sock) is IS_WINDOWS
    finally:
        sock.close()


@pytest.mark.skipif(not IS_WINDOWS, reason="SIO_UDP_CONNRESET is Windows-only")
def test_disable_connreset_needs_wsaioctl_not_socket_ioctl():
    """There is no stdlib route, which is why this lives here.

    CPython exports no `socket.SIO_UDP_CONNRESET` on any version, and
    `socket.ioctl` whitelists commands -- so even with the documented value it
    answers `ValueError: invalid ioctl command`. A consuming project's own copy
    used the `getattr` route and was a silent no-op on every platform.
    """
    from netimps import _winsock

    assert getattr(socket, "SIO_UDP_CONNRESET", None) is None
    assert _winsock.SIO_UDP_CONNRESET == 0x9800000C
    sock = bind("127.0.0.1", 0)
    try:
        with pytest.raises(ValueError, match="invalid ioctl"):
            sock.ioctl(_winsock.SIO_UDP_CONNRESET, False)
        # ...while the WSAIoctl route succeeds on the same socket.
        _winsock.set_udp_connreset(sock, False)
    finally:
        sock.close()


@pytest.mark.skipif(not IS_WINDOWS, reason="only Windows has the option to refuse")
def test_disable_connreset_is_refused_on_a_stream_socket():
    """UDP-only, and a refusal degrades rather than raising."""
    sock = bind("127.0.0.1", 0, kind=socket.SOCK_STREAM)
    try:
        assert disable_connreset(sock) is False
    finally:
        sock.close()


def test_bind_connreset_keyword_works_on_every_platform():
    """A no-op off Windows rather than an error, so one call site serves all."""
    sock = bind("127.0.0.1", 0, connreset=False)
    try:
        assert sock.getsockname()[0] == "127.0.0.1"
    finally:
        sock.close()
    # The default leaves it alone.
    sock = bind("127.0.0.1", 0)
    sock.close()


# --------------------------------------------------------------------------- #
# D2 -- set_buffer_size                                                        #
# --------------------------------------------------------------------------- #


def test_set_buffer_size_reports_what_was_granted_not_what_was_asked():
    """The silent partial grant is the failure mode this exists to expose.

    `setsockopt` succeeds and the kernel may still grant less (Linux
    `rmem_max`) -- or more, since Linux doubles the request for its own
    bookkeeping. Either way the answer comes from `getsockopt`.
    """
    sock = bind("127.0.0.1", 0)
    try:
        want = 1 << 20
        got_rx, got_tx = set_buffer_size(sock, receive=want)
        assert got_rx == sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        assert got_tx == sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        assert got_rx > 0 and got_tx > 0
    finally:
        sock.close()


def test_set_buffer_size_only_grows():
    """It must not undo a caller's earlier tuning."""
    sock = bind("127.0.0.1", 0)
    try:
        big = 1 << 20
        before_rx, _ = set_buffer_size(sock, receive=big)
        after_rx, _ = set_buffer_size(sock, receive=1024)
        assert after_rx >= before_rx, "a smaller request must not shrink the buffer"
    finally:
        sock.close()


def test_set_buffer_size_skips_a_direction_given_none():
    sock = bind("127.0.0.1", 0)
    try:
        baseline = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        _rx, tx = set_buffer_size(sock, receive=1 << 20)
        assert tx == baseline
        # Both None is a pure query.
        assert set_buffer_size(sock) == (
            sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
            sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
        )
    finally:
        sock.close()


def test_set_buffer_size_rejects_a_negative_request():
    sock = bind("127.0.0.1", 0)
    try:
        with pytest.raises(ValueError, match="negative"):
            set_buffer_size(sock, receive=-1)
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# E / F -- MACAddress.hex, SocketOption                                        #
# --------------------------------------------------------------------------- #


def test_mac_hex_matches_bytes_hex():
    """A pure passthrough -- the reason callers subclassed this type."""
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert mac.hex() == "aabbccddeeff" == mac.packed.hex()
    assert mac.hex(":") == mac.packed.hex(":") == "aa:bb:cc:dd:ee:ff"
    assert mac.hex("-", 2) == mac.packed.hex("-", 2) == "aabb-ccdd-eeff"


def test_mac_hex_is_lowercase_like_str_and_unlike_format_upper():
    mac = MACAddress("AA:BB:CC:DD:EE:FF")
    assert mac.hex(":") == "aa:bb:cc:dd:ee:ff"
    assert mac.format(":", upper=True) == "AA:BB:CC:DD:EE:FF"


def test_socket_option_is_a_tuple_and_bind_takes_either_form():
    """A widening only: bare tuples must keep working."""
    option = SocketOption(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    assert isinstance(option, tuple)
    assert tuple(option) == (option.level, option.name, option.value)

    for options in ([option], [(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)]):
        sock = bind("127.0.0.1", 0, options=options)
        try:
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) > 0
        finally:
            sock.close()


def test_the_new_names_are_all_exported():
    for name in (
        "join_host",
        "unmap",
        "is_wildcard",
        "SocketOption",
        "disable_connreset",
        "set_buffer_size",
    ):
        assert hasattr(netimps, name), name
        assert name in netimps.__all__, name


# --------------------------------------------------------------------------- #
# bind() and split_host() take the package's usual loose union             #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("str", "127.0.0.1", "127.0.0.1"),
        ("IPv4Address", ipaddress.IPv4Address("127.0.0.1"), "127.0.0.1"),
        ("IPv4Interface", ipaddress.IPv4Interface("127.0.0.1/8"), "127.0.0.1"),
        ("Host", None, "127.0.0.1"),
        ("FQDN", None, "127.0.0.1"),
    ],
)
def test_bind_accepts_more_than_a_string(label, value, expected):
    """It used to leak a raw socket-layer TypeError for values every other
    entry point in the package takes.

    "str, bytes or bytearray expected, not IPv4Address" -- not even a netimps
    error, for an address object. `ping`, `resolve` and `UDPEndpoint.send` all
    coerce through the same helper; this one entry point simply never did.
    """
    if label == "Host":
        value = netimps.Host("127.0.0.1")
    elif label == "FQDN":
        value = netimps.FQDN("localhost")
    sock = bind(value, 0)
    try:
        assert sock.getsockname()[0] == expected
    finally:
        sock.close()


def test_bind_still_treats_the_empty_string_as_the_wildcard():
    sock = bind("", 0)
    try:
        assert sock.getsockname()[0] in ("0.0.0.0", "")
    finally:
        sock.close()


def test_bind_refuses_a_network():
    """A network names no single address, and guessing one would be worse."""
    with pytest.raises(TypeError, match="not a network"):
        bind(ipaddress.ip_network("10.0.0.0/24"), 0)


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("str", "example.com:80", ("example.com", 80)),
        ("IPv4Address", ipaddress.IPv4Address("1.2.3.4"), ("1.2.3.4", None)),
        ("IPv6Address", ipaddress.IPv6Address("::1"), ("::1", None)),
        ("IPv4Interface", ipaddress.IPv4Interface("10.0.0.5/24"), ("10.0.0.5", None)),
    ],
)
def test_normalize_host_accepts_more_than_a_string(label, value, expected):
    """`join_host`, its inverse, already did -- this rejected the values a caller
    holding "the host" most often has."""
    assert netimps.split_host(value) == expected


def test_normalize_host_accepts_host_and_fqdn():
    assert netimps.split_host(netimps.Host("example.com")) == ("example.com", None)
    # An FQDN keeps its trailing dot, which is identity-bearing for a name.
    assert netimps.split_host(netimps.FQDN("b.com.")) == ("b.com.", None)


@pytest.mark.parametrize("bad", [None, 42, [], b"x", object()])
def test_normalize_host_uses_an_allowlist_not_a_str_fallback(bad):
    """`str(None)` is the hostname "None" -- a plausible answer that is wrong.

    An earlier version of this widening fell back to `str()` for anything
    unrecognised, which accepted `None`, an int and a list and turned each into a
    hostname a caller could not detect as bogus. The allowlist is the point.
    """
    with pytest.raises((ValueError, TypeError)):
        netimps.split_host(bad)


def test_normalize_host_still_refuses_a_network_and_an_empty_string():
    with pytest.raises(TypeError, match="not a network"):
        netimps.split_host(ipaddress.ip_network("10.0.0.0/24"))
    with pytest.raises(ValueError):
        netimps.split_host("")


@pytest.mark.parametrize(
    "host, port",
    [
        (ipaddress.IPv6Address("::1"), 69),
        (ipaddress.IPv4Address("10.0.0.1"), 80),
        ("example.com", 443),
    ],
)
def test_the_round_trip_law_survives_the_widening(host, port):
    """`split_host(join_host(h, p))` must still come back equal.

    The pair are inverses, and widening one input must not break that -- which is
    why this is asserted against the *parsed* forms the widening added, not only
    against strings.
    """
    assert netimps.split_host(netimps.join_host(host, port)) == (str(host), port)
