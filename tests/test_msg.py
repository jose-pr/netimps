"""The cross-platform ``recvmsg``/``sendmsg`` layer and the stdlib patch.

Real loopback sockets throughout, nothing mocked -- the whole point of this
layer is that a platform either delivers or it does not, and a fake socket
cannot tell you which. Where a platform genuinely cannot do something the test
skips with the reason rather than asserting the degraded answer.
"""

import os
import socket
import struct
import sys

import pytest

import netimps

IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# The functions, independent of any patching                                   #
# --------------------------------------------------------------------------- #


def test_the_functions_work_whether_or_not_the_patch_is_installed():
    """`netimps.recvmsg` is the supported surface; the patch is only sugar.

    Asserted explicitly because the dependency must not run the other way: a
    caller who declines the patch keeps every one of these.
    """
    assert netimps.supports_recvmsg() is True
    assert callable(netimps.recvmsg)
    assert callable(netimps.sendmsg)
    assert netimps.CMSG_SPACE(8) >= netimps.CMSG_LEN(8) > 8


def test_cmsg_space_leaves_room_for_a_following_header():
    """CMSG_SPACE >= CMSG_LEN, and the gap is the alignment pad.

    Sizing a buffer with CMSG_LEN is the classic way to silently lose the
    second cmsg, so the relationship is pinned rather than assumed.
    """
    for length in (0, 1, 4, 8, 12, 20, 64):
        assert netimps.CMSG_SPACE(length) >= netimps.CMSG_LEN(length)
    # No assertion about *which* alignment: it is not the same everywhere.
    # Linux and Windows pad to pointer width, macOS to 4 -- measured, where
    # CMSG_SPACE(8) is 20 there and 24 on the other two. Asserting pointer
    # alignment here encoded a Linux/Windows assumption as a universal law and
    # failed on macOS, which is the mistake this file exists to catch.
    assert netimps.CMSG_SPACE(1) >= netimps.CMSG_LEN(1)


def test_cmsg_helpers_reject_a_negative_length():
    # Only our own implementation validates; CPython's raises its own error.
    with pytest.raises((ValueError, OverflowError, OSError)):
        netimps.CMSG_LEN(-1)


@pytest.mark.parametrize(
    "family, host",
    [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")],
)
def test_recvmsg_round_trip_reports_the_sender_exactly_as_recvfrom(family, host):
    """The sender tuple must be indistinguishable from `recvfrom`'s.

    Including arity: an AF_INET6 sender is a 4-tuple
    `(host, port, flowinfo, scope_id)`, and a caller that unpacks two values
    would break on it. This is the assertion that caught nothing on POSIX and
    everything on the hand-rolled Windows sockaddr decoder.
    """
    try:
        server = socket.socket(family, socket.SOCK_DGRAM)
        server.bind((host, 0))
    except OSError as exc:
        pytest.skip("cannot bind %s: %s" % (host, exc))
    server.settimeout(5.0)
    try:
        port = server.getsockname()[1]
        client = socket.socket(family, socket.SOCK_DGRAM)
        try:
            client.sendto(b"via-recvmsg", (host, port))
            data, _anc, _flags, shim_sender = netimps.recvmsg(
                server, 1500, netimps.CMSG_SPACE(64)
            )
            assert data == b"via-recvmsg"

            client.sendto(b"via-recvfrom", (host, port))
            _data2, native_sender = server.recvfrom(1500)
        finally:
            client.close()
        assert len(shim_sender) == len(native_sender)
        assert shim_sender[0] == native_sender[0] == host
        if family == socket.AF_INET6:
            assert len(shim_sender) == 4, "an IPv6 sender is a 4-tuple"
    finally:
        server.close()


@pytest.mark.parametrize(
    "family, host",
    [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")],
)
def test_sendmsg_delivers_without_ancillary_data(family, host):
    try:
        peer = socket.socket(family, socket.SOCK_DGRAM)
        peer.bind((host, 0))
    except OSError as exc:
        pytest.skip("cannot bind %s: %s" % (host, exc))
    peer.settimeout(5.0)
    sender = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sent = netimps.sendmsg(sender, [b"hello"], (), 0, peer.getsockname())
        assert sent == 5
        assert peer.recvfrom(100)[0] == b"hello"
    finally:
        sender.close()
        peer.close()


def test_sendmsg_rejects_a_bare_bytes_like_cpython_does():
    """`buffers` is a *sequence* of buffers. A bare bytes is the classic slip.

    CPython raises TypeError for it, and so must we -- iterating a bytes would
    otherwise send one datagram per byte.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(TypeError):
            netimps.sendmsg(sock, b"not-a-sequence", (), 0, ("127.0.0.1", 9))
    finally:
        sock.close()


def test_empty_non_blocking_socket_raises_blockingioerror():
    """The error vocabulary is CPython's, on Windows too.

    Winsock reports WSAEWOULDBLOCK, which only becomes BlockingIOError because
    the code routes it through `ctypes.WinError` rather than constructing an
    OSError by hand. Easy to regress, invisible until a caller's `except
    BlockingIOError` stops matching.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    try:
        with pytest.raises(BlockingIOError):
            netimps.recvmsg(sock, 1500, netimps.CMSG_SPACE(64))
    finally:
        sock.close()


def test_a_tiny_control_buffer_truncates_instead_of_reading_out_of_bounds():
    """A control buffer smaller than one header must not walk off the end.

    This is a regression test for a real out-of-bounds read: Winsock sets
    `WSAMSG.Control.len` to the size it *wanted* (measured: 24 against a 1-byte
    buffer), not the size it wrote, so believing it indexed past the ctypes
    allocation. The flag must be reported and the parse must stay in bounds.
    """
    ip_pktinfo = getattr(socket, "IP_PKTINFO", None)
    if ip_pktinfo is None:
        pytest.skip("no IP_PKTINFO on this platform")
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5.0)
    try:
        try:
            server.setsockopt(socket.IPPROTO_IP, ip_pktinfo, 1)
        except OSError as exc:
            pytest.skip("IP_PKTINFO refused: %s" % (exc,))
        port = server.getsockname()[1]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client.sendto(b"squeezed", ("127.0.0.1", port))
            data, ancdata, flags, _sender = netimps.recvmsg(server, 1500, 1)
        finally:
            client.close()
        assert data == b"squeezed", "the payload survives a truncated control buffer"
        assert ancdata == [], "nothing can be parsed out of one byte"
        assert flags & getattr(socket, "MSG_CTRUNC", 0), "MSG_CTRUNC must be reported"
    finally:
        server.close()


def test_two_cmsgs_in_one_buffer_are_both_parsed():
    """The walk must step by the *aligned* length, or it loses the second cmsg.

    Needs a platform with two simultaneously-available v4 options. Windows and
    macOS both export IP_PKTINFO and IP_RECVDSTADDR; Linux has only the first,
    and skips.
    """
    options = [
        (socket.IPPROTO_IP, getattr(socket, "IP_PKTINFO", None)),
        (socket.IPPROTO_IP, getattr(socket, "IP_RECVDSTADDR", None)),
    ]
    options = [(lvl, opt) for lvl, opt in options if opt is not None]
    if len(options) < 2:
        pytest.skip("this platform exports fewer than two v4 ancillary options")

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5.0)
    try:
        enabled = 0
        for level, option in options:
            try:
                server.setsockopt(level, option, 1)
                enabled += 1
            except OSError:
                pass
        if enabled < 2:
            pytest.skip("could not enable two options at once")
        port = server.getsockname()[1]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client.sendto(b"two-cmsgs", ("127.0.0.1", port))
            _data, ancdata, flags, _sender = netimps.recvmsg(
                server, 1500, netimps.CMSG_SPACE(256)
            )
        finally:
            client.close()
        assert not flags & getattr(socket, "MSG_CTRUNC", 0)
        assert len(ancdata) >= 2, (
            "both cmsgs must survive the walk; got %r -- a step that is not "
            "pointer-aligned loses the second" % (ancdata,)
        )
        for level, ctype, cdata in ancdata:
            assert isinstance(cdata, bytes) and len(cdata) > 0
    finally:
        server.close()


# --------------------------------------------------------------------------- #
# The patch                                                                    #
# --------------------------------------------------------------------------- #


def test_patch_is_a_no_op_where_cpython_already_provides_these():
    """On POSIX nothing is installed, and `socket` keeps CPython's own methods.

    The guarantee is that netimps is invisible to the rest of the process on a
    platform that does not need it -- importing a network helper must not change
    how anyone else's `recvmsg` behaves.
    """
    if IS_WINDOWS:
        pytest.skip("Windows is the platform that does need the patch")
    assert netimps.socket_patched() is False
    assert netimps.patch_socket_module() == []
    assert socket.socket.recvmsg.__qualname__.startswith("socket")


@pytest.mark.skipif(
    not IS_WINDOWS, reason="the patch only installs where names are absent"
)
def test_patch_installs_all_four_names_on_windows():
    """All four, not just the method: the POSIX idiom needs CMSG_SPACE too.

    Patching `recvmsg` alone would let `hasattr(socket.socket, "recvmsg")`
    succeed and then fail on the next line, turning "this platform cannot" into
    "this library is broken".
    """
    assert netimps.socket_patched() is True
    assert hasattr(socket.socket, "recvmsg")
    assert hasattr(socket.socket, "sendmsg")
    assert hasattr(socket, "CMSG_LEN")
    assert hasattr(socket, "CMSG_SPACE")


@pytest.mark.skipif(not IS_WINDOWS, reason="nothing to toggle where names are native")
def test_patch_is_idempotent_and_reversible():
    """Install twice changes nothing; removing restores the original state.

    And critically: the module-level functions keep working with the patch off,
    because they never depended on it.
    """
    assert netimps.patch_socket_module() == [], "a second install must be a no-op"
    removed = netimps.patch_socket_module(False)
    try:
        assert sorted(removed) == [
            "CMSG_LEN",
            "CMSG_SPACE",
            "socket.recvmsg",
            "socket.sendmsg",
        ]
        assert netimps.socket_patched() is False
        assert not hasattr(socket.socket, "recvmsg")
        assert not hasattr(socket, "CMSG_SPACE")
        # The real surface is unaffected.
        assert netimps.supports_recvmsg() is True
        assert netimps.CMSG_SPACE(8) > 0
        assert netimps.patch_socket_module(False) == [], "double-remove is a no-op"
    finally:
        netimps.patch_socket_module()
    assert netimps.socket_patched() is True


@pytest.mark.skipif(not IS_WINDOWS, reason="the patched method only exists on Windows")
def test_the_patched_method_round_trips_on_a_real_socket():
    """Via the stdlib *method name*, which is the whole point of patching."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5.0)
    try:
        port = server.getsockname()[1]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client.sendto(b"through-the-method", ("127.0.0.1", port))
            data, _anc, _flags, sender = server.recvmsg(1500, socket.CMSG_SPACE(64))
        finally:
            client.close()
        assert data == b"through-the-method"
        assert sender[0] == "127.0.0.1"
    finally:
        server.close()


def test_the_patch_never_replaces_a_native_name():
    """Strictly additive, so it stands down if CPython ever ships these.

    Verified by construction rather than by platform: whatever is installed
    must be a name the platform did *not* already have.
    """
    from netimps import _msg

    for name in _msg._installed:
        attribute = name.split(".", 1)[-1]
        if name.startswith("socket."):
            assert getattr(_msg, "_NATIVE_%s" % attribute.upper()) is None
        else:
            assert getattr(_msg, "_NATIVE_%s" % attribute.upper()) is None


def test_opt_out_is_readable_from_the_environment(monkeypatch):
    """`NETIMPS_NO_SOCKET_PATCH` is read once, at import, and these spellings.

    Tested on the predicate rather than by re-importing netimps: the decision
    has to be makeable before the first import, so there is no way to exercise
    the real path twice in one process.
    """
    from netimps._msg import _patch_requested

    monkeypatch.delenv("NETIMPS_NO_SOCKET_PATCH", raising=False)
    assert _patch_requested() is True
    for value in ("1", "true", "TRUE", "yes", "on", "anything"):
        monkeypatch.setenv("NETIMPS_NO_SOCKET_PATCH", value)
        assert _patch_requested() is False, "%r should disable the patch" % (value,)
    for value in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("NETIMPS_NO_SOCKET_PATCH", value)
        assert _patch_requested() is True, "%r should not disable the patch" % (value,)


# --------------------------------------------------------------------------- #
# The Winsock backend itself                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not IS_WINDOWS, reason="_winsock is Windows-only by construction")
def test_winsock_alignment_and_header_size():
    """The cmsg data offset is pointer-aligned, not 4-aligned.

    Worth pinning because the Linux value a reader might assume happens to work
    on 32-bit and silently misparses everything on 64-bit.
    """
    from netimps import _winsock

    import ctypes

    assert _winsock._ALIGN == ctypes.sizeof(ctypes.c_void_p)
    # WSACMSGHDR is {SIZE_T len; INT level; INT type}.
    assert _winsock._CMSGHDR_SIZE == ctypes.sizeof(ctypes.c_size_t) + 2 * ctypes.sizeof(
        ctypes.c_int
    )
    assert _winsock.CMSG_LEN(0) == _winsock._align(_winsock._CMSGHDR_SIZE)
    assert _winsock.CMSG_SPACE(4) >= _winsock.CMSG_LEN(4)
    assert _winsock.available() is True


@pytest.mark.skipif(not IS_WINDOWS, reason="_winsock is Windows-only by construction")
def test_winsock_control_parser_stops_at_the_buffer_end():
    """A header claiming more than the buffer holds truncates the walk.

    Fed a deliberately lying length, because that is exactly what Winsock does
    and the parser is the last line of defence against indexing past the
    allocation.
    """
    from netimps import _winsock

    import ctypes

    # Built from the real struct rather than a format string: the header mixes
    # SIZE_T with INT, which `struct` cannot express portably in standard mode.
    header = _winsock._WSACMSGHDR(
        cmsg_len=_winsock.CMSG_LEN(4), cmsg_level=socket.IPPROTO_IP, cmsg_type=19
    )
    buffer = bytes(
        bytearray(ctypes.string_at(ctypes.byref(header), ctypes.sizeof(header)))
    )
    payload = b"\x7f\x00\x00\x01"
    padded = buffer + payload.ljust(
        _winsock._align(_winsock._CMSGHDR_SIZE) - len(buffer) + 4, b"\x00"
    )

    # Honest buffer: the one cmsg parses.
    parsed = _winsock._parse_control(padded, len(padded))
    assert len(parsed) == 1
    assert parsed[0][0] == socket.IPPROTO_IP and parsed[0][1] == 19

    # Lying length: Winsock really does report more than it wrote, so the parser
    # must clamp to the allocation instead of indexing past it.
    clamped = _winsock._parse_control(padded, 4096)
    assert all(len(data) <= len(padded) for _, _, data in clamped)

    # A header claiming less than its own size stops the walk rather than looping.
    short = _winsock._WSACMSGHDR(cmsg_len=1, cmsg_level=0, cmsg_type=0)
    short_bytes = ctypes.string_at(ctypes.byref(short), ctypes.sizeof(short))
    assert _winsock._parse_control(bytes(short_bytes), len(short_bytes)) == []


@pytest.mark.skipif(IS_WINDOWS, reason="importing _winsock off Windows must fail")
def test_winsock_is_not_importable_off_windows():
    """The module is Windows-only and documented as such.

    If this ever starts passing on POSIX, the lazy guard in `_msg` has become
    load-bearing for the wrong reason and someone will import it directly.
    """
    with pytest.raises(Exception):
        __import__("netimps._winsock")
    assert sys.platform != "win32"


# --------------------------------------------------------------------------- #
# sendmsg on a stream socket -- WSASend, not WSASendMsg                        #
# --------------------------------------------------------------------------- #


def _tcp_pair():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(listener.getsockname())
    server, _ = listener.accept()
    server.settimeout(5.0)
    listener.close()
    return client, server


def test_sendmsg_works_on_a_connected_stream_socket():
    """WSASendMsg refuses SOCK_STREAM, so the buffers-only path uses WSASend.

    Measured on Windows 11 build 28000: WSASendMsg answers WSAEINVAL for a
    connected SOCK_STREAM while accepting a connected SOCK_DGRAM, so the
    refusal is about the socket *type*, not about being connected. Without the
    dispatch, every TCP sendmsg failed -- which also meant asyncio's
    scatter-gather write path could never have worked through the shim.
    """
    client, server = _tcp_pair()
    try:
        sent = netimps.sendmsg(client, [b"hel", b"lo ", b"world"])
        assert sent == 11
        received = b""
        while len(received) < sent:
            received += server.recv(4096)
        assert received == b"hello world", "the buffers must be gathered in order"
    finally:
        client.close()
        server.close()


def test_sendmsg_gathers_many_buffers_on_a_stream_socket():
    """No small IOV_MAX-like cap was found; 500 buffers go in one call."""
    client, server = _tcp_pair()
    try:
        chunks = [bytes([65 + (index % 26)]) for index in range(500)]
        sent = netimps.sendmsg(client, chunks)
        assert sent == 500
        received = b""
        while len(received) < sent:
            received += server.recv(4096)
        assert received == b"".join(chunks)
    finally:
        client.close()
        server.close()


def test_sendmsg_still_routes_a_destination_through_wsasendmsg():
    """The dispatch must not lose the case WSASend cannot serve: a destination."""
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(5.0)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        assert netimps.sendmsg(sender, [b"ab", b"cd"], (), 0, peer.getsockname()) == 4
        assert peer.recvfrom(100)[0] == b"abcd"
    finally:
        sender.close()
        peer.close()


def test_sendmsg_still_routes_ancdata_through_wsasendmsg():
    """The other case WSASend cannot serve: a control buffer.

    Exercised through the public wrapper that depends on it, since src pinning
    is the only thing in the package that sends ancillary data.
    """
    from netimps import UdpEndpoint, bind

    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(5.0)
    endpoint = UdpEndpoint(bind("0.0.0.0", 0))
    try:
        if not endpoint.supports_src_pinning:
            pytest.skip("no src pinning on this platform")
        endpoint.send(b"pinned", "127.0.0.1", peer.getsockname()[1], src="127.0.0.1")
        _data, observed = peer.recvfrom(100)
        assert observed[0] == "127.0.0.1"
    finally:
        endpoint.close()
        peer.close()


def test_sendmsg_on_a_connected_datagram_socket_needs_no_address():
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(5.0)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.connect(peer.getsockname())
    try:
        assert netimps.sendmsg(sender, [b"xy"]) == 2
        assert peer.recvfrom(100)[0] == b"xy"
    finally:
        sender.close()
        peer.close()
