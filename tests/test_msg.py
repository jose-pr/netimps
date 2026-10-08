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

# Private: platform constants for the pktinfo options; no decision is read from it.
from netimps import _pktinfo

IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# The functions, independent of any patching                                   #
# --------------------------------------------------------------------------- #


def test_the_functions_work_whether_or_not_the_patch_is_installed():
    """`netimps.recvmsg` is the supported surface; the patch is only sugar.

    Asserted explicitly because the dependency must not run the other way: a
    caller who declines the patch keeps every one of these.
    """
    assert netimps.has_recvmsg() is True
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


def test_recvmsg_waits_out_a_socket_timeout():
    """A socket with a timeout is non-blocking underneath. `recvmsg` has to wait
    for it as the stdlib method does: on Windows it returned `WSAEWOULDBLOCK`
    as `BlockingIOError` after 0.000 s of a 0.3 s timeout."""
    import time

    sock = netimps.bind("127.0.0.1", 0)
    sock.settimeout(0.2)
    try:
        began = time.monotonic()
        with pytest.raises(socket.timeout):
            netimps.recvmsg(sock, 100)
        assert time.monotonic() - began >= 0.15
    finally:
        sock.close()


def test_recvmsg_returns_a_datagram_that_arrives_inside_the_timeout():
    """The wait ends when the datagram arrives, not when the timeout does."""
    import threading
    import time

    sock = netimps.bind("127.0.0.1", 0)
    sock.settimeout(5.0)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    timer = threading.Timer(0.1, sender.sendto, (b"late", sock.getsockname()))
    try:
        began = time.monotonic()
        timer.start()
        data = netimps.recvmsg(sock, 100)[0]
        assert data == b"late"
        assert time.monotonic() - began < 4.0
    finally:
        timer.cancel()
        timer.join()
        sender.close()
        sock.close()


def test_sendmsg_works_on_a_socket_with_a_timeout():
    """The send side waits for writability the same way; a UDP socket is
    writable at once, so the call must simply succeed."""
    sock = netimps.bind("127.0.0.1", 0)
    sock.settimeout(0.5)
    peer = netimps.bind("127.0.0.1", 0)
    try:
        assert netimps.sendmsg(sock, [b"ping"], (), 0, peer.getsockname()) == 4
        assert peer.recvfrom(100)[0] == b"ping"
    finally:
        peer.close()
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
    # From `_pktinfo`, not from `socket`: `socket.IP_PKTINFO` only exists from
    # CPython 3.12, so probing it here skipped this test on 3.9 -- the same blind
    # spot that let the constant bug reach main in the first place. The literal
    # table in `_pktinfo` is the platform fact; `socket` is just one source for it.
    # Private: platform constants for the pktinfo options; no decision is read from it.
    from netimps import _pktinfo

    ip_pktinfo = _pktinfo._IP_PKTINFO
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


#: Winsock's own values, written as literals so the test does not read the
#: constants the library under test reads.
_WIN_MSG_TRUNC = 0x100
_WIN_MSG_CTRUNC = 0x200


@pytest.mark.skipif(not IS_WINDOWS, reason="WSAEMSGSIZE is Winsock's answer")
@pytest.mark.parametrize(
    "family, host",
    [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")],
)
@pytest.mark.parametrize(
    "bufsize, ancbufsize, expected",
    [
        (100, 64, 0),
        (1, 64, _WIN_MSG_TRUNC),
        (100, 1, _WIN_MSG_CTRUNC),
        (100, 0, _WIN_MSG_CTRUNC),
        (1, 1, _WIN_MSG_TRUNC | _WIN_MSG_CTRUNC),
    ],
    ids=["both-fit", "payload-cut", "control-cut", "no-control-buffer", "both-cut"],
)
def test_windows_reports_each_buffer_that_was_too_small_and_only_that_one(
    family, host, bufsize, ancbufsize, expected
):
    """`MSG_TRUNC` means the payload was cut, `MSG_CTRUNC` that the control data was.

    Winsock answers `WSAEMSGSIZE` for either buffer being too small. Measured
    on Windows 11 ARM64 (2026-10-09): a 2-octet datagram read with a 100-octet
    buffer and a control buffer of 0 or 1 octets came back whole with both flags
    set, because the wrapper took the error code for a cut payload.
    """
    receiver = socket.socket(family, socket.SOCK_DGRAM)
    sender = socket.socket(family, socket.SOCK_DGRAM)
    try:
        receiver.bind((host, 0))
        receiver.settimeout(5.0)
        if family == socket.AF_INET:
            receiver.setsockopt(socket.IPPROTO_IP, _pktinfo._IP_PKTINFO, 1)
        else:
            receiver.setsockopt(socket.IPPROTO_IPV6, _pktinfo._IPV6_PKTINFO, 1)
        sender.sendto(b"hi", receiver.getsockname()[:2])
        data, _ancdata, flags, _sender = netimps.recvmsg(receiver, bufsize, ancbufsize)
    finally:
        receiver.close()
        sender.close()
    assert data == b"hi"[:bufsize]
    assert flags & (_WIN_MSG_TRUNC | _WIN_MSG_CTRUNC) == expected


def test_two_cmsgs_in_one_buffer_are_both_parsed():
    """The walk must step by the *aligned* length, or it loses the second cmsg.

    Needs a platform with two simultaneously-available v4 options. Windows and
    macOS both export IP_PKTINFO and IP_RECVDSTADDR; Linux has only the first,
    and skips.
    """
    options = [
        (socket.IPPROTO_IP, _pktinfo._IP_PKTINFO),
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
    assert netimps.is_socket_patched() is False
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
    assert netimps.is_socket_patched() is True
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
        # os.sysconf joins the set on a platform that lacks it: it is part of
        # the same patch, because installing sendmsg is what makes the stdlib's
        # "sendmsg implies os.sysconf is available" inference wrong.
        assert {"socket.recvmsg", "socket.sendmsg", "CMSG_LEN", "CMSG_SPACE"} <= set(
            removed
        )
        assert set(removed) <= {
            "CMSG_LEN",
            "CMSG_SPACE",
            "socket.recvmsg",
            "socket.sendmsg",
            "os.sysconf",
            "os.sysconf_names",
        }
        assert netimps.is_socket_patched() is False
        assert not hasattr(socket.socket, "recvmsg")
        assert not hasattr(socket, "CMSG_SPACE")
        # Nothing native was displaced, so removal leaves the name truly absent.
        import os as _os_check

        assert not hasattr(_os_check, "sysconf")
        # The real surface is unaffected.
        assert netimps.has_recvmsg() is True
        assert netimps.CMSG_SPACE(8) > 0
        assert netimps.patch_socket_module(False) == [], "double-remove is a no-op"
    finally:
        netimps.patch_socket_module()
    assert netimps.is_socket_patched() is True


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
    import os as _os

    # Private: the socket patch and control-message sizing are not public.
    from netimps import _msg
    from netimps._msg import _patch, _sysconf

    # Expressed against what is actually installed, rather than through a
    # `_NATIVE_*` naming convention: that convention only ever covered the four
    # socket names and passed vacuously for anything else, os.sysconf included.
    expected = {
        "socket.recvmsg": _patch._patched_recvmsg,
        "socket.sendmsg": _patch._patched_sendmsg,
        "CMSG_LEN": _msg.CMSG_LEN,
        "CMSG_SPACE": _msg.CMSG_SPACE,
        "os.sysconf": _sysconf._shim_sysconf,
    }
    for name, (owner, attribute) in _patch._installed.items():
        if name == "os.sysconf_names":
            assert isinstance(getattr(owner, attribute), dict)
            continue
        assert name in expected, "unknown installed name %r" % (name,)
        assert getattr(owner, attribute) is expected[name], (
            "%s is not the function netimps installed -- something native was "
            "displaced" % (name,)
        )


def test_opt_out_is_readable_from_the_environment(monkeypatch):
    """`NETIMPS_SOCKET_PATCH` is read once, at import, with explicit spellings.

    Tested on the predicate rather than by re-importing netimps: the decision
    has to be makeable before the first import, so there is no way to exercise
    the real path twice in one process.

    Unset or empty: patch (True). "1", "true", "yes", "on": patch (True).
    "0", "false", "no", "off": do not patch (False). Anything else: ValueError.
    """
    # Private: the socket patch and control-message sizing are not public.
    from netimps._msg._patch import _patch_requested

    monkeypatch.delenv("NETIMPS_SOCKET_PATCH", raising=False)
    monkeypatch.delenv("NETIMPS_NO_SOCKET_PATCH", raising=False)
    # Unset: patch
    assert _patch_requested() is True
    # Empty: patch
    monkeypatch.setenv("NETIMPS_SOCKET_PATCH", "")
    assert _patch_requested() is True
    # True spellings (case-insensitive): patch
    for value in ("1", "true", "TRUE", "True", "yes", "YES", "on", "ON"):
        monkeypatch.setenv("NETIMPS_SOCKET_PATCH", value)
        assert _patch_requested() is True, "%r should enable the patch" % (value,)
    # False spellings (case-insensitive): do not patch
    for value in ("0", "false", "FALSE", "no", "NO", "off", "OFF"):
        monkeypatch.setenv("NETIMPS_SOCKET_PATCH", value)
        assert _patch_requested() is False, "%r should disable the patch" % (value,)
    # Invalid values: raise ValueError
    for value in ("maybe", "nope", "2"):
        monkeypatch.setenv("NETIMPS_SOCKET_PATCH", value)
        with pytest.raises(ValueError, match="NETIMPS_SOCKET_PATCH must be one of"):
            _patch_requested()
    # Old variable: raise ValueError
    monkeypatch.delenv("NETIMPS_SOCKET_PATCH", raising=False)
    monkeypatch.setenv("NETIMPS_NO_SOCKET_PATCH", "1")
    with pytest.raises(
        ValueError, match="NETIMPS_NO_SOCKET_PATCH is no longer supported"
    ):
        _patch_requested()


# --------------------------------------------------------------------------- #
# The Winsock backend itself                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(not IS_WINDOWS, reason="_winsock is Windows-only by construction")
def test_winsock_alignment_and_header_size():
    """The cmsg data offset is pointer-aligned, not 4-aligned.

    Worth pinning because the Linux value a reader might assume happens to work
    on 32-bit and silently misparses everything on 64-bit.
    """
    # Private: the Windows ctypes layouts are private and checked by size off Windows.
    from netimps import _winsock
    from netimps._winsock import _abi, _cmsg

    import ctypes

    assert _abi._ALIGN == ctypes.sizeof(ctypes.c_void_p)
    # WSACMSGHDR is {SIZE_T len; INT level; INT type}.
    assert _abi._CMSGHDR_SIZE == ctypes.sizeof(ctypes.c_size_t) + 2 * ctypes.sizeof(
        ctypes.c_int
    )
    assert _winsock.CMSG_LEN(0) == _cmsg._align(_abi._CMSGHDR_SIZE)
    assert _winsock.CMSG_SPACE(4) >= _winsock.CMSG_LEN(4)
    assert _winsock.available() is True


@pytest.mark.skipif(not IS_WINDOWS, reason="_winsock is Windows-only by construction")
def test_winsock_control_parser_stops_at_the_buffer_end():
    """A header claiming more than the buffer holds truncates the walk.

    Fed a deliberately lying length, because that is exactly what Winsock does
    and the parser is the last line of defence against indexing past the
    allocation.
    """
    # Private: the Windows ctypes layouts are private and checked by size off Windows.
    from netimps import _winsock
    from netimps._winsock import _abi, _cmsg

    import ctypes

    # Built from the real struct rather than a format string: the header mixes
    # SIZE_T with INT, which `struct` cannot express portably in standard mode.
    header = _abi._WSACMSGHDR(
        cmsg_len=_winsock.CMSG_LEN(4), cmsg_level=socket.IPPROTO_IP, cmsg_type=19
    )
    buffer = bytes(
        bytearray(ctypes.string_at(ctypes.byref(header), ctypes.sizeof(header)))
    )
    payload = b"\x7f\x00\x00\x01"
    padded = buffer + payload.ljust(
        _cmsg._align(_abi._CMSGHDR_SIZE) - len(buffer) + 4, b"\x00"
    )

    # Honest buffer: the one cmsg parses.
    parsed = _cmsg._parse_control(padded, len(padded))
    assert len(parsed) == 1
    assert parsed[0][0] == socket.IPPROTO_IP and parsed[0][1] == 19

    # Lying length: Winsock really does report more than it wrote, so the parser
    # must clamp to the allocation instead of indexing past it.
    clamped = _cmsg._parse_control(padded, 4096)
    assert all(len(data) <= len(padded) for _, _, data in clamped)

    # A header claiming less than its own size stops the walk rather than looping.
    short = _abi._WSACMSGHDR(cmsg_len=1, cmsg_level=0, cmsg_type=0)
    short_bytes = ctypes.string_at(ctypes.byref(short), ctypes.sizeof(short))
    assert _cmsg._parse_control(bytes(short_bytes), len(short_bytes)) == []


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
    from netimps import UDPEndpoint, bind

    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(5.0)
    endpoint = UDPEndpoint(bind("0.0.0.0", 0))
    try:
        if not endpoint.has_src_pinning:
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


# --------------------------------------------------------------------------- #
# The os.sysconf shim -- subprocess tests, because order matters               #
# --------------------------------------------------------------------------- #

#: Every check here spawns a **fresh interpreter**. In-process tests cannot see
#: these bugs: by the time a test body runs, pytest has already imported asyncio
#: (verified) so `_HAS_SENDMSG` was decided before netimps was imported at all,
#: and the import order that breaks is the one a plain script uses.
_FRESH = [sys.executable, "-c"]


def _fresh(code, env=None):
    """Run *code* in a new interpreter and return (returncode, stdout, stderr)."""
    import subprocess

    full_env = dict(os.environ)
    full_env.pop("NETIMPS_SOCKET_PATCH", None)
    full_env.pop("NETIMPS_NO_SOCKET_PATCH", None)
    # The child does not inherit sys.path, and netimps may be reachable only
    # through it (a bare checkout with PYTHONPATH=src rather than an install).
    # Without this the subprocess fails with ModuleNotFoundError and the test
    # reads as a netimps bug.
    full_env["PYTHONPATH"] = os.pathsep.join(path for path in sys.path if path)
    if env:
        full_env.update(env)
    result = subprocess.run(
        _FRESH + [code], capture_output=True, text=True, env=full_env, timeout=120
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def test_importing_netimps_does_not_break_import_asyncio():
    """The regression that shipped: `import netimps; import asyncio` crashed.

    CPython's asyncio/selector_events does, at import time::

        _HAS_SENDMSG = hasattr(socket.socket, 'sendmsg')
        if _HAS_SENDMSG:
            try: SC_IOV_MAX = os.sysconf('SC_IOV_MAX')
            except OSError: _HAS_SENDMSG = False

    `sendmsg` and `os.sysconf` are both POSIX and have always travelled
    together, so that `hasattr` is a sound POSIX proxy -- until the patch makes
    `sendmsg` exist where `os.sysconf` does not. The guard catches only
    `OSError`, so the `AttributeError` escaped and the import died.
    """
    code = "import netimps; import asyncio; print('ok')"
    rc, out, err = _fresh(code)
    assert rc == 0, "import netimps then asyncio failed:\n%s" % err
    assert out == "ok"


def test_the_other_stdlib_sysconf_callers_still_work():
    """No single exception type satisfies all three, hence the per-name shim.

    Measured: raising OSError for every name rescues asyncio and breaks
    ProcessPoolExecutor, which catches only (AttributeError, ValueError);
    raising ValueError or AttributeError for every name does the reverse. So
    SC_IOV_MAX returns a value and everything else raises ValueError.
    """
    code = (
        "import netimps\n"
        "from concurrent.futures.process import _check_system_limits\n"
        "try: _check_system_limits()\n"
        "except NotImplementedError: pass\n"
        "import multiprocessing.util as mu\n"
        "assert isinstance(mu.MAXFD, int), mu.MAXFD\n"
        "print('ok')\n"
    )
    rc, out, err = _fresh(code)
    assert rc == 0, "a stdlib sysconf caller broke:\n%s" % err
    assert out == "ok"


def test_unknown_sysconf_names_raise_valueerror():
    """What POSIX does for an unrecognised name, and what the other two catch."""
    if not IS_WINDOWS:
        pytest.skip("the shim only installs where os.sysconf is absent")
    import os as _os

    assert netimps.is_socket_patched()
    assert _os.sysconf("SC_IOV_MAX") > 0
    with pytest.raises(ValueError):
        _os.sysconf("SC_NPROCESSORS_ONLN")
    with pytest.raises(ValueError):
        _os.sysconf("not-a-name")


def test_sc_open_max_is_the_descriptor_table_the_platform_has():
    """A library that reads ``SC_OPEN_MAX`` behind ``hasattr(os, "sysconf")``
    got a ``ValueError`` and failed every session.

    The number is measured, not taken from the module: descriptors are opened
    until the C runtime refuses one.
    """
    if not IS_WINDOWS:
        pytest.skip("the shim only installs where os.sysconf is absent")
    import errno
    import os as _os

    assert netimps.is_socket_patched()
    opened = []
    try:
        with pytest.raises(OSError) as refused:
            while True:
                opened.append(_os.open(_os.devnull, _os.O_RDONLY))
        highest = max(opened)
    finally:
        for descriptor in opened:
            _os.close(descriptor)
    assert refused.value.errno == errno.EMFILE
    assert _os.sysconf("SC_OPEN_MAX") == highest + 1
    assert "SC_OPEN_MAX" in _os.sysconf_names


def test_iov_max_is_reportable_and_tunable():
    """1024 is a choice, not a measurement -- so it is a parameter.

    Windows reports no buffer-count limit anywhere (no IOV-like socket name,
    and 1048576 buffers in one WSASend were accepted), and the system limit is
    not settable on POSIX either: Linux's is `#define UIO_MAXIOV 1024` in
    linux/uio.h with no sysctl and no /proc entry.
    """
    if not IS_WINDOWS:
        pytest.skip("the shim only installs where os.sysconf is absent")
    import os as _os

    assert _os.sysconf("SC_IOV_MAX") == 1024
    try:
        netimps.patch_socket_module(iov_max=4096)
        assert _os.sysconf("SC_IOV_MAX") == 4096
        assert _os.sysconf_names["SC_IOV_MAX"] == 4096
    finally:
        netimps.patch_socket_module(False)
        netimps.patch_socket_module()
    # Unpatching resets it, so a later install does not inherit the tuning.
    assert _os.sysconf("SC_IOV_MAX") == 1024
    with pytest.raises(ValueError, match="at least 1"):
        netimps.patch_socket_module(iov_max=0)


def test_sysconf_is_installed_and_removed_with_the_socket_names():
    """One mechanism: os.sysconf is needed only because sendmsg was patched."""
    if not IS_WINDOWS:
        pytest.skip("nothing to install where the platform has both")
    import os as _os

    # Private: the socket patch and control-message sizing are not public.
    from netimps._msg import _patch

    assert "os.sysconf" in _patch._installed
    removed = netimps.patch_socket_module(False)
    try:
        assert "os.sysconf" in removed
        assert not hasattr(_os, "sysconf")
        assert not hasattr(socket.socket, "sendmsg")
    finally:
        netimps.patch_socket_module()
    assert hasattr(_os, "sysconf") and hasattr(socket.socket, "sendmsg")


def test_opting_out_leaves_both_modules_untouched():
    code = (
        "import netimps, os, socket\n"
        "assert not netimps.is_socket_patched()\n"
        "assert not hasattr(socket.socket, 'recvmsg')\n"
        "assert not hasattr(os, 'sysconf')\n"
        "import asyncio\n"
        "print('ok')\n"
    )
    if not IS_WINDOWS:
        pytest.skip("on POSIX both names are native, so there is nothing to opt out of")
    rc, out, err = _fresh(code, env={"NETIMPS_SOCKET_PATCH": "0"})
    assert rc == 0, err
    assert out == "ok"


# --------------------------------------------------------------------------- #
# The patched methods reshape the payload; netimps' own functions do not        #
# --------------------------------------------------------------------------- #


def _one_pktinfo(ancdata, ip_pktinfo):
    found = [
        cd for lv, ty, cd in ancdata if lv == socket.IPPROTO_IP and ty == ip_pktinfo
    ]
    return found[0] if found else None


def _recv_both_ways(dest="127.0.0.1", bind_to="0.0.0.0"):
    """One datagram, captured through netimps.recvmsg and through sock.recvmsg."""
    import select

    # Private: platform constants for the pktinfo options; no decision is read from it.
    from netimps import _pktinfo

    option = _pktinfo._IP_PKTINFO
    if option is None:
        pytest.skip("no IPv4 IP_PKTINFO on this platform")
    out = {}
    for label in ("native", "patched"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, option, 1)
        except OSError:
            sock.close()
            pytest.skip("IP_PKTINFO refused on this socket")
        sock.bind((bind_to, 0))
        port = sock.getsockname()[1]
        sock.settimeout(5.0)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            tx.sendto(b"probe", (dest, port))
        except OSError as exc:
            tx.close()
            sock.close()
            pytest.skip("cannot send to %s: %s" % (dest, exc))
        tx.close()
        if not select.select([sock], [], [], 3)[0]:
            sock.close()
            pytest.skip("no delivery to %s here" % (dest,))
        if label == "native":
            _d, anc, _f, _a = netimps.recvmsg(sock, 1500, netimps.CMSG_SPACE(64))
        else:
            _d, anc, _f, _a = sock.recvmsg(1500, socket.CMSG_SPACE(64))
        out[label] = _one_pktinfo(anc, option)
        sock.close()
    return out


@pytest.mark.skipif(not IS_WINDOWS, reason="only Windows has a layout to reshape")
def test_the_patched_recvmsg_returns_the_posix_layout():
    """The patched method impersonates POSIX in layout as well as in name.

    Installing the name without the layout is a half-impersonation, and the
    missing half is the one that makes POSIX-shaped parsing code wrong: it
    unpacks `=I4s4s` from an 8-byte buffer and gets `struct.error`, which is not
    an OSError and so escapes a receive handler.
    """
    captured = _recv_both_ways()
    native, patched = captured["native"], captured["patched"]
    assert native is not None and patched is not None

    # Native: Windows IN_PKTINFO, 8 bytes, address first.
    assert len(native) == 8
    address, index = struct.unpack("=4sI", native)
    assert socket.inet_ntoa(address) == "127.0.0.1" and index > 0

    # Patched: POSIX in_pktinfo, 12 bytes, index first.
    assert len(patched) == 12
    pidx, spec_dst, paddr = struct.unpack("=I4s4s", patched)
    assert pidx == index
    assert socket.inet_ntoa(paddr) == "127.0.0.1"
    assert spec_dst == b"\x00\x00\x00\x00", "spec_dst must be zero-filled"


@pytest.mark.skipif(not IS_WINDOWS, reason="only Windows has a layout to reshape")
def test_the_normalized_bytes_are_byte_identical_to_macos():
    """Not a fourth behaviour -- an existing platform's.

    macOS, measured on a CI runner for a unicast to 127.0.0.1 on interface 1,
    produces exactly this payload: ifindex first, spec_dst zero-filled, then the
    destination. Pinning the hex keeps the claim honest.
    """
    captured = _recv_both_ways()
    patched = captured["patched"]
    index = struct.unpack("=I4s4s", patched)[0]
    expected = struct.pack("=I4s4s", index, b"\x00" * 4, socket.inet_aton("127.0.0.1"))
    assert patched == expected
    if index == 1:
        assert patched.hex() == "01000000000000007f000001"


@pytest.mark.skipif(not IS_WINDOWS, reason="only Windows has a layout to reshape")
def test_spec_dst_is_zero_rather_than_a_copy_of_the_destination(
    allow_off_host_destination,
):
    """Copying `ipi_addr` into `ipi_spec_dst` would be a plausible wrong address.

    Measured on Linux: for a broadcast the two fields genuinely differ --
    spec_dst is the local interface address while addr is 255.255.255.255. Code
    that reads spec_dst does so precisely to get the local address, so handing it
    the broadcast address would silently corrupt the one field it wanted. Zero is
    visibly wrong; 255.255.255.255 is not.

    The destination has to be the limited broadcast for the kernel to report
    it, so one datagram goes out on the local segment.
    """
    captured = _recv_both_ways(dest="255.255.255.255")
    patched = captured["patched"]
    assert len(patched) == 12
    _idx, spec_dst, addr = struct.unpack("=I4s4s", patched)
    assert socket.inet_ntoa(addr) == "255.255.255.255"
    assert spec_dst == b"\x00" * 4
    assert spec_dst != addr, "spec_dst must not be a copy of the destination"


def test_netimps_recvmsg_always_reports_the_platforms_own_bytes():
    """The split that makes the reshaping defensible.

    `netimps.recvmsg` is this package's own API and reports what the kernel
    said; only the impersonation reshapes. `UDPEndpoint` depends on this, since
    it calls `_msg` directly and carries its own per-platform layout table.
    """
    # Private: platform constants for the pktinfo options; no decision is read from it.
    from netimps import _pktinfo

    captured = _recv_both_ways()
    native = captured["native"]
    expected_size = struct.calcsize(_pktinfo._PKTINFO_V4)
    assert (
        len(native) == expected_size
    ), "netimps.recvmsg must agree with _pktinfo's layout table for this platform"


@pytest.mark.skipif(
    IS_WINDOWS, reason="POSIX installs nothing, so there is nothing to reshape"
)
def test_on_posix_the_two_paths_are_identical():
    captured = _recv_both_ways()
    assert captured["native"] == captured["patched"]
    assert len(captured["native"]) == 12


@pytest.mark.skipif(not IS_WINDOWS, reason="only Windows accepts two layouts")
def test_the_patched_sendmsg_accepts_either_layout():
    """So a caller can round-trip what the patched recvmsg handed it."""
    # Private: platform constants for the pktinfo options; no decision is read from it.
    from netimps import _pktinfo

    option = _pktinfo._IP_PKTINFO
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(5.0)
    target = peer.getsockname()

    posix_form = struct.pack("=I4s4s", 0, socket.inet_aton("127.0.0.1"), b"\x00" * 4)
    native_form = struct.pack("=4sI", socket.inet_aton("127.0.0.1"), 0)

    for label, payload in (("posix", posix_form), ("native", native_form)):
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.bind(("0.0.0.0", 0))
        try:
            sent = sender.sendmsg(
                [b"shaped-" + label.encode()],
                [(socket.IPPROTO_IP, option, payload)],
                0,
                target,
            )
            assert sent > 0
            data, observed = peer.recvfrom(100)
            assert data == b"shaped-" + label.encode()
            assert observed[0] == "127.0.0.1", (
                "%s layout did not pin the source" % label
            )
        finally:
            sender.close()
    peer.close()


@pytest.mark.skipif(not IS_WINDOWS, reason="only Windows reshapes")
def test_a_round_trip_through_the_patched_methods():
    """Receive through the patched method, send the same cmsg straight back."""
    # Private: platform constants for the pktinfo options; no decision is read from it.
    from netimps import _pktinfo

    option = _pktinfo._IP_PKTINFO
    captured = _recv_both_ways()
    patched = captured["patched"]

    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    peer.settimeout(5.0)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.bind(("0.0.0.0", 0))
    try:
        # The bytes that came out of recvmsg go straight into sendmsg.
        sender.sendmsg(
            [b"round-trip"],
            [(socket.IPPROTO_IP, option, patched)],
            0,
            peer.getsockname(),
        )
        data, _observed = peer.recvfrom(100)
        assert data == b"round-trip"
    finally:
        sender.close()
        peer.close()


@pytest.mark.parametrize(
    "env, patched",
    [
        ({}, True),
        ({"NETIMPS_SOCKET_PATCH": "1"}, True),
        ({"NETIMPS_SOCKET_PATCH": "TRUE"}, True),
        ({"NETIMPS_SOCKET_PATCH": "0"}, False),
        ({"NETIMPS_SOCKET_PATCH": "Off"}, False),
    ],
)
def test_the_variable_decides_the_patch_at_a_real_import(env, patched):
    """The predicate is tested above; this is the import itself, in a fresh
    interpreter, because the decision is made once per process. Off Windows the
    patch has nothing to install, so the answer there is always no."""
    code = "import netimps; print(netimps.is_socket_patched())"
    returncode, out, err = _fresh(code, env)
    assert returncode == 0, err
    assert out == str(patched and IS_WINDOWS)


@pytest.mark.parametrize(
    "env, named",
    [
        ({"NETIMPS_SOCKET_PATCH": "flase"}, "NETIMPS_SOCKET_PATCH"),
        ({"NETIMPS_NO_SOCKET_PATCH": "1"}, "NETIMPS_NO_SOCKET_PATCH"),
    ],
)
def test_a_value_that_cannot_be_read_stops_the_import(env, named):
    """A typo, or the variable with the opposite sense, must not pass for a
    choice: either would install the patch for someone who asked for it to be
    left out. The error names the variable."""
    returncode, out, err = _fresh("import netimps", env)
    assert returncode != 0
    assert "ValueError" in err and named in err


# --------------------------------------------------------------------------- #
# A second import, a failed patch call, a stream socket                        #
# --------------------------------------------------------------------------- #


def test_a_second_import_of_the_package_decodes_and_reports_the_same():
    """A reloader or a test runner imports the package again in one process.

    The second copy captured the first copy's installed `recvmsg` as the native
    one, so on Windows it reshaped the control data twice: the destination came
    out as `1.0.0.0` with index 0, and `is_socket_patched()` said False while
    the method was still on `socket.socket`.
    """
    code = (
        "import sys, socket\n"
        "import netimps\n"
        "def look():\n"
        "    r = netimps.bind('127.0.0.1', 0)\n"
        "    ep = netimps.UDPEndpoint(r)\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "    s.sendto(b'x', r.getsockname())\n"
        "    r.settimeout(5)\n"
        "    d = ep.recv()\n"
        "    ep.close(); s.close()\n"
        "    return str(d.destination), d.interface_index != 0, "
        "netimps.is_socket_patched(), hasattr(socket.socket, 'recvmsg')\n"
        "first = look()\n"
        "for n in [n for n in sys.modules if n == 'netimps' or n.startswith('netimps.')]:\n"
        "    del sys.modules[n]\n"
        "import netimps\n"
        "print(first == look(), first)\n"
    )
    rc, out, err = _fresh(code)
    assert rc == 0, err
    assert out.startswith("True"), out


def test_a_second_import_can_remove_what_the_first_installed():
    if not IS_WINDOWS:
        pytest.skip("POSIX installs nothing, so there is nothing to adopt")
    code = (
        "import sys, socket\n"
        "import netimps\n"
        "for n in [n for n in sys.modules if n == 'netimps' or n.startswith('netimps.')]:\n"
        "    del sys.modules[n]\n"
        "import netimps\n"
        "assert netimps.is_socket_patched()\n"
        "netimps.patch_socket_module(False)\n"
        "print(hasattr(socket.socket, 'recvmsg'), netimps.is_socket_patched())\n"
    )
    rc, out, err = _fresh(code)
    assert rc == 0, err
    assert out == "False False"


def test_a_patch_call_that_raises_changes_nothing():
    """`iov_max=0` raised `ValueError` after the patch was already installed."""
    was_patched = netimps.is_socket_patched()
    netimps.patch_socket_module(False)
    try:
        with pytest.raises(ValueError):
            netimps.patch_socket_module(True, iov_max=0)
        assert netimps.is_socket_patched() is False
        assert not (IS_WINDOWS and hasattr(socket.socket, "recvmsg"))
    finally:
        if was_patched:
            netimps.patch_socket_module()


def test_recvmsg_works_on_a_stream_socket():
    """`WSARecvMsg` refuses a stream socket with `WSAEINVAL`; the send side
    already picks `WSASend` for one, and the receive side picks `WSARecv`."""
    a, b = socket.socketpair()
    try:
        a.settimeout(5)
        b.sendall(b"hello")
        data, ancdata, flags, _address = netimps.recvmsg(a, 100, 64)
        assert data == b"hello"
        assert ancdata == []
        assert flags == 0
        a.settimeout(0.3)
        with pytest.raises(socket.timeout):
            netimps.recvmsg(a, 100)
        b.close()
        a.settimeout(5)
        assert netimps.recvmsg(a, 100)[0] == b""
    finally:
        a.close()
        b.close()


# --------------------------------------------------------------------------- #
# The receive buffer                                                          #
# --------------------------------------------------------------------------- #


def _datagram_pair():
    server = netimps.bind("127.0.0.1", 0)
    server.settimeout(5)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.connect(server.getsockname())
    return server, client


def test_successive_receives_each_return_their_own_bytes():
    server, client = _datagram_pair()
    try:
        client.send(b"the-first-datagram")
        first = netimps.recvmsg(server, 65536)[0]
        client.send(b"second")
        second = netimps.recvmsg(server, 65536)[0]
        assert (first, second) == (b"the-first-datagram", b"second")
    finally:
        server.close()
        client.close()


def test_a_smaller_bufsize_after_a_larger_one_still_truncates():
    server, client = _datagram_pair()
    try:
        client.send(b"x" * 200)
        assert netimps.recvmsg(server, 65536)[0] == b"x" * 200
        client.send(bytes(range(100)))
        data, _anc, flags, _sender = netimps.recvmsg(server, 10)
        assert data == bytes(range(10))
        assert flags & getattr(socket, "MSG_TRUNC", 0)
    finally:
        server.close()
        client.close()


def test_threads_receiving_at_once_each_get_their_own_datagrams():
    import threading

    rounds = 200
    failures = []

    def receive(server, client, fill):
        try:
            for size in range(1, rounds + 1):
                client.send(fill * size)
                got = netimps.recvmsg(server, 65536)[0]
                if got != fill * size:
                    failures.append((fill, size, got[:16]))
                    return
        except Exception as exc:
            failures.append((fill, repr(exc)))

    pairs = [_datagram_pair() for _ in range(4)]
    threads = [
        threading.Thread(target=receive, args=(server, client, bytes([65 + n])))
        for n, (server, client) in enumerate(pairs)
    ]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        assert not failures
        assert not any(thread.is_alive() for thread in threads)
    finally:
        for server, client in pairs:
            server.close()
            client.close()


@pytest.mark.skipif(not IS_WINDOWS, reason="_winsock is Windows-only by construction")
def test_windows_receives_do_not_allocate_a_payload_buffer_each():
    """A fresh 64 KiB buffer is faulted in page by page on every receive."""
    import ctypes

    # Private: the Windows receive path's allocation seam.
    from netimps._winsock import _calls

    allocated = []

    class _Counting:
        @staticmethod
        def create_string_buffer(init, size=None):
            allocated.append(init if size is None else size)
            return ctypes.create_string_buffer(init, size)

        def __getattr__(self, name):
            return getattr(ctypes, name)

    server, client = _datagram_pair()
    real = _calls._ctypes
    _calls._ctypes = _Counting()
    try:
        for _ in range(5):
            client.send(b"datagram")
            assert netimps.recvmsg(server, 65536)[0] == b"datagram"
    finally:
        _calls._ctypes = real
        server.close()
        client.close()
    assert allocated.count(65536) <= 1


@pytest.mark.skipif(not IS_WINDOWS, reason="_winsock is Windows-only by construction")
def test_windows_receive_started_inside_another_takes_its_own_buffer():
    """A signal handler or a finalizer can receive between the call and the copy."""
    import ctypes

    # Private: the Windows receive path's allocation seam.
    from netimps._winsock import _calls

    outer, outer_kept = _calls._take_buffer(1024)
    try:
        inner, inner_kept = _calls._take_buffer(1024)
        assert outer_kept and not inner_kept
        assert ctypes.addressof(outer) != ctypes.addressof(inner)
    finally:
        _calls._release_buffer(outer_kept)
    again, again_kept = _calls._take_buffer(1024)
    _calls._release_buffer(again_kept)
    assert again_kept and ctypes.addressof(again) == ctypes.addressof(outer)


@pytest.mark.skipif(not IS_WINDOWS, reason="_winsock is Windows-only by construction")
def test_windows_receive_keeps_no_buffer_larger_than_a_datagram():
    # Private: the Windows receive path's allocation seam.
    from netimps._winsock import _calls

    large, kept = _calls._take_buffer(_calls._KEPT_BUFFER_MAX + 1)
    assert not kept and len(large) == _calls._KEPT_BUFFER_MAX + 1
