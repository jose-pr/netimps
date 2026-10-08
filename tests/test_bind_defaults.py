"""What ``bind()`` does when told nothing: family, ICMP errors, error text, buffers.

Each test pins the difference from what a caller wrote by hand around the old
defaults: computing the family before every call, passing ``connreset=False`` on
every datagram bind, and joining ``bind_error_hint`` onto the exception.

Also here: ``bind_error_hint``, the one exception type for a taken port,
resistance to a hijacked port, UDP port sharing, and the address types ``bind``
accepts.
"""

import errno
import ipaddress
import logging
import os
import socket
import time

import pytest

import netimps
from netimps import AddressInUseError, bind, bind_error_hint, set_buffer_size


def _closed_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _ipv6_loopback_works() -> bool:
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        probe.bind(("::1", 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


requires_ipv6 = pytest.mark.skipif(
    not _ipv6_loopback_works(), reason="this host cannot bind ::1"
)


# --------------------------------------------------------------------------- #
# family                                                                       #
# --------------------------------------------------------------------------- #


@requires_ipv6
def test_an_ipv6_literal_is_bound_as_ipv6_without_a_family():
    """A caller used to compute ``family=`` from the address before every call.

    The old default was ``AF_INET``, so ``bind("::1")`` failed with a
    ``gaierror`` from the socket layer.
    """
    sock = bind("::1", 0)
    try:
        assert sock.family == socket.AF_INET6
        assert sock.getsockname()[0] == "::1"
    finally:
        sock.close()


@requires_ipv6
def test_an_ipv6_address_object_and_a_stream_socket_infer_too():
    sock = bind(netimps.IPv6Address("::1"), 0, kind=socket.SOCK_STREAM, listen=1)
    try:
        assert sock.family == socket.AF_INET6
    finally:
        sock.close()


@pytest.mark.parametrize("address", ["", "127.0.0.1", "0.0.0.0", "localhost"])
def test_the_wildcard_an_ipv4_literal_and_an_ipv4_name_stay_ipv4(address):
    """The wildcard says nothing about the family, so it keeps meaning IPv4.

    ``localhost`` has both families on most hosts; it keeps binding as IPv4,
    as it did when the default was a constant.
    """
    sock = bind(address, 0)
    try:
        assert sock.family == socket.AF_INET
    finally:
        sock.close()


def test_an_explicit_family_still_wins_over_inference():
    if not socket.has_ipv6:
        pytest.skip("no IPv6 in this interpreter")
    sock = bind("", 0, family=socket.AF_INET6)
    try:
        assert sock.family == socket.AF_INET6
    finally:
        sock.close()


@requires_ipv6
def test_an_interface_with_an_ipv6_address_gives_an_ipv6_socket():
    loopback = next((i for i in netimps.get_interfaces() if i.is_loopback), None)
    if loopback is None or not any(ip.ip.version == 6 for ip in loopback.ips):
        pytest.skip("no loopback interface with an IPv6 address")
    sock = bind(port=0, interface=netimps.IPv6Address("::1"))
    try:
        assert sock.family == socket.AF_INET6
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# connreset                                                                    #
# --------------------------------------------------------------------------- #


def _what_a_receive_does_after_an_unreachable_send(sock: socket.socket) -> str:
    sock.settimeout(1.0)
    sock.sendto(b"x", ("127.0.0.1", _closed_udp_port()))
    time.sleep(0.2)
    try:
        sock.recvfrom(100)
    except ConnectionResetError:
        return "reset"
    except socket.timeout:
        return "quiet"
    return "data"


def test_an_unconnected_udp_socket_from_bind_ignores_an_icmp_unreachable():
    """A server loop died on a packet some other host did not want.

    Both protocol libraries passed ``connreset=False`` on every datagram bind.
    Ground truth comes from the platform: a bare stdlib socket tells whether
    this host reports the error at all (Windows does, POSIX does not for an
    unconnected socket), and ``bind()`` must then not.
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw.bind(("127.0.0.1", 0))
    try:
        platform_reports = (
            _what_a_receive_does_after_an_unreachable_send(raw) == "reset"
        )
    finally:
        raw.close()

    sock = bind("127.0.0.1", 0)
    try:
        assert _what_a_receive_does_after_an_unreachable_send(sock) == "quiet"
    finally:
        sock.close()

    kept = bind("127.0.0.1", 0, connreset=True)
    try:
        expected = "reset" if platform_reports else "quiet"
        assert _what_a_receive_does_after_an_unreachable_send(kept) == expected
    finally:
        kept.close()


def test_connreset_false_still_forces_it_off():
    sock = bind("127.0.0.1", 0, connreset=False)
    try:
        assert _what_a_receive_does_after_an_unreachable_send(sock) == "quiet"
    finally:
        sock.close()


def test_a_stream_socket_is_not_touched_by_the_default(monkeypatch):
    """The default switches ``SIO_UDP_CONNRESET`` off for datagrams only.

    A stream socket has nothing to observe, so the call is watched instead:
    there is no public route to "was this option touched".
    """
    calls = []
    monkeypatch.setattr(
        netimps._sockets._bind,
        "disable_connreset",
        lambda sock: calls.append(sock.type),
    )
    bind("127.0.0.1", 0, kind=socket.SOCK_STREAM).close()
    assert calls == []
    bind("127.0.0.1", 0).close()
    assert calls == [socket.SOCK_DGRAM]


# --------------------------------------------------------------------------- #
# error text                                                                   #
# --------------------------------------------------------------------------- #


def test_an_in_use_bind_carries_the_hint_in_its_message():
    """Callers joined ``bind_error_hint`` onto the exception themselves."""
    holder = bind("127.0.0.1", 0, reuse_address=False)
    port = holder.getsockname()[1]
    try:
        with pytest.raises(AddressInUseError) as caught:
            bind("127.0.0.1", port, reuse_address=False)
    finally:
        holder.close()
    hint = bind_error_hint(caught.value.__cause__, port)
    assert hint and hint in str(caught.value)


def test_another_failure_keeps_its_class_and_gains_the_hint():
    with pytest.raises(OSError) as caught:
        bind("192.0.2.99", 9)  # not a local address
    hint = bind_error_hint(caught.value.__cause__, 9)
    assert hint, "this host gave an error the hint does not recognise"
    assert hint in str(caught.value)
    assert not isinstance(caught.value, AddressInUseError)
    assert caught.value.errno == caught.value.__cause__.errno
    assert type(caught.value) is type(caught.value.__cause__)


# --------------------------------------------------------------------------- #
# set_buffer_size                                                              #
# --------------------------------------------------------------------------- #


class _StingySocket:
    """Grants half of any buffer it is asked for, as a capped kernel does."""

    def __init__(self):
        self.values = {socket.SO_RCVBUF: 1000, socket.SO_SNDBUF: 1000}

    def getsockopt(self, level, option):
        return self.values[option]

    def setsockopt(self, level, option, value):
        self.values[option] = value // 2


@pytest.fixture
def no_shortfall_seen(monkeypatch):
    """Each test starts with no shortfall logged yet in this process."""
    # Private: the set of shortfalls already logged is process-wide.
    from netimps._sockets import _options

    monkeypatch.setattr(_options, "_warned_shortfalls", set())


def test_a_shortfall_is_logged_once_however_many_sockets_have_it(
    caplog, no_shortfall_seen
):
    """A server that opens a socket per transfer has one shortfall, not one per
    transfer: a warning for each drowned the log and said nothing new.

    The kernel agrees to a ``setsockopt`` and grants less; the stand-in does
    exactly that, since Windows grants 2 GiB and cannot show it.
    """
    with caplog.at_level(logging.WARNING, logger="netimps._sockets"):
        for _ in range(3):
            sock = _StingySocket()
            assert set_buffer_size(sock, receive=8000, send=8000) == (4000, 4000)
    records = [r for r in caplog.records if r.name == "netimps._sockets"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert "SO_RCVBUF" in records[0].getMessage()
    assert "8000" in records[0].getMessage()


def test_a_different_shortfall_is_logged_as_well(caplog, no_shortfall_seen):
    with caplog.at_level(logging.WARNING, logger="netimps._sockets"):
        set_buffer_size(_StingySocket(), receive=8000)
        set_buffer_size(_StingySocket(), receive=9000)
    records = [r for r in caplog.records if r.name == "netimps._sockets"]
    assert len(records) == 2
    assert "9000" in records[1].getMessage()


def test_no_warning_when_the_request_is_met(caplog):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with caplog.at_level(logging.DEBUG, logger="netimps"):
            granted = set_buffer_size(sock, receive=1024, send=1024)
        assert min(granted) >= 1024
    finally:
        sock.close()
    assert caplog.records == []


def test_the_library_installs_no_log_handler():
    import logging as stdlib_logging

    assert stdlib_logging.getLogger("netimps._sockets").handlers == []
    assert stdlib_logging.getLogger("netimps").handlers == []


IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# bind                                                                        #
# --------------------------------------------------------------------------- #


def test_bind_datagram_defaults():
    sock = bind("127.0.0.1", 0)
    try:
        host, port = sock.getsockname()
        assert host == "127.0.0.1" and port > 0
        if os.name == "nt":
            # SO_REUSEADDR does NOT mean the same thing here: on Windows it lets
            # another process bind a port that is already live, so the default
            # asks for exclusivity instead. Asserting SO_REUSEADDR on this
            # platform was asserting that the port could be stolen.
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE)
            assert not sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        else:
            # And POSIX gets NEITHER for a datagram socket. This used to assert
            # SO_REUSEADDR, which was asserting that the port could be stolen on
            # Linux too: TIME_WAIT is a TCP concept, so on UDP the option's only
            # remaining effect there is to permit duplicate bindings of live
            # sockets -- measured, the second binder received the datagram.
            assert not sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
    finally:
        sock.close()


def test_bind_does_not_leave_a_listener_stealable():
    """The property the option is there for, asserted directly.

    On Windows a second socket setting SO_REUSEADDR could take a live port out
    from under a `netimps.bind()` listener; a plain stdlib bind was refused.
    This is that reproduction, turned into a regression test.
    """
    server = bind("127.0.0.1", 0, kind=socket.SOCK_STREAM, listen=1)
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


def test_bind_stream_with_listen():
    sock = bind("127.0.0.1", 0, kind=socket.SOCK_STREAM, listen=5)
    try:
        # A listening socket accepts connections; a merely-bound one does not.
        client = socket.create_connection(sock.getsockname(), timeout=2.0)
        client.close()
    finally:
        sock.close()


def test_bind_sets_broadcast():
    sock = bind("", 0, broadcast=True)
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST)
    finally:
        sock.close()


def test_bind_reuse_port_is_a_noop_where_absent():
    """SO_REUSEPORT does not exist on Windows -- it must not raise there."""
    sock = bind("127.0.0.1", 0, reuse_port=True)
    try:
        option = getattr(socket, "SO_REUSEPORT", None)
        if option is not None:
            assert sock.getsockopt(socket.SOL_SOCKET, option)
    finally:
        sock.close()


def test_bind_applies_extra_options():
    sock = bind(
        "127.0.0.1",
        0,
        options=[(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)],
    )
    try:
        # Kernels may round the value up, so assert it took effect at all.
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) > 0
    finally:
        sock.close()


def test_bind_closes_socket_on_failure():
    """A failed bind must not leak the socket it was configuring."""
    closed = []
    real = socket.socket

    class Tracking(real):
        def close(self):
            closed.append(True)
            super().close()

    original = netimps._sockets._bind._socket.socket
    netimps._sockets._bind._socket.socket = Tracking
    try:
        with pytest.raises(OSError):
            bind("192.0.2.99", 9)  # not a local address
    finally:
        netimps._sockets._bind._socket.socket = original
    assert closed, "socket was not closed after the failed bind"


def test_bind_unknown_interface_raises():
    with pytest.raises(ValueError, match="no interface named"):
        bind(port=0, interface="no-such-nic")


def test_bind_to_interface_uses_its_address():
    loopback = next((i for i in netimps.get_interfaces() if i.is_loopback), None)
    if loopback is None:  # pragma: no cover - host without a loopback entry
        pytest.skip("no loopback interface enumerated on this host")
    # The adapter's own pick, not a loopback address: WSL2's `lo` (measured 2026-10-09) also holds a
    # routable 10.255.255.254/32, which `primary_ip()` ranks first.
    sock = bind(port=0, interface=loopback)
    try:
        assert netimps.parse(sock.getsockname()[0]) == loopback.primary_ip().ip
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# bind_error_hint                                                             #
# --------------------------------------------------------------------------- #


def test_hint_for_permission_denied():
    hint = netimps.bind_error_hint(PermissionError(errno.EACCES, "denied"), 67)
    assert hint and "permission denied" in hint.lower()
    assert "1024" in hint  # the actionable part: privileged port


def test_hint_for_high_port_omits_privileged_note():
    hint = netimps.bind_error_hint(PermissionError(errno.EACCES, "denied"), 8080)
    assert hint and "1024" not in hint


def test_hint_for_address_in_use():
    exc = OSError(errno.EADDRINUSE, "in use")
    hint = netimps.bind_error_hint(exc, 8080)
    assert hint and "already in use" in hint


def test_hint_recognises_windows_error_codes():
    """Windows reports WinError 10013/10048, not the POSIX errnos."""
    in_use = OSError("in use")
    in_use.winerror = 10048
    assert "already in use" in (netimps.bind_error_hint(in_use, 80) or "")


@pytest.mark.parametrize("port", [67, 64514])
def test_wsaeaccess_is_not_a_privilege_problem(port):
    """WSAEACCES means the address is taken, not that you need elevation.

    Windows has no privileged-port concept -- any user may bind port 80 -- so
    reading 10013 as POSIX EACCES sends the reader after an elevation problem
    that cannot exist there. It actually means another socket holds the
    address exclusively, or a firewall or excluded port range refuses it.

    Python maps WSAEACCES to PermissionError with errno EACCES, which is why
    this must be tested before the POSIX branch: reported downstream as
    "permission denied binding port 64514" -- a privilege message about an
    unprivileged port -- and worked around by hand in a consuming package.
    """
    denied = OSError("denied")
    denied.winerror = 10013
    denied.errno = errno.EACCES
    hint = netimps.bind_error_hint(denied, port) or ""

    assert "in use, not privileged" in hint
    assert "1024" not in hint, "the privileged-port advice does not apply on Windows"
    assert "permission denied" not in hint.lower()


def test_posix_eacces_keeps_the_privileged_port_advice():
    """The POSIX reading stays intact -- there the advice is correct."""
    low = netimps.bind_error_hint(PermissionError(errno.EACCES, "denied"), 67) or ""
    assert "permission denied" in low.lower() and "1024" in low

    high = netimps.bind_error_hint(PermissionError(errno.EACCES, "denied"), 8080) or ""
    assert "permission denied" in high.lower() and "1024" not in high


def test_hint_returns_none_for_unrecognised():
    """Unknown failures keep their original message rather than a paraphrase."""
    assert netimps.bind_error_hint(OSError(errno.EPIPE, "broken pipe"), 80) is None
    assert netimps.bind_error_hint(ValueError("not an OSError")) is None


def test_hint_without_a_port():
    hint = netimps.bind_error_hint(OSError(errno.EADDRINUSE, "in use"))
    assert hint and "that port" in hint.lower()


# --------------------------------------------------------------------------- #
# bind() takes the package's usual loose union                                #
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


# --------------------------------------------------------------------------- #
# bind(reuse_address=False) cannot be hijacked                                #
# --------------------------------------------------------------------------- #


def _hijack_attempt(holder_address, thief_address, **bind_kwargs):
    """Bind a holder, then try to steal its port from *thief_address*."""
    import select

    holder = bind(holder_address, 0, **bind_kwargs)
    port = holder.getsockname()[1]
    thief = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    thief.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        try:
            thief.bind((thief_address, port))
        except OSError:
            return "refused"
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.sendto(b"who-gets-this", ("127.0.0.1", port))
        sender.close()
        ready, _, _ = select.select([holder, thief], [], [], 1.5)
        if thief in ready:
            return "stolen"
        if holder in ready:
            return "holder"
        return "lost"
    finally:
        thief.close()
        holder.close()


@pytest.mark.skipif(not IS_WINDOWS, reason="the takeover is a Windows behaviour")
@pytest.mark.parametrize("reuse_address", [False, True])
def test_a_wildcard_bind_cannot_be_hijacked_whatever_reuse_address_says(reuse_address):
    """`reuse_address=False` used to set nothing, and nothing is the unsafe state.

    Measured before the fix: a thief binding the more specific `127.0.0.1` with
    `SO_REUSEADDR` received the datagram while the holder on `0.0.0.0` got
    nothing and no error. So the flag that reads as "strictest" was the least
    strict setting available -- the careful caller got the unsafe behaviour,
    which is why this is parametrised over *both* values rather than only the
    one that was broken.
    """
    assert _hijack_attempt("0.0.0.0", "127.0.0.1", reuse_address=reuse_address) == (
        "refused"
    )


@pytest.mark.skipif(not IS_WINDOWS, reason="SO_EXCLUSIVEADDRUSE is Windows-only")
@pytest.mark.parametrize("reuse_address", [False, True])
def test_exclusive_use_is_set_for_both_values_of_reuse_address(reuse_address):
    """The mechanism behind the test above, pinned directly.

    On Windows this option's only effect is denying takeover, so setting it
    regardless costs nothing: there is no TIME_WAIT restart for UDP it could
    forbid, and for TCP it is already what `reuse_address=True` asked for.
    """
    sock = bind("0.0.0.0", 0, reuse_address=reuse_address)
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE) == 1
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
    finally:
        sock.close()


@pytest.mark.skipif(not IS_WINDOWS, reason="SO_EXCLUSIVEADDRUSE is Windows-only")
def test_allow_address_takeover_still_opts_into_the_unsafe_behaviour():
    """The escape hatch has to keep working, and keep being the only one."""
    sock = bind("0.0.0.0", 0, allow_address_takeover=True)
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 1
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE) == 0
    finally:
        sock.close()
    assert _hijack_attempt("0.0.0.0", "127.0.0.1", allow_address_takeover=True) != (
        "refused"
    )


@pytest.mark.skipif(IS_WINDOWS, reason="the POSIX half of the same flag")
@pytest.mark.parametrize("reuse_address", [False, True])
def test_on_posix_reuse_address_governs_so_reuseaddr_for_stream_sockets(reuse_address):
    """The Windows hijack fix must not change what POSIX does for TCP.

    Stream sockets specifically: this test used to bind the *default* datagram
    kind and assert the same thing, which encoded the very behaviour the Linux
    UDP-sharing finding was about. `TIME_WAIT` is a TCP concept, so a datagram
    socket never wanted this option -- see
    `test_a_default_udp_bind_does_not_set_so_reuseaddr`.
    """
    sock = bind("0.0.0.0", 0, kind=socket.SOCK_STREAM, reuse_address=reuse_address)
    try:
        value = sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        assert bool(value) is reuse_address
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# "the port is taken" is one exception type                                   #
# --------------------------------------------------------------------------- #


def _assert_stable_in_use(make_second, port_holder_kwargs=None):
    """Create a real port conflict and check the one type comes out of it.

    The conflict has to be built per platform, which is itself the finding's
    point. ``bind()`` defaults to ``reuse_address=True``, and on **Linux UDP**
    that sets ``SO_REUSEADDR``, which lets two sockets *share* the port -- so a
    second bind succeeds and there is nothing to raise. ``reuse_address=False``
    is what makes it a conflict there, while on Windows it is now the exclusive
    setting. (An earlier version of this test asserted a raise with the defaults
    and passed on Windows while failing on Linux for exactly this reason.)
    """
    holder = bind("127.0.0.1", 0, **(port_holder_kwargs or {"reuse_address": False}))
    port = holder.getsockname()[1]
    try:
        with pytest.raises(AddressInUseError) as caught:
            second = make_second(port)
            second.close()
        error = caught.value
        assert error.errno == errno.EADDRINUSE
        # The whole point: it must NOT say "privilege problem".
        assert not isinstance(error, PermissionError)
        # And it must stay catchable as what it has always been.
        assert isinstance(error, OSError)
        # The platform's own detail stays reachable.
        assert error.__cause__ is not None
        if IS_WINDOWS:
            assert getattr(error, "winerror", None) in (10013, 10048)
        return error
    finally:
        holder.close()


def test_an_in_use_bind_raises_one_stable_type():
    """Three shapes before, on the same situation: PermissionError/13 on 3.14,
    OSError/10013 on 3.9, OSError/10048 without the takeover flag."""
    _assert_stable_in_use(lambda port: bind("127.0.0.1", port, reuse_address=False))


@pytest.mark.skipif(
    not IS_WINDOWS, reason="on Linux UDP this flag shares the port instead of clashing"
)
def test_the_takeover_flag_also_yields_the_stable_type():
    """This is the row that used to be PermissionError on 3.14 -- the harmful one,
    since Windows has no privileged ports for the type to be describing."""
    error = _assert_stable_in_use(
        lambda port: bind("127.0.0.1", port, allow_address_takeover=True)
    )
    assert getattr(error, "winerror", None) == 10013


def test_the_in_use_error_carries_the_hint_as_its_message():
    error = _assert_stable_in_use(
        lambda port: bind("127.0.0.1", port, reuse_address=False)
    )
    assert str(error), "the message must not be empty"
    assert "use" in str(error).lower()


@pytest.mark.skipif(IS_WINDOWS, reason="Windows has no privileged ports")
def test_a_genuine_privilege_failure_is_left_alone():
    """POSIX EACCES on a low port is a real privilege problem, not an in-use one.

    Left exactly as it was: narrowing it to AddressInUseError would be the same
    class of misdiagnosis in the other direction.
    """
    if os.geteuid() == 0:
        pytest.skip("running as root, so a low port is permitted")
    with pytest.raises(PermissionError) as caught:
        bind("127.0.0.1", 80)
    assert not isinstance(caught.value, AddressInUseError)


def test_address_in_use_error_is_exported():
    assert netimps.AddressInUseError is AddressInUseError
    assert "AddressInUseError" in netimps.__all__
    assert issubclass(AddressInUseError, OSError)
    assert not issubclass(AddressInUseError, PermissionError)


# --------------------------------------------------------------------------- #
# bind()'s default refuses a second live UDP socket on the port               #
# --------------------------------------------------------------------------- #


def _second_bind_succeeds(port, **kwargs):
    try:
        second = bind("127.0.0.1", port, **kwargs)
    except OSError:
        return False
    second.close()
    return True


def test_a_duplicate_udp_bind_is_refused_under_the_defaults():
    """`SO_REUSEADDR` on a UDP socket buys nothing and costs the port.

    `TIME_WAIT` is a TCP concept, so on a datagram socket the option's one
    remaining effect on Linux is permitting duplicate bindings of *live* sockets.
    Measured on WSL before the fix: a second `bind()` of the same live UDP
    `addr:port` with default arguments succeeded and the datagram went to the
    **second** socket, with the holder getting no error. `socket(7)` is explicit
    that the exception is an active *listening* socket, and a UDP socket never
    listens -- so the guarantee the docs claimed here was true for TCP only.
    """
    holder = bind("127.0.0.1", 0)
    try:
        port = holder.getsockname()[1]
        assert not _second_bind_succeeds(
            port
        ), "a second live UDP bind must be refused under the defaults"
    finally:
        holder.close()


def test_a_default_udp_bind_does_not_set_so_reuseaddr():
    """The mechanism, pinned directly, so the fix cannot regress quietly."""
    sock = bind("127.0.0.1", 0)
    try:
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
    finally:
        sock.close()


def test_a_stream_socket_still_gets_so_reuseaddr_on_posix():
    """The legitimate use survives: restarting a TCP server over `TIME_WAIT`.

    This is the whole reason `reuse_address` defaults to True, and narrowing the
    fix to datagram sockets is what keeps it.
    """
    if IS_WINDOWS:
        pytest.skip("Windows gets SO_EXCLUSIVEADDRUSE instead; covered above")
    sock = bind("127.0.0.1", 0, kind=socket.SOCK_STREAM)
    try:
        # Truthiness, not `== 1`: getsockopt returns an implementation-defined
        # nonzero for a boolean option, and macOS returns **4** here. Asserting
        # the literal 1 passed on Linux and Windows and failed on macOS CI.
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
    finally:
        sock.close()


def test_sharing_a_udp_port_is_still_reachable_by_an_explicit_name():
    """Taking the default away must not take the capability away.

    **Which name works is a platform fact**, and asserting both everywhere was
    wrong -- it failed on macOS CI. `SO_REUSEADDR` alone does not permit an exact
    duplicate UDP bind on BSD/Darwin; there `SO_REUSEPORT` is the one that does.
    `SO_REUSEPORT` in turn does not exist on Windows, where
    `allow_address_takeover` is the route. So the law worth pinning is that **at
    least one** explicit name still shares, not that a particular one does.
    """
    candidates = [{"reuse_port": True}, {"allow_address_takeover": True}]
    outcomes = {}
    for kwargs in candidates:
        try:
            holder = bind("127.0.0.1", 0, **kwargs)
        except OSError as exc:  # pragma: no cover - option absent on this platform
            outcomes[str(kwargs)] = "unavailable: %s" % (exc,)
            continue
        try:
            port = holder.getsockname()[1]
            outcomes[str(kwargs)] = _second_bind_succeeds(port, **kwargs)
        finally:
            holder.close()
    assert any(
        value is True for value in outcomes.values()
    ), "no explicit name can share a UDP port any more: %r" % (outcomes,)


def test_multicast_socket_does_not_depend_on_the_old_default():
    """It sets what it needs itself, so the change cannot have broken it.

    Checked rather than assumed -- the finding asked for exactly this, since a
    multicast receiver is the one legitimate case for sharing a port.
    """
    import inspect

    source = inspect.getsource(netimps.multicast_socket)
    assert (
        "SO_REUSEADDR" in source
    ), "multicast_socket must set SO_REUSEADDR itself, not inherit it from bind()"
    sock = netimps.multicast_socket("239.1.2.3", 0)
    try:
        # Truthiness, not `== 1` -- macOS returns 4. See the note above.
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
    finally:
        sock.close()
