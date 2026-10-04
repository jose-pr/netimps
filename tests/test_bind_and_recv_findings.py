"""Reported defects in bind() and UDPEndpoint, each pinned by a test."""

import errno
import os
import socket

import pytest

import netimps
from netimps import AddressInUseError, UDPEndpoint, bind

IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# bind(reuse_address=False) was hijackable on Windows                          #
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
# UDPEndpoint.recv() enumerated every interface, per packet                    #
# --------------------------------------------------------------------------- #


def test_recv_enumerates_once_for_many_packets(monkeypatch):
    """The default path used to call get_interfaces() on every datagram.

    Measured on Windows loopback: 1.07 ms/packet against 0.015 with
    `resolve_interface=False` -- a 70x cost on the path the class docstring's own
    example uses. A server loop is a hot loop by definition, since the sender
    controls the rate.
    """
    from netimps import _ifaddrs

    calls = []
    real = _ifaddrs.get_interfaces

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(_ifaddrs, "get_interfaces", counting)

    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no pktinfo on this platform")
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for _ in range(10):
                sender.sendto(b"packet", ("127.0.0.1", port))
                packet = endpoint.recv(1500)
                assert packet.interface is not None
        finally:
            sender.close()

    assert (
        len(calls) == 1
    ), "10 datagrams on one interface must cost one enumeration, got %d" % len(calls)


def test_the_interface_cache_keeps_a_negative_answer(monkeypatch):
    """An index with no adapter is a real answer, and must not re-enumerate.

    Otherwise a stale or vanished index makes every subsequent packet pay the
    full cost -- the expensive case becoming the common one.
    """
    from netimps import _ifaddrs

    calls = []
    real = _ifaddrs.get_interfaces
    monkeypatch.setattr(
        _ifaddrs, "get_interfaces", lambda *a, **k: calls.append(1) or real(*a, **k)
    )
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        assert endpoint._interface_for(999999) is None
        first = len(calls)
        assert endpoint._interface_for(999999) is None
        assert len(calls) == first, "a cached negative must not re-enumerate"


def test_resolve_interface_false_never_enumerates(monkeypatch):
    from netimps import _ifaddrs

    calls = []
    real = _ifaddrs.get_interfaces
    monkeypatch.setattr(
        _ifaddrs, "get_interfaces", lambda *a, **k: calls.append(1) or real(*a, **k)
    )
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"packet", ("127.0.0.1", port))
            packet = endpoint.recv(1500, resolve_interface=False)
        finally:
            sender.close()
        assert packet.interface is None
        assert calls == []


def test_the_cache_is_per_endpoint():
    """Not a module global: two endpoints must not share a stale view."""
    first = UDPEndpoint(bind("127.0.0.1", 0))
    second = UDPEndpoint(bind("127.0.0.1", 0))
    try:
        first._interface_for(1)
        assert second._iface_cache == {}, "the cache must not be shared"
    finally:
        first.close()
        second.close()


# --------------------------------------------------------------------------- #
# "the port is taken" had three different shapes                               #
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
# bind()'s default used to let a second live UDP socket take the port on Linux  #
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
