"""UDPEndpoint: the receive path, pktinfo, source pinning, the interface cache.

Loopback only; each test runs against real sockets.
"""

import ipaddress
import os
import socket
import struct
import sys

import pytest

import netimps

# Private: the native walks, caches and sockaddr decoders are tested apart from the live host.
from netimps import UDPEndpoint, _ifaddrs, _pktinfo, _udp, bind

# --------------------------------------------------------------------------- #
# UDPEndpoint                                                                 #
# --------------------------------------------------------------------------- #


#: Both loopbacks, so every endpoint test runs against each address family.
#: The v6 half is the regression: ``IP_PKTINFO`` is silently accepted on an
#: AF_INET6 socket, so a v4-only test suite stays green while v6 reports an
#: arrival interface it never receives.
_LOOPBACKS = [
    pytest.param(socket.AF_INET, "127.0.0.1", id="ipv4"),
    pytest.param(socket.AF_INET6, "::1", id="ipv6"),
]


def _loopback_endpoint(family, host):
    """A bound loopback endpoint, skipping where the family is unavailable."""
    try:
        sock = bind(host, 0, family=family)
    except OSError as exc:  # no IPv6 stack, or no ::1 configured
        pytest.skip("cannot bind %s: %s" % (host, exc))
    endpoint = UDPEndpoint(sock)
    endpoint.socket.settimeout(5.0)
    return endpoint


def _platform_delivers_pktinfo(family, host):
    """Whether the platform hands a plain socket a pktinfo control message.

    Ground truth comes from the kernel: every pktinfo receive option the module
    names for this family is set on a plain socket, a datagram is sent to it,
    and the *raw* level of the control message that arrives is read. Only constants are
    taken from `_pktinfo`; whether a message arrived is never decided by its
    decoder, so a regression in the decoder cannot turn this into a skip.
    ``None`` means the probe itself could not be made.
    """
    if not netimps.has_recvmsg():
        return False
    level = socket.IPPROTO_IPV6 if family == socket.AF_INET6 else socket.IPPROTO_IP
    if family == socket.AF_INET6:
        options = [
            (socket.IPPROTO_IPV6, _pktinfo._IPV6_RECVPKTINFO),
            (socket.IPPROTO_IPV6, _pktinfo._IPV6_PKTINFO),
        ]
    else:
        options = [(socket.IPPROTO_IP, _pktinfo._IP_PKTINFO)]
    try:
        probe = bind(host, 0, family=family)
    except OSError:
        return None
    peer = socket.socket(family, socket.SOCK_DGRAM)
    try:
        for option_level, option in options:
            if option is None:
                continue
            try:
                probe.setsockopt(option_level, option, 1)
            except OSError:
                continue
        peer.sendto(b"ground-truth", (host, probe.getsockname()[1]))
        probe.settimeout(5.0)
        _data, ancdata, _flags, _sender = netimps.recvmsg(
            probe, 512, netimps.CMSG_SPACE(256)
        )
    except OSError:
        return None
    finally:
        peer.close()
        probe.close()
    return any(received == level for received, _type, _cdata in ancdata)


@pytest.mark.parametrize("family, host", _LOOPBACKS)
def test_udp_endpoint_round_trip(family, host):
    """The flag and the data must agree, for both address families.

    ``has_pktinfo`` is the single thing the docs tell a caller to check,
    so a ``True`` that is followed by an empty ``interface_index`` is worse
    than an honest ``False``. Asserting only ``data``/``sender`` -- which this
    test used to do -- leaves the whole pktinfo path free to be dead.
    """
    with _loopback_endpoint(family, host) as endpoint:
        port = endpoint.socket.getsockname()[1]
        sender = bind(host, 0, family=family)
        try:
            sender.sendto(b"payload", (host, port))
            packet = endpoint.recv(1024)
        finally:
            sender.close()

    assert packet.data == b"payload"
    assert packet.sender[0] == host
    assert packet.control_truncated is False

    # Degrading to False is honest, but it must not become the escape hatch:
    # where the platform delivers the control message to a plain socket, the
    # endpoint has to claim it. The platform is asked, not the module's own
    # option table.
    if _platform_delivers_pktinfo(family, host):
        assert endpoint.has_pktinfo
    if sys.platform.startswith("freebsd") and family == socket.AF_INET:
        # FreeBSD's IPv4 carrier is not IP_PKTINFO, so the option table above
        # names nothing for it; the platform delivers the arrival all the same.
        assert endpoint.has_pktinfo

    if not endpoint.has_pktinfo:
        assert packet.interface_index == 0 and packet.interface is None
        return
    assert packet.interface_index != 0
    assert packet.interface is not None
    assert packet.destination is not None and packet.destination.is_loopback


def test_udp_endpoint_reports_truncated_control_data():
    """``MSG_CTRUNC`` must reach the caller, not be dropped with the cmsg.

    The buffer is sized for several messages precisely so this is rare, but
    when it does happen the empty interface fields mean "something was
    discarded", not "the kernel had nothing to say" -- and nothing else
    distinguishes the two.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no IP_PKTINFO on this platform")
        # Smaller than any cmsg header, so the kernel truncates our own.
        endpoint._cmsg_size = 1
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = bind("127.0.0.1", 0)
        try:
            sender.sendto(b"squeezed", ("127.0.0.1", port))
            packet = endpoint.recv(64)
        finally:
            sender.close()

    assert packet.data == b"squeezed"
    assert packet.control_truncated is True
    assert packet.interface_index == 0


def test_udp_endpoint_ancillary_buffer_holds_more_than_one_cmsg():
    """Room for exactly one cmsg loses the pktinfo to any other option.

    Measured on Linux with ``SO_TIMESTAMP`` and ``IP_PKTINFO`` both enabled:
    a one-slot buffer kept the timestamp, discarded the pktinfo and set
    ``MSG_CTRUNC``. The caller owns the raw socket, so a second enabled
    option is ordinary rather than exotic.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no IP_PKTINFO on this platform")
        one = socket.CMSG_SPACE(struct.calcsize(_pktinfo._PKTINFO_V4))
        assert endpoint._cmsg_size >= one * 2


@pytest.mark.parametrize("family, host", _LOOPBACKS)
def test_udp_endpoint_pins_the_source_it_is_given(family, host):
    """``src`` is honoured where the platform can, and ignored where it cannot.

    Both halves matter: a pinned send that never applies the pin is the
    silent wrong answer, and a raise on a platform without ``sendmsg`` would
    break the documented degrade.
    """
    with _loopback_endpoint(family, host) as receiver:
        port = receiver.socket.getsockname()[1]
        with _loopback_endpoint(family, host) as sender:
            assert sender.send(b"pinned", host, port, src=host) == 6
            # The flag may be False (Windows has no sendmsg; macOS has no
            # IP_PKTINFO), but it must never claim a pin it cannot apply.
            assert not sender.has_src_pinning or hasattr(socket.socket, "sendmsg")
        packet = receiver.recv(64)
    assert packet.data == b"pinned"


def _addresses_of_this_host(family):
    """The loopback address and every routable address an interface holds."""
    version = 4 if family == socket.AF_INET else 6
    found = ["127.0.0.1" if version == 4 else "::1"]
    for iface in netimps.get_interfaces():
        for ip in iface.ips:
            if (
                ip.version == version
                and not ip.ip.is_loopback
                and not ip.ip.is_link_local
            ):
                found.append(str(ip.ip))
    return found


@pytest.mark.parametrize("family, host", _LOOPBACKS)
def test_a_pinned_source_is_the_address_the_receiver_observes(family, host):
    """A datagram sent with ``src=`` arrives *from* that address.

    `test_udp_endpoint_pins_the_source_it_is_given` binds the sender to the
    pinned address, so it passes whether or not the control message is sent.
    Here the sender is bound to the wildcard, the receiver is a plain socket,
    and a (destination, source) pair of this host's own addresses is chosen
    where an unpinned datagram arrives from a *different* address: only a pin
    that reached the kernel changes what the receiver sees. Which pairs a
    kernel accepts is the kernel's to say (Windows refuses a source that is not
    the destination's own interface), so the pairs are tried and the test skips
    when none is accepted.
    """
    addresses = _addresses_of_this_host(family)
    wildcard = "0.0.0.0" if family == socket.AF_INET else "::"
    try:
        sender = UDPEndpoint(bind(wildcard, 0, family=family))
        plain = bind(wildcard, 0, family=family)
    except OSError as exc:
        pytest.skip("cannot bind %s: %s" % (wildcard, exc))
    with sender, plain:
        if not sender.has_src_pinning:
            pytest.skip("this platform cannot pin a source")
        for destination in addresses:
            receiver = socket.socket(family, socket.SOCK_DGRAM)
            try:
                receiver.bind((destination, 0))
                receiver.settimeout(0.5)
                port = receiver.getsockname()[1]
                plain.sendto(b"unpinned", (destination, port))
                unpinned = ipaddress.ip_address(receiver.recvfrom(64)[1][0])
                for source in addresses:
                    if ipaddress.ip_address(source) == unpinned:
                        continue
                    try:
                        sender.send(b"pinned", destination, port, src=source)
                        data, peer = receiver.recvfrom(64)
                    except OSError:
                        continue  # the kernel refuses this pair
                    assert data == b"pinned"
                    assert ipaddress.ip_address(peer[0]) == ipaddress.ip_address(
                        source
                    ), "pinned %s, the receiver saw %s (unpinned: %s)" % (
                        source,
                        peer[0],
                        unpinned,
                    )
                    return
            except OSError:
                continue
            finally:
                receiver.close()
    pytest.skip("no pair of this host's addresses lets a pinned source be observed")


def test_udp_endpoint_send_rejects_a_source_of_the_wrong_family():
    """Linux *accepts* an IPv6 cmsg on an AF_INET socket and ignores it.

    Measured: ``sendmsg`` returns the byte count, and the pin does nothing.
    So the mismatch has to be caught here -- the kernel will not report it.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as sender:
        if not sender.has_src_pinning:
            pytest.skip("no IPv4 source pinning on this platform")
        with pytest.raises(ValueError, match="IPv6 source"):
            sender.send(b"x", "127.0.0.1", 9, src="::1")


def test_udp_endpoint_send_rejects_an_unresolvable_source():
    """A spec naming no local adapter is a caller error, not a fallback.

    Sending from whatever the routing table picks is exactly the silent
    wrong answer ``src`` exists to prevent.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as sender:
        if not sender.has_src_pinning:
            pytest.skip("no IPv4 source pinning on this platform")
        with pytest.raises(ValueError, match="cannot resolve src"):
            sender.send(b"x", "127.0.0.1", 9, src="no-such-adapter")


def test_udp_endpoint_degrades_without_pktinfo(monkeypatch):
    """No IP_PKTINFO must mean empty interface fields, not a failure."""
    monkeypatch.setattr(_pktinfo, "_IP_PKTINFO", None)
    # FreeBSD carries IPv4 arrival data without IP_PKTINFO; a platform with
    # neither is what this simulates.
    monkeypatch.setattr(_udp._freebsd, "IS_FREEBSD", False)
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        assert endpoint.has_pktinfo is False
        # Same constant serves both directions for IPv4, so neither is claimed.
        assert endpoint.has_src_pinning is False
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = bind("127.0.0.1", 0)
        try:
            sender.sendto(b"x", ("127.0.0.1", port))
            packet = endpoint.recv(64)
        finally:
            sender.close()
    assert packet.data == b"x"
    assert packet.interface is None and packet.interface_index == 0
    assert packet.destination is None and packet.control_truncated is False


def test_udp_endpoint_send_falls_back_without_source():
    with UDPEndpoint(bind("127.0.0.1", 0)) as receiver:
        receiver.socket.settimeout(5.0)
        port = receiver.socket.getsockname()[1]
        with UDPEndpoint(bind("127.0.0.1", 0)) as sender:
            assert sender.send(b"hi", "127.0.0.1", port) == 2
        assert receiver.recv(64).data == b"hi"


def test_udp_endpoint_repr_and_close():
    endpoint = UDPEndpoint(bind("127.0.0.1", 0))
    # Both capability flags belong in the repr: they are what a bug report
    # about "interface is always None" needs to carry.
    assert "UDPEndpoint(" in repr(endpoint)
    assert "pktinfo=" in repr(endpoint) and "src_pinning=" in repr(endpoint)
    endpoint.close()


@pytest.mark.parametrize("family, host", _LOOPBACKS)
def test_udp_endpoint_claims_pktinfo_whenever_the_platform_delivers_it(family, host):
    """If a raw socket can get a pktinfo cmsg, the endpoint must not say it cannot.

    This asks the **platform**, not the library: a guard that read the module's
    own option table switched itself off when that table returned None for IPv6
    on Windows, and the round trip passed through its degraded branch. Measured
    on a CI runner: `UDPEndpoint(bind("::", 0)).has_pktinfo` was False while a
    raw `recvmsg` on the very same socket delivered the cmsg. The verdict is the
    raw level of that control message, never what the module's
    decoder makes of it, so a decoder regression is not read as "the platform
    does not deliver".
    """
    delivered = _platform_delivers_pktinfo(family, host)
    if delivered is None:
        pytest.skip("the ground-truth probe could not be made on %s" % (host,))
    if not delivered:
        pytest.skip("platform delivers no pktinfo cmsg for family %s" % (family,))

    with _loopback_endpoint(family, host) as endpoint:
        assert endpoint.has_pktinfo, (
            "a raw recvmsg got a pktinfo cmsg for family %s, so UDPEndpoint "
            "must not report has_pktinfo=False" % (family,)
        )


def test_udp_endpoint_dual_stack_reports_a_v4_arrival_as_v4_mapped():
    """`destination` on an AF_INET6 endpoint is v4-mapped on every platform.

    The platforms genuinely disagree about the wire form: Linux and macOS put
    the v4-mapped address in the v6 cmsg, while Windows reports a *plain* v4
    address at level IPPROTO_IP -- and on Windows the same datagram's `sender`
    is already `::ffff:127.0.0.1`, so the two halves contradict each other.
    The documented contract is the mapped form, so this pins the normalisation.
    """
    # IPV6_V6ONLY has to be cleared **before** the bind -- Windows answers
    # WSAEINVAL for a change after it, which is why this builds the socket by
    # hand instead of going through `bind()`.
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", 0))
    except OSError as exc:
        sock.close()
        pytest.skip("no dual-stack :: socket here -- %s" % (exc,))
    with UDPEndpoint(sock) as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no pktinfo on this platform")
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"v4-arrival", ("127.0.0.1", port))
            packet = endpoint.recv(1024)
        except OSError as exc:
            pytest.skip("no dual-stack v4 delivery here: %s" % (exc,))
        finally:
            sender.close()

        assert packet.data == b"v4-arrival"
        if packet.destination is None:
            pytest.skip("this platform reported no arrival address for a v4 arrival")
        assert (
            packet.destination.version == 6
        ), "an AF_INET6 endpoint must report a v6 address, got %r" % (
            packet.destination,
        )
        assert packet.destination == ipaddress.IPv6Address("::ffff:127.0.0.1")


def test_udp_endpoint_reports_a_virtual_ip_as_the_arrival_address():
    """A wildcard socket must say *which* address the datagram was sent to.

    This is the entire reason pktinfo exists: replying from the VIP a client
    addressed, not from whatever the routing table prefers. 127.0.0.2 is a
    convenient stand-in for a VIP on Linux and Windows; macOS assigns only
    127.0.0.1 and rejects it, which the skip records rather than hides.
    """
    with _loopback_endpoint(socket.AF_INET, "0.0.0.0") as endpoint:
        if not endpoint.has_pktinfo:
            pytest.skip("no pktinfo on this platform")
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"to-the-vip", ("127.0.0.2", port))
            packet = endpoint.recv(1024)
        except OSError as exc:
            pytest.skip("127.0.0.2 is not reachable on this host: %s" % (exc,))
        finally:
            sender.close()
        if packet.destination is None:
            pytest.skip("no arrival address reported")
        assert str(packet.destination) == "127.0.0.2", (
            "the wildcard socket reported %r, losing which address the client "
            "actually addressed" % (packet.destination,)
        )


def _force_index_only_spec(monkeypatch):
    """Make any src resolve to an interface index but no address.

    The public API cannot express that state -- every spec it accepts either
    names an address or resolves to one -- so the resolver is faked. What is
    being tested is our own branch, not the resolver.
    """
    monkeypatch.setattr(_udp._send, "interface_address", lambda *a, **k: None)
    monkeypatch.setattr(_udp._send, "interface_index", lambda *a, **k: 1)


@pytest.mark.skipif(os.name != "nt", reason="the zero-address rule is Windows-only")
def test_windows_refuses_an_index_only_source_rather_than_sending_from_zero(
    monkeypatch,
):
    """Windows sends a zero source address literally, so it must refuse instead.

    Measured: a pin of 0.0.0.0 arrives *from* 0.0.0.0, where Linux reads zero as
    "kernel chooses". Silently sending from an unintended address is the exact
    failure `src=` exists to prevent, so this raises rather than degrading.
    """
    _force_index_only_spec(monkeypatch)
    with _loopback_endpoint(socket.AF_INET, "127.0.0.1") as endpoint:
        with pytest.raises(ValueError, match="index alone"):
            endpoint._pktinfo_control("any-spec")


@pytest.mark.skipif(os.name == "nt", reason="the POSIX half of the zero-address rule")
@pytest.mark.skipif(
    sys.platform.startswith("freebsd"),
    reason="FreeBSD pins an IPv4 source by address only; it has no index pin",
)
def test_posix_packs_a_zero_source_for_an_index_only_pin(monkeypatch):
    """The counterpart: on POSIX a zero address *is* "kernel chooses".

    Paired with the Windows test deliberately. The two platforms read identical
    bytes in opposite ways, so pinning one without the other would let a future
    change make them agree -- which would be wrong on one of them.
    """
    _force_index_only_spec(monkeypatch)
    with _loopback_endpoint(socket.AF_INET, "127.0.0.1") as endpoint:
        control = endpoint._pktinfo_control("any-spec")
        assert control is not None
        _level, _ctype, data = control
        index, _spec_dst, address = struct.unpack(_pktinfo._PKTINFO_V4, data)
        assert index == 1
        assert address == b"\x00\x00\x00\x00", "a zero address is the POSIX idiom"


# --------------------------------------------------------------------------- #
# UDPEndpoint.recv() enumerates once for many packets                         #
# --------------------------------------------------------------------------- #


def test_recv_enumerates_once_for_many_packets(monkeypatch):
    """The default path used to call get_interfaces() on every datagram.

    Measured on Windows loopback: 1.07 ms/packet against 0.015 with
    `resolve_interface=False` -- a 70x cost on the path the class docstring's own
    example uses. A server loop is a hot loop by definition, since the sender
    controls the rate.
    """
    # Private: the native walks, caches and sockaddr decoders are tested apart from the live host.
    from netimps import _ifaddrs

    # Private: the receive path's private seams.
    from netimps._udp import _endpoint

    calls = []
    real = _ifaddrs.get_interfaces

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(_endpoint, "get_interfaces", counting)

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
    # Private: the native walks, caches and sockaddr decoders are tested apart from the live host.
    from netimps import _ifaddrs

    # Private: the receive path's private seams.
    from netimps._udp import _endpoint

    calls = []
    real = _ifaddrs.get_interfaces
    monkeypatch.setattr(
        _endpoint, "get_interfaces", lambda *a, **k: calls.append(1) or real(*a, **k)
    )
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        assert endpoint._interface_for(999999) is None
        first = len(calls)
        assert endpoint._interface_for(999999) is None
        assert len(calls) == first, "a cached negative must not re-enumerate"


def test_resolve_interface_false_never_enumerates(monkeypatch):
    # Private: the native walks, caches and sockaddr decoders are tested apart from the live host.
    from netimps import _ifaddrs

    # Private: the receive path's private seams.
    from netimps._udp import _endpoint

    calls = []
    real = _ifaddrs.get_interfaces
    monkeypatch.setattr(
        _endpoint, "get_interfaces", lambda *a, **k: calls.append(1) or real(*a, **k)
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
# has_pktinfo                                                                 #
# --------------------------------------------------------------------------- #


def test_supports_pktinfo_agrees_with_an_actual_endpoint():
    """It must answer exactly what building an endpoint would answer.

    That is the whole contract: this is a cached shorthand for exactly that, so
    a different answer here would be a regression dressed as a convenience.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        expected = UDPEndpoint(probe).has_pktinfo
    finally:
        probe.close()
    assert netimps.has_pktinfo(socket.AF_INET) == expected


def test_supports_pktinfo_does_not_feature_test_the_constant_name():
    """**The trap this function exists to avoid.**

    `getattr(socket, "IP_PKTINFO", None)` is `None` on CPython 3.9-3.11 on
    *every* platform -- the constant arrived in 3.12 -- while the kernel
    supported it throughout. A name test therefore says "no" on a platform that
    works, pushing a server onto a per-address bind it did not need (and on
    Linux that bind receives no broadcasts at all).

    So on 3.9-3.11 the constant being absent must NOT make this False.
    """
    answer = netimps.has_pktinfo(socket.AF_INET)
    if not hasattr(socket, "IP_PKTINFO"):
        # The interpreter lacks the name. The answer must come from the socket.
        assert (
            answer is True
        ), "answered False on an interpreter that merely lacks the constant"
    assert isinstance(answer, bool)


def test_supports_pktinfo_is_cached_per_family(monkeypatch):
    """Cached because it is a property of the platform, not of a socket."""
    netimps._udp._support._PKTINFO_SUPPORT.clear()
    created = []
    real = socket.socket

    class Counting(socket.socket):
        def __init__(self, *args, **kwargs):
            created.append(args[:2])
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(netimps._udp._support._socket, "socket", Counting)
    netimps.has_pktinfo(socket.AF_INET)
    netimps.has_pktinfo(socket.AF_INET)
    netimps.has_pktinfo(socket.AF_INET)
    assert len(created) == 1, "probed more than once for one family"
    netimps.has_pktinfo(socket.AF_INET6)
    assert len(created) == 2, "a second family must be probed separately"
    assert real is socket.socket or True


def test_supports_pktinfo_returns_false_rather_than_raising(monkeypatch):
    """A family whose socket cannot be created is a "no", not an error.

    IPv6 disabled on the host is the realistic case, and a server asking "can
    you report arrivals?" wants an answer it can branch on.
    """
    netimps._udp._support._PKTINFO_SUPPORT.clear()

    def refuse(*args, **kwargs):
        raise OSError("no such family")

    monkeypatch.setattr(netimps._udp._support._socket, "socket", refuse)
    assert netimps.has_pktinfo(socket.AF_INET6) is False


def test_supports_pktinfo_defaults_to_ipv4():
    netimps._udp._support._PKTINFO_SUPPORT.clear()
    assert netimps.has_pktinfo() == netimps.has_pktinfo(socket.AF_INET)
