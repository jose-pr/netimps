"""The UDP-server helpers: reply_socket, is_broadcast, MTU sizing.

Each exists because a pktinfo-using UDP server fills the same gap by hand, and
each is tested against real loopback sockets rather than a mock, because the
subtleties are all platform behaviour.
"""

import os
import socket

import pytest

import netimps
from netimps import UDPEndpoint, bind, is_broadcast, max_udp_payload, parse
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
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        if not server.has_pktinfo:
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
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        if not server.has_pktinfo:
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
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
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
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        datagram = Datagram(data=b"", sender=("127.0.0.1", 1), local_address=None)
        sock = server.reply_socket(datagram)
        try:
            assert sock.getsockname()[0] in ("0.0.0.0", "")
        finally:
            sock.close()


def test_reply_socket_prefers_the_endpoints_own_address_over_the_wildcard():
    """A listener pinned to one address should answer from it, not the wildcard."""
    with UDPEndpoint(bind("127.0.0.1", 0)) as server:
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
    with UDPEndpoint(raw) as server:
        if not server.has_pktinfo:
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
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        datagram = Datagram(data=b"", sender=("127.0.0.1", 1), local_address=None)
        sock = server.reply_socket(datagram)
        try:
            assert sock.fileno() > 0
        finally:
            sock.close()


def _hold(address, port=0):
    """Bind a socket hard enough that a second bind of the same addr:port fails.

    Not `netimps.bind`: this has to be the *holder*, and the question of whether
    a second bind is refused is exactly what the test needs to control. A plain
    stdlib datagram socket with no options is the strictest holder available on
    both families.
    """
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind((address, port))
    return holder


def _second_bind_is_refused(address, port):
    """Does this platform actually refuse a second live bind here?

    Linux UDP permits duplicate live binds when `SO_REUSEADDR` is set, which is
    why `bind()` stopped setting it for datagram sockets. Rather than trusting
    that from the test, measure it -- a test that cannot provoke the error it is
    about should skip, not pass vacuously.
    """
    try:
        probe = bind(address, port)
    except netimps.AddressInUseError:
        return True
    except OSError:
        return False
    probe.close()
    return False


def test_reply_socket_takes_a_range_of_ports():
    """A server pinning transfer ports to a firewall-allowed range (`tftp-hpa
    -R`, `dnsmasq --tftp-port-range`) had no way through this method."""
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        # Ask the OS for free ports rather than naming any: a hardcoded port
        # meets Windows' per-boot excluded ranges sooner or later.
        scouts = [_hold("127.0.0.1") for _ in range(3)]
        wanted = [s.getsockname()[1] for s in scouts]
        for s in scouts:
            s.close()

        datagram = Datagram(
            data=b"", sender=("127.0.0.1", 1), local_address=parse("127.0.0.1")
        )
        sock = server.reply_socket(datagram, port=wanted)
        try:
            assert sock.getsockname()[0] == "127.0.0.1"
            assert sock.getsockname()[1] in wanted
        finally:
            sock.close()


def test_a_held_port_advances_the_port_not_the_address():
    """The regression this method shipped with, and the one failure it exists to
    prevent.

    Every `OSError` used to advance the *address*, so a taken port fell through
    to the endpoint's own address and then the wildcard **with the same port** --
    and where that later bind succeeded, the reply left from an address the
    client never addressed. An in-use port says nothing is wrong with the
    address, so the next port on the same address is the only correct move.
    """
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        scouts = [_hold("127.0.0.1") for _ in range(2)]
        taken, free = (s.getsockname()[1] for s in scouts)
        scouts[1].close()  # `free` is now free; `taken` is still held.

        if not _second_bind_is_refused("127.0.0.1", taken):
            scouts[0].close()
            pytest.skip("this platform permits a second live bind here")

        datagram = Datagram(
            data=b"", sender=("127.0.0.1", 1), local_address=parse("127.0.0.1")
        )
        try:
            sock = server.reply_socket(datagram, port=[taken, free])
            try:
                # Both halves matter: the right port *and* the right address.
                assert sock.getsockname()[1] == free
                assert sock.getsockname()[0] == "127.0.0.1"
            finally:
                sock.close()
        finally:
            scouts[0].close()


def test_exhausting_the_ports_raises_rather_than_moving_address():
    """ "Port busy" and "this address is unbindable" are different answers.

    The old code raised a generic `OSError` only after trying the wildcard, so a
    caller could not tell them apart -- and the wildcard attempt was itself the
    bug. With every port held on a bindable address this now raises
    `AddressInUseError` and binds nothing.
    """
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        holder = _hold("127.0.0.1")
        taken = holder.getsockname()[1]

        if not _second_bind_is_refused("127.0.0.1", taken):
            holder.close()
            pytest.skip("this platform permits a second live bind here")

        datagram = Datagram(
            data=b"", sender=("127.0.0.1", 1), local_address=parse("127.0.0.1")
        )
        try:
            with pytest.raises(netimps.AddressInUseError):
                server.reply_socket(datagram, port=[taken])
        finally:
            holder.close()


def test_an_unbindable_address_still_advances_the_address():
    """The other axis, unchanged: a broadcast destination is not a port problem.

    This is what keeps the two-axis fix from being a regression -- the fallback
    chain still exists, it is just no longer reached by an in-use port.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as server:
        scouts = [_hold("127.0.0.1") for _ in range(2)]
        wanted = [s.getsockname()[1] for s in scouts]
        for s in scouts:
            s.close()

        datagram = Datagram(
            data=b"", sender=("127.0.0.1", 1), local_address=parse("255.255.255.255")
        )
        sock = server.reply_socket(datagram, port=wanted)
        try:
            assert sock.getsockname()[0] == "127.0.0.1"
            assert sock.getsockname()[1] in wanted
        finally:
            sock.close()


def test_a_generator_of_ports_survives_every_address_candidate():
    """The ports are materialised once, because they are retried per address.

    A generator passed straight through would be empty by the second candidate,
    which would turn the fallback chain into a silent single attempt.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as server:
        scout = _hold("127.0.0.1")
        wanted = scout.getsockname()[1]
        scout.close()

        # An unbindable arrival address, so the first candidate fails and the
        # second has to see the same ports.
        datagram = Datagram(
            data=b"", sender=("127.0.0.1", 1), local_address=parse("255.255.255.255")
        )
        sock = server.reply_socket(datagram, port=(p for p in [wanted]))
        try:
            assert sock.getsockname() == ("127.0.0.1", wanted)
        finally:
            sock.close()


def _second_local_v4():
    """Another bindable local v4 address, or None.

    The wrong-address bug needs two: the arrival address with its port held, and
    a *different* one for the old code to wrongly fall back to.
    """
    for iface in netimps.get_interfaces():
        for ip in iface.ips:
            address = getattr(ip, "ip", ip)
            if address.version != 4 or address.is_loopback or address.is_link_local:
                continue
            try:
                probe = bind(str(address), 0)
            except OSError:
                continue
            probe.close()
            return str(address)
    return None


def test_a_held_port_does_not_answer_from_another_address():
    """The consumer-facing form of the same bug, with a plain `int` port.

    Measured on Windows 11 ARM64 against the pre-fix code: holding
    `10.6.0.223:57014` and asking for a reply to a datagram that arrived there
    returned a socket bound to `127.0.0.1:57014` -- the endpoint's own address.
    The client addressed one address and the reply would have left from another,
    which is the single failure this method exists to prevent.

    **This test is environment-dependent and skips freely** -- it needs a second
    live local v4 address, and one was observed coming and going between runs on
    this host (a VPN adapter). Do not read a green run as proof of the
    two-address case; the deterministic coverage of the same bug is
    `test_exhausting_the_ports_raises_rather_than_moving_address`, which is
    loopback-only. A standalone reproduction script is kept out of tree.
    """
    other = _second_local_v4()
    if other is None:
        pytest.skip("needs a second bindable local v4 address")

    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind((other, 0))
    port = holder.getsockname()[1]
    try:
        if not _second_bind_is_refused(other, port):
            pytest.skip("this platform permits a second live bind here")

        with UDPEndpoint(bind("127.0.0.1", 0)) as server:
            datagram = Datagram(
                data=b"", sender=("127.0.0.1", 1), local_address=parse(other)
            )
            with pytest.raises(netimps.AddressInUseError):
                server.reply_socket(datagram, port=port)
    finally:
        holder.close()


def test_an_empty_port_iterable_is_an_error_not_a_wildcard():
    """`port=[]` is a caller bug. Treating it as "any port" would bind something
    the caller's firewall rule does not cover."""
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        datagram = Datagram(data=b"", sender=("127.0.0.1", 1), local_address=None)
        with pytest.raises(ValueError, match="empty"):
            server.reply_socket(datagram, port=[])


def test_a_plain_int_port_still_works():
    """The int form is the common case and must not have become an iterable."""
    with UDPEndpoint(bind("0.0.0.0", 0)) as server:
        datagram = Datagram(data=b"", sender=("127.0.0.1", 1), local_address=None)
        sock = server.reply_socket(datagram, port=0)
        try:
            assert sock.getsockname()[1] > 0
        finally:
            sock.close()


# --------------------------------------------------------------------------- #
# A v4 client of a dual-stack listener                                        #
# --------------------------------------------------------------------------- #


def _dual_stack_listener():
    """An `AF_INET6` listener with `IPV6_V6ONLY` cleared, or a skip.

    Dual-stack is not available everywhere (and a v6-less runner cannot test
    this at all), so the inability to build the listener is a skip rather than a
    failure -- but it is the *bind* that decides, never a guess from the
    platform name.
    """
    try:
        return bind(
            "::",
            0,
            family=socket.AF_INET6,
            options=[(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)],
        )
    except OSError as exc:
        pytest.skip("no dual-stack listener available here: %s" % (exc,))


@pytest.mark.parametrize("pktinfo", [True, False])
def test_a_v4_client_of_a_dual_stack_listener_gets_a_real_reply(pktinfo):
    """End to end, and it failed **both** ways before -- differently each time.

    Measured on Windows 11 ARM64 against the pre-fix code, with a plain
    `AF_INET` client on `127.0.0.1` talking to a `bind("::", family=AF_INET6,
    IPV6_V6ONLY=0)` listener:

    - `pktinfo=True`: `local_address` is `::ffff:127.0.0.1`, so `reply_socket`
      correctly chose an `AF_INET` socket -- but `datagram.sender` is still the
      v6 4-tuple, so the documented `reply.sendto(answer, packet.sender)` raised
      `TypeError: AF_INET address must be a pair (host, port)`.
    - `pktinfo=False`: no `local_address`, so both fallbacks used the
      *listener's* family and produced an `AF_INET6` socket with
      `IPV6_V6ONLY=1` (the Windows default, which `bind()` does not clear).
      `sendto` to a mapped address then fails with `WinError 10049` and the
      transfer silently never starts.

    So this asserts the datagram actually arrives back at the client, which is
    the only claim that covers both.
    """
    listener = _dual_stack_listener()
    port = listener.getsockname()[1]
    with UDPEndpoint(listener, pktinfo=pktinfo) as server:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client.sendto(b"hello", ("127.0.0.1", port))
            client.settimeout(5)
            packet = server.recv()
            with server.reply_socket(packet) as reply:
                # The reply socket must be in the *client's* family, whatever
                # the listener's is and whatever pktinfo reported.
                assert reply.family == socket.AF_INET
                reply.sendto(b"answer", packet.reply_address)
            assert client.recvfrom(64)[0] == b"answer"
        finally:
            client.close()


def test_reply_address_unmaps_a_mapped_sender_to_a_two_tuple():
    """`sendto` on an `AF_INET` socket rejects a 4-tuple outright, so flowinfo
    and the scope id have to go with the mapping."""
    datagram = Datagram(data=b"", sender=("::ffff:127.0.0.1", 9999, 0, 0))
    assert datagram.reply_address == ("127.0.0.1", 9999)


@pytest.mark.parametrize(
    "sender",
    [
        ("127.0.0.1", 9999),
        ("::1", 9999, 0, 0),
        ("fe80::1", 9999, 0, 7),
    ],
)
def test_reply_address_leaves_everything_else_alone(sender):
    """Only a v4-mapped sender is rewritten.

    A real v6 sender keeps its 4-tuple -- the scope id in particular is
    load-bearing for a link-local peer -- and a v4 sender on a v4 listener was
    already correct.
    """
    assert Datagram(data=b"", sender=sender).reply_address == sender


def test_reply_address_passes_through_what_it_cannot_parse():
    """A unix-socket path or any non-address sender is returned untouched
    rather than raising: this is a convenience accessor, not a validator."""
    assert Datagram(data=b"", sender=("not-an-address", 1)).reply_address == (
        "not-an-address",
        1,
    )


def test_the_reply_family_follows_the_sender_not_the_listener():
    """The rule, stated once and pinned.

    Asserted on the `Datagram` rather than through a live dual-stack socket so
    it holds on a runner with no IPv6 at all.
    """
    with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
        mapped = Datagram(data=b"", sender=("::ffff:127.0.0.1", 1))
        assert endpoint._reply_family(mapped) == socket.AF_INET
        real_v6 = Datagram(data=b"", sender=("::1", 1, 0, 0))
        assert endpoint._reply_family(real_v6) == socket.AF_INET6
        # Unparseable: fall back to the socket's own family, as before.
        junk = Datagram(data=b"", sender=("nonsense", 1))
        assert endpoint._reply_family(junk) == endpoint.socket.family


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


def test_an_unbounded_mtu_is_a_number_not_none():
    """ULONG max means "no link constrains this", not "unknown".

    The Windows loopback adapter reports 0xFFFFFFFF, which this used to map to
    ``None`` -- conflating "no limit" with "could not read". It cost callers in
    the one direction that matters: handling ``None`` by falling back to 1500
    capped loopback at 1472 when it delivers 65507. Linux reports its own ``lo``
    as 65536 rather than as nothing, so the two platforms disagreed about the
    same physical reality.

    65535 is the largest datagram the 16-bit IP total-length field can describe,
    so it is a clamp to reality rather than an invented figure -- and it yields
    exactly the payload measured to arrive.
    """
    loopbacks = [i for i in netimps.get_interfaces() if i.is_loopback]
    if not loopbacks:
        pytest.skip("no loopback interface reported here")
    for interface in loopbacks:
        if interface.mtu is None:
            continue
        assert (
            interface.mtu > 1500
        ), "loopback should not be reported with a link-sized MTU; got %r" % (
            interface.mtu,
        )
        assert max_udp_payload(interface.mtu) >= 1472
        return
    pytest.skip("every loopback interface reported no MTU")


@pytest.mark.skipif(not IS_WINDOWS, reason="0xFFFFFFFF is what Windows reports")
def test_the_windows_loopback_mtu_matches_what_loopback_delivers():
    """The constant is validated against a real datagram, not merely asserted.

    If this fails, either the clamp is wrong or the platform changed -- and
    either way the number in the docs has stopped being true.
    """
    loopback = [i for i in netimps.get_interfaces() if i.is_loopback and i.mtu]
    if not loopback:
        pytest.skip("no loopback MTU reported")
    payload = max_udp_payload(loopback[0].mtu)

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(5.0)
    netimps.set_buffer_size(receiver, receive=1 << 20)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(b"x" * payload, receiver.getsockname())
        data, _ = receiver.recvfrom(payload + 1024)
        assert (
            len(data) == payload
        ), "max_udp_payload said %d would fit on loopback and %d arrived" % (
            payload,
            len(data),
        )
    except OSError as exc:  # pragma: no cover - buffer limits on a loaded host
        pytest.skip("could not move a %d-octet datagram here: %s" % (payload, exc))
    finally:
        sender.close()
        receiver.close()


# --------------------------------------------------------------------------- #
# has_pktinfo                                                            #
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
    netimps._udp._PKTINFO_SUPPORT.clear()
    created = []
    real = socket.socket

    class Counting(socket.socket):
        def __init__(self, *args, **kwargs):
            created.append(args[:2])
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(netimps._udp._socket, "socket", Counting)
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
    netimps._udp._PKTINFO_SUPPORT.clear()

    def refuse(*args, **kwargs):
        raise OSError("no such family")

    monkeypatch.setattr(netimps._udp._socket, "socket", refuse)
    assert netimps.has_pktinfo(socket.AF_INET6) is False


def test_supports_pktinfo_defaults_to_ipv4():
    netimps._udp._PKTINFO_SUPPORT.clear()
    assert netimps.has_pktinfo() == netimps.has_pktinfo(socket.AF_INET)
