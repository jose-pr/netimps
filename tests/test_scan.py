"""Tests for port/host scanning and multicast helpers.

Everything is pointed at loopback -- these never scan anything external.
"""

import ipaddress
import socket

import pytest

import netimps
from netimps import PORT_RANGES, IPv4Interface, is_multicast, scan_hosts, scan_ports


@pytest.fixture
def listener():
    """A real listening socket on loopback, yielding its port."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    yield server.getsockname()[1]
    server.close()


# --------------------------------------------------------------------------- #
# scan_ports                                                                   #
# --------------------------------------------------------------------------- #


def test_scan_ports_finds_a_listener(listener):
    closed = netimps.get_free_port()
    result = scan_ports("127.0.0.1", [listener, closed], timeout=1.0)
    assert listener in result
    assert closed not in result


def test_scan_ports_accepts_interface_object(listener):
    result = scan_ports(IPv4Interface("127.0.0.1/8"), [listener], timeout=1.0)
    assert listener in result


def test_scan_ports_returns_sorted(listener):
    extra = socket.socket()
    extra.bind(("127.0.0.1", 0))
    extra.listen(1)
    try:
        second = extra.getsockname()[1]
        result = scan_ports("127.0.0.1", [second, listener], timeout=1.0)
        assert result == sorted(result)
        assert {listener, second} <= set(result)
    finally:
        extra.close()


def test_scan_ports_accepts_named_range():
    result = scan_ports("127.0.0.1", "common", timeout=0.2)
    assert isinstance(result, list)
    assert all(p in PORT_RANGES["common"] for p in result)


def test_scan_ports_accepts_single_int_and_range(listener):
    assert scan_ports("127.0.0.1", listener, timeout=1.0) == [listener]
    result = scan_ports("127.0.0.1", range(listener, listener + 2), timeout=1.0)
    assert listener in result


def test_scan_ports_unknown_named_range():
    with pytest.raises(ValueError, match="unknown port range or scheme"):
        scan_ports("127.0.0.1", "nonsense")


def test_ports_accept_scheme_names():
    """A scheme name resolves through get_default_port."""
    from netimps._scan import _resolve_ports

    assert _resolve_ports("https") == (443,)
    assert _resolve_ports("ssh") == (22,)
    assert _resolve_ports("socks5") == (1080,)  # absent from /etc/services
    assert _resolve_ports("8080") == (8080,)  # numeric string
    assert _resolve_ports(["ssh", 8080, "443"]) == (22, 8080, 443)


def test_range_name_wins_over_scheme_name():
    """A caller writing 'common' means the set, not some scheme."""
    from netimps._scan import _resolve_ports

    assert len(_resolve_ports("common")) > 1
    assert _resolve_ports("common") == PORT_RANGES["common"]


def test_unresolvable_port_in_list_raises():
    from netimps._scan import _resolve_ports

    with pytest.raises(ValueError, match="cannot resolve"):
        _resolve_ports([80, "definitely-not-a-scheme"])


def test_scan_hosts_accepts_scheme_name(listener):
    """port= takes a scheme name, same as scan_ports."""
    result = scan_hosts("127.0.0.1/32", port=listener, timeout=1.0)
    assert result  # sanity: the numeric form still works
    # A scheme name must not raise, whatever it finds.
    assert isinstance(scan_hosts("127.0.0.1/32", port="https", timeout=0.3), list)


def test_scan_ports_empty_is_empty():
    assert scan_ports("127.0.0.1", []) == []


def test_scan_ports_closed_host_is_empty():
    """An unreachable host yields nothing rather than raising."""
    assert scan_ports("127.0.0.1", [netimps.get_free_port()], timeout=0.3) == []


def test_port_ranges_are_sane():
    assert PORT_RANGES["well-known"][0] == 1
    assert PORT_RANGES["well-known"][-1] == 1023
    assert len(PORT_RANGES["all"]) == 65535
    assert 443 in PORT_RANGES["common"] and 22 in PORT_RANGES["common"]
    # 'common' must be a genuine shortcut, not a near-full sweep.
    assert len(PORT_RANGES["common"]) < 100


# --------------------------------------------------------------------------- #
# scan_hosts                                                                   #
# --------------------------------------------------------------------------- #


def test_scan_hosts_finds_loopback(listener):
    result = scan_hosts("127.0.0.1/32", port=listener, timeout=1.0)
    assert result
    address, ports = result[0]
    assert str(address) == "127.0.0.1"
    assert ports == [listener]


def test_scan_hosts_skips_hosts_with_nothing_open():
    assert scan_hosts("127.0.0.1/32", port=netimps.get_free_port(), timeout=0.3) == []


@pytest.mark.parametrize("network", ["10.0.0.0/8", "0.0.0.0/0", "172.16.0.0/12"])
def test_scan_hosts_refuses_huge_networks(network):
    """A /8 sweep is 16M hosts -- a mistake, not an intention."""
    with pytest.raises(ValueError, match="scan a /16 or smaller"):
        scan_hosts(network, port=80)


def test_scan_hosts_refuses_huge_ipv6():
    with pytest.raises(ValueError, match="too large"):
        scan_hosts("2001:db8::/64", port=80)


def test_scan_hosts_rejects_port_and_ports_together():
    with pytest.raises(ValueError, match="either port or ports"):
        scan_hosts("127.0.0.1/32", port=80, ports=[80, 443])


def test_scan_hosts_results_are_sorted(listener):
    result = scan_hosts("127.0.0.0/30", port=listener, timeout=0.5)
    addresses = [address for address, _ in result]
    assert addresses == sorted(addresses)


# --------------------------------------------------------------------------- #
# port validation                                                              #
# --------------------------------------------------------------------------- #


def test_out_of_range_port_raises_instead_of_wrapping(listener):
    """A port above 65535 must not be masked to 16 bits and answered about.

    Measured before the fix: with a listener on ``p``, ``p + 65536`` scanned
    as open -- a confident answer about a port nobody asked about, and an easy
    ``base + offset`` slip to make in a loop.
    """
    with pytest.raises(ValueError, match="out of range"):
        scan_ports("127.0.0.1", [listener + 65536], timeout=0.5)
    with pytest.raises(ValueError, match="out of range"):
        scan_hosts("127.0.0.1/32", port=listener + 65536, timeout=0.5)


@pytest.mark.parametrize("port", [-1, 65536, 100000])
def test_resolve_ports_rejects_out_of_range(port):
    """Every spelling of a port spec goes through the same gate."""
    from netimps._scan import _resolve_ports

    for spec in (port, [port], str(port)):
        with pytest.raises(ValueError, match="out of range"):
            _resolve_ports(spec)


def test_coerce_port_accepts_the_whole_range_and_nothing_else():
    from netimps._scheme import coerce_port

    assert coerce_port(0) == 0
    assert coerce_port(65535) == 65535
    with pytest.raises(ValueError, match="out of range"):
        coerce_port(65536)
    with pytest.raises(ValueError, match="source port out of range"):
        coerce_port(70000, "source port")
    with pytest.raises(TypeError, match="must be an int"):
        coerce_port("443")
    # True is never a port anyone meant; unrejected it would scan port 1.
    with pytest.raises(TypeError, match="must be an int"):
        coerce_port(True)


def test_unicode_digit_falls_through_to_scheme_lookup():
    """``str.isdigit()`` admits characters ``int()`` then rejects.

    SUPERSCRIPT TWO is a digit by ``isdigit()`` and not by ``int()``, so the
    old numeric test crashed inside the conversion instead of trying the value
    as a scheme name and reporting it unresolvable.
    """
    from netimps._scan import _port_number, _resolve_ports

    assert "²".isdigit()  # the premise, pinned
    assert _port_number("²", netimps.get_default_port) is None
    with pytest.raises(ValueError, match="unknown port range or scheme"):
        _resolve_ports("²")
    with pytest.raises(ValueError, match="cannot resolve"):
        _resolve_ports([80, "²"])


# --------------------------------------------------------------------------- #
# timeouts                                                                     #
# --------------------------------------------------------------------------- #


def test_zero_timeout_still_finds_an_open_port(listener):
    """``settimeout(0)`` is *non-blocking*, not "do not wait".

    Unfloored it makes ``connect`` raise ``BlockingIOError`` at once, which
    reads as closed -- so a scan at ``timeout=0`` reported every port on every
    host closed, quickly and silently.
    """
    assert scan_ports("127.0.0.1", [listener], timeout=0) == [listener]
    assert scan_hosts("127.0.0.1/32", port=listener, timeout=0) == [
        (netimps.IPv4Address("127.0.0.1"), [listener])
    ]


def test_floor_timeout_clamps_zero_and_rejects_negative():
    from netimps._scan import _MIN_TIMEOUT, _floor_timeout

    assert _floor_timeout(0) == _MIN_TIMEOUT
    assert _floor_timeout(0.5) == 0.5
    assert _MIN_TIMEOUT > 0
    with pytest.raises(ValueError, match="must not be negative"):
        _floor_timeout(-1)


@pytest.mark.parametrize(
    "call",
    [
        lambda: scan_ports("127.0.0.1", [80], timeout=-0.5),
        lambda: scan_hosts("127.0.0.1/32", port=80, timeout=-0.5),
    ],
)
def test_negative_timeout_raises(call):
    """A negative timeout has no reading -- ``settimeout`` rejects it too."""
    with pytest.raises(ValueError, match="must not be negative"):
        call()


# --------------------------------------------------------------------------- #
# resolution happens once per scan, not once per probe                         #
# --------------------------------------------------------------------------- #


def _record_lookups(monkeypatch):
    """Record every host passed to ``getaddrinfo``, still resolving it.

    Patching the ``socket`` module global covers ``create_connection`` as
    well, which is where the per-probe resolutions came from.
    """
    seen = []
    real = socket.getaddrinfo

    def counting(host, *args, **kwargs):
        seen.append(host)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", counting)
    return seen


def _names(looked_up):
    """The lookups that are names rather than address literals."""
    return [
        host for host in looked_up if netimps.try_parse(host, netimps.IPAddress) is None
    ]


def test_scan_ports_resolves_a_name_once(listener, monkeypatch):
    """One lookup for the scan, not one per port.

    Measured before the fix: eight ports meant eight ``getaddrinfo`` calls for
    the same name. The cost is not only latency -- a rate-limited resolver
    starts failing those lookups partway through, ``tcp_check`` reads a failed
    lookup as unreachable, and those ports are reported **closed** by the
    function whose whole output is the list of open ones.
    """
    spare = [netimps.get_free_port() for _ in range(3)]
    looked_up = _record_lookups(monkeypatch)

    scan_ports("localhost", [listener] + spare, timeout=0.5)

    assert _names(looked_up) == ["localhost"]


def test_scan_hosts_never_looks_up_a_name(listener, monkeypatch):
    """Its targets come from the network, so nothing reaches the resolver.

    Asserted as "no *name* was looked up" rather than a call count, so it
    still holds if :func:`netimps.tcp_check` later stops resolving literals.
    """
    looked_up = _record_lookups(monkeypatch)

    found = scan_hosts("127.0.0.1/32", port=listener, timeout=0.5)

    assert found, "sanity: the scan still ran"
    assert _names(looked_up) == []


def test_probe_tries_every_resolved_address(monkeypatch):
    """Resolving once must not quietly reduce a name to its first address.

    ``create_connection`` looped over every address inside each probe, so a
    dual-stack name still has to report a port open on either family.
    """
    from netimps._scan import _probe

    tried = []

    def fake_tcp_check(dst, port, timeout):
        tried.append(dst)
        return dst == "127.0.0.1"

    monkeypatch.setattr(netimps, "tcp_check", fake_tcp_check)

    assert _probe(["::1", "127.0.0.1"], 80, 1.0) is True
    assert tried == ["::1", "127.0.0.1"]


def test_an_unresolvable_host_scans_as_nothing_open(monkeypatch):
    """The single point of failure answers [], as the per-probe one did."""

    def refuse(*args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    assert scan_ports("no-such-host.example", [80, 443], timeout=0.5) == []


def test_an_address_literal_is_never_sent_to_the_resolver(monkeypatch):
    from netimps._scan import _probe_addresses

    def refuse(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("a literal was passed to getaddrinfo")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    assert _probe_addresses("127.0.0.1") == ["127.0.0.1"]
    assert _probe_addresses(IPv4Interface("10.0.0.5/24")) == ["10.0.0.5"]


# --------------------------------------------------------------------------- #
# an empty ports list means none, not "the default set"                        #
# --------------------------------------------------------------------------- #


def test_scan_hosts_with_an_empty_ports_list_probes_nothing(monkeypatch):
    """``ports or "common"`` read an explicit ``[]`` as "unset".

    A caller asking for no ports got the full 36-port common sweep of the
    whole network instead.
    """
    probed = []

    def fake_tcp_check(dst, port, timeout):
        probed.append(port)
        return False

    monkeypatch.setattr(netimps, "tcp_check", fake_tcp_check)

    assert scan_hosts("127.0.0.1/32", ports=[], timeout=0.5) == []
    assert probed == []

    # Omitted -- as opposed to empty -- still means the default set.
    scan_hosts("127.0.0.1/32", timeout=0.5)
    assert len(probed) == len(PORT_RANGES["common"])


# --------------------------------------------------------------------------- #
# scheme <-> port registry (_scheme, exercised through the public surface)     #
# --------------------------------------------------------------------------- #


@pytest.fixture
def clean_ports():
    """Snapshot/restore the port tables -- registration mutates module state."""
    from netimps import _scheme

    ports = dict(_scheme._DEFAULT_PORTS)
    schemes = dict(_scheme._PORT_SCHEMES)
    yield
    _scheme._DEFAULT_PORTS.clear()
    _scheme._DEFAULT_PORTS.update(ports)
    _scheme._PORT_SCHEMES.clear()
    _scheme._PORT_SCHEMES.update(schemes)


def test_register_port_drops_the_stale_reverse_entry(clean_ports):
    """Re-registering *moves* a scheme; its old port must stop naming it.

    Measured before the fix: after re-registering on 8888, ``get_default_port``
    said 8888 while ``get_default_scheme(9999)`` still said ``'zzztest'`` -- a
    registry contradicting itself.
    """
    netimps.register_port("zzztest", 9999)
    assert netimps.get_default_scheme(9999) == "zzztest"

    netimps.register_port("zzztest", 8888)
    assert netimps.get_default_port("zzztest") == 8888
    assert netimps.get_default_scheme(8888) == "zzztest"
    assert netimps.get_default_scheme(9999) != "zzztest"


def test_a_vacated_port_falls_to_a_scheme_still_claiming_it(clean_ports):
    """Aliases keep the slot warm rather than leaving it unnamed."""
    netimps.register_port("zzz-first", 9991)
    netimps.register_port("zzz-second", 9991)
    assert netimps.get_default_scheme(9991) == "zzz-first"  # earliest wins

    netimps.register_port("zzz-first", 9992)
    assert netimps.get_default_scheme(9991) == "zzz-second"
    assert netimps.get_default_scheme(9992) == "zzz-first"


def test_re_registering_the_same_port_leaves_the_canonical_rules_alone(clean_ports):
    netimps.register_port("zzz-alias", 443)
    assert netimps.get_default_scheme(443) == "https"  # an alias steals nothing

    netimps.register_port("zzz-alias", 443, canonical=True)
    assert netimps.get_default_scheme(443) == "zzz-alias"  # explicit override


def test_services_lookup_names_the_protocol(monkeypatch):
    """A protocol-less ``getservbyname`` answers per host, not per contract.

    TCP is asked first so the answer is the same everywhere, then UDP so a
    UDP-only service is still found.
    """
    from netimps import _scheme

    asked = []

    def fake_getservbyname(name, protocol=None):
        asked.append((name, protocol))
        if protocol != "udp":
            raise OSError("no such service")
        return 5555

    monkeypatch.setattr(_scheme._socket, "getservbyname", fake_getservbyname)

    assert netimps.get_default_port("zzz-udp-only") == 5555
    assert asked == [("zzz-udp-only", "tcp"), ("zzz-udp-only", "udp")]


def test_services_reverse_lookup_names_the_protocol(monkeypatch):
    """Port 514 is shell/cmd over TCP and syslog over UDP -- TCP wins."""
    from netimps import _scheme

    asked = []

    def fake_getservbyport(port, protocol=None):
        asked.append((port, protocol))
        return "zzz-%s" % (protocol,)

    monkeypatch.setattr(_scheme._socket, "getservbyport", fake_getservbyport)

    assert netimps.get_default_scheme(64999) == "zzz-tcp"
    assert asked == [(64999, "tcp")]


# --------------------------------------------------------------------------- #
# multicast                                                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "address, expected",
    [
        ("224.0.0.251", True),  # mDNS
        ("239.1.2.3", True),
        ("ff02::fb", True),
        ("10.0.0.1", False),
        ("127.0.0.1", False),
        ("garbage", False),
        ("", False),
        (None, False),
    ],
)
def test_is_multicast(address, expected):
    assert is_multicast(address) is expected


@pytest.mark.parametrize(
    "address, expected",
    [
        (ipaddress.ip_address("239.1.2.3"), True),
        (ipaddress.ip_interface("239.1.2.3/32"), True),
        (ipaddress.ip_interface("ff02::fb/128"), True),
        (ipaddress.ip_interface("10.0.0.1/24"), False),
        (ipaddress.ip_network("239.1.2.0/24"), False),  # a network is not an address
        (12345, False),
    ],
)
def test_is_multicast_accepts_the_same_forms_as_its_callers(address, expected):
    """It is the gatekeeper for join_group/leave_group, so it must accept what they do.

    Testing an ``IPv4Interface`` directly asked whether a *network* was
    multicast -- which it never is -- so a real group passed in the form every
    other function in this package accepts came back "not a multicast group".
    A network still answers False, and nothing raises.
    """
    assert is_multicast(address) is expected


def test_multicast_socket_round_trip():
    """A datagram sent to the group comes back on the joined socket.

    Skipped rather than failed when nothing arrives: a host firewall dropping
    inbound multicast is common (verified on a firewalld host, where plain
    stdlib multicast fails identically), and that is an environment fact, not
    a defect in the socket setup. The configuration itself is asserted by the
    surrounding tests, which do not need traffic to flow.
    """
    group, port = "239.7.7.42", 55571
    source = netimps.get_source_ip()
    if source is None:  # pragma: no cover - host without a route
        pytest.skip("no routable source address")

    receiver = netimps.multicast_socket(group, port, interface=str(source))
    try:
        receiver.settimeout(5.0)
        sender = netimps.multicast_socket(interface=str(source), bind=False)
        try:
            try:
                sender.sendto(b"payload", (group, port))
                data, _ = receiver.recvfrom(1024)
            except (socket.timeout, OSError):  # pragma: no cover - env dependent
                # Either the send had no multicast route (macOS CI runners
                # report ENETUNREACH here) or the datagram was filtered.
                pytest.skip("multicast is unavailable on this host")
            assert data == b"payload"
        finally:
            sender.close()
    finally:
        receiver.close()


def test_multicast_socket_rejects_non_group():
    for bad in ("10.0.0.1", "127.0.0.1", "garbage"):
        with pytest.raises(ValueError, match="not a multicast group"):
            netimps.multicast_socket(bad, 0)


def test_multicast_socket_unknown_interface_name():
    with pytest.raises(ValueError, match="no interface named"):
        netimps.multicast_socket("239.7.7.43", 0, interface="no-such-nic")


def test_multicast_socket_unknown_mac():
    with pytest.raises(ValueError, match="no interface with MAC"):
        netimps.multicast_socket(
            "239.7.7.44", 0, interface=netimps.MACAddress("02:00:00:00:00:99")
        )


def test_multicast_send_only_socket_can_send():
    """bind=False is the send-side configuration: usable, but claims no port.

    Asserting on getsockname() would be wrong -- an unbound socket has no name
    on Windows and raises there -- so this checks the property that matters:
    it can transmit. A host with no multicast route (macOS CI runners) raises
    ENETUNREACH on the send, which is an environment fact rather than a defect
    in the socket setup.
    """
    sock = netimps.multicast_socket(bind=False)
    try:
        try:
            assert sock.sendto(b"x", ("239.7.7.46", 55572)) == 1
        except OSError:  # pragma: no cover - env dependent
            pytest.skip("no multicast route on this host")
    finally:
        sock.close()


def test_join_group_rejects_non_group():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(ValueError, match="not a multicast group"):
            netimps.join_group(sock, "10.0.0.1")
        with pytest.raises(ValueError, match="not a multicast group"):
            netimps.leave_group(sock, "10.0.0.1")
    finally:
        sock.close()


def test_multicast_socket_closes_on_failure(monkeypatch):
    """A failed join must not leak the socket it was configuring."""
    closed = []
    real_socket = socket.socket

    class Tracking(real_socket):
        def close(self):
            closed.append(True)
            super().close()

    monkeypatch.setattr(netimps._multicast._socket, "socket", Tracking)
    with pytest.raises(ValueError):
        netimps.multicast_socket("239.7.7.45", 0, interface="no-such-nic")
    assert closed, "socket was not closed after the failure"


# --------------------------------------------------------------------------- #
# multicast: per-family interface selection                                    #
# --------------------------------------------------------------------------- #
#
# IPv6 identifies an adapter by *index*, IPv4 by local *address*. These fake
# get_interfaces() so the assertions are exact rather than host-dependent, and
# capture setsockopt on a stub rather than asking the kernel to accept a
# membership for an adapter that may not carry IPv6 on the runner.

_FAKE_INDEX = 37


@pytest.fixture
def fake_adapter(monkeypatch):
    """One non-loopback adapter with both families and a known index."""
    adapter = netimps.Interface(
        name="fake0",
        index=_FAKE_INDEX,
        mac=netimps.MACAddress("02:00:00:00:00:01"),
        ips=[
            netimps.IPv4Interface("192.0.2.10/24"),
            netimps.IPv6Interface("2001:db8::10/64"),
        ],
    )
    # Everything reaches enumeration through `._ifaddrs.get_interfaces` (a
    # function-local import in each caller), so one patch covers them all.
    monkeypatch.setattr(netimps._ifaddrs, "get_interfaces", lambda **k: [adapter])
    return adapter


class _StubSocket:
    """Records setsockopt calls; everything else is a no-op."""

    def __init__(self, *args, **kwargs):
        self.options = []

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))

    def bind(self, address):
        pass

    def close(self):
        pass


@pytest.fixture
def stub_socket(monkeypatch):
    made = []

    def _factory(*args, **kwargs):
        sock = _StubSocket(*args, **kwargs)
        made.append(sock)
        return sock

    monkeypatch.setattr(netimps._multicast._socket, "socket", _factory)
    return made


@pytest.mark.parametrize("spec", ["fake0", "2001:db8::10", "02:00:00:00:00:01"])
def test_ipv6_membership_carries_the_interface_index(fake_adapter, spec):
    """The v6 mreq's trailing index must be the adapter's, not 0.

    The regression: `interface=` was reduced to an *address* and then fed to
    `if_nametoindex()`, which always raises for an address string -- so the
    index silently stayed 0, i.e. "kernel's choice", the exact default the
    caller passed `interface=` to override.
    """
    import struct

    request = netimps._multicast._membership_request("ff02::fb", spec, ipv6=True)
    assert len(request) == 20  # 16-byte group + 4-byte index
    assert request[:16] == socket.inet_pton(socket.AF_INET6, "ff02::fb")
    assert struct.unpack("@I", request[16:])[0] == _FAKE_INDEX


def test_ipv6_membership_without_an_interface_is_still_kernel_choice(fake_adapter):
    """No `interface=` means index 0 -- unchanged, and the documented default."""
    import struct

    request = netimps._multicast._membership_request("ff02::fb", None, ipv6=True)
    assert struct.unpack("@I", request[16:])[0] == 0


def test_ipv4_membership_is_unchanged_by_the_v6_fix(fake_adapter):
    """v4 still names the adapter by address, byte-for-byte as before."""
    request = netimps._multicast._membership_request("239.7.7.50", "fake0", ipv6=False)
    assert request == socket.inet_aton("239.7.7.50") + socket.inet_aton("192.0.2.10")


def test_ipv6_multicast_socket_sets_multicast_if(fake_adapter, stub_socket):
    """Sends must be pinned too, or joins and sends use different adapters."""
    import struct

    netimps.multicast_socket("ff02::fb", 5353, interface="fake0")
    (sock,) = stub_socket
    pinned = [
        value
        for level, option, value in sock.options
        if (level, option) == (socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF)
    ]
    assert pinned, "IPV6_MULTICAST_IF was never set"
    assert struct.unpack("@I", pinned[0])[0] == _FAKE_INDEX


def test_ipv4_multicast_socket_still_sets_multicast_if_by_address(
    fake_adapter, stub_socket
):
    netimps.multicast_socket("239.7.7.51", 5354, interface="fake0")
    (sock,) = stub_socket
    pinned = [
        value
        for level, option, value in sock.options
        if (level, option) == (socket.IPPROTO_IP, socket.IP_MULTICAST_IF)
    ]
    assert pinned == [socket.inet_aton("192.0.2.10")]


def test_ipv6_interface_without_an_index_raises_rather_than_defaulting(monkeypatch):
    """Index 0 is the kernel's "pick for me" -- never a resolved answer.

    Returning it for an adapter the caller explicitly named would recreate
    the silent wrong-adapter failure, so an adapter the platform reports no
    index for is an error instead.
    """
    indexless = netimps.Interface(
        name="fake0", index=0, ips=[netimps.IPv6Interface("2001:db8::10/64")]
    )
    monkeypatch.setattr(netimps._ifaddrs, "get_interfaces", lambda **k: [indexless])
    with pytest.raises(ValueError, match="reports no index"):
        netimps._multicast._membership_request("ff02::fb", "fake0", ipv6=True)


# --------------------------------------------------------------------------- #
# multicast_socket address family                                              #
# --------------------------------------------------------------------------- #


def test_send_only_socket_can_be_ipv6():
    """`any()` over an empty group list is False, so send-only was always IPv4.

    The docstring's own send-only example -- `multicast_socket(ttl=32,
    bind=False)` -- had no group to infer a family from, so an IPv6 sender was
    simply unreachable through this function: the hop limit went onto the IPv4
    option and `sendto` to an IPv6 group could not work.
    """
    sender = netimps.multicast_socket(ttl=32, bind=False)
    try:
        assert sender.family == socket.AF_INET  # unchanged default
    finally:
        sender.close()

    sender6 = netimps.multicast_socket(ttl=32, bind=False, ipv6=True)
    try:
        assert sender6.family == socket.AF_INET6
    finally:
        sender6.close()


def test_family_is_still_inferred_from_the_group():
    """ipv6=None keeps the old behaviour wherever a group says which family.

    IPv4 only, deliberately. `multicast_socket` *joins* the group it is given,
    and joining a link-local IPv6 group with no `interface=` fails on macOS
    with EADDRNOTAVAIL -- which is a real, still-open finding about the join,
    not about the family inference this test is named for. Asserting inference
    through a call that has to succeed at joining would make this test fail for
    an unrelated reason on one platform.

    The IPv6 half of the inference is covered without joining anything by
    `test_explicit_family_may_not_contradict_the_group`: for that to raise, the
    code must already have read `ff02::fb` as v6.
    """
    sock = netimps.multicast_socket("239.1.2.3", bind=False)
    try:
        assert sock.family == socket.AF_INET
    finally:
        sock.close()


def test_mixed_family_groups_are_rejected():
    """One socket has one family; picking either and letting the other join
    fail surfaced as an opaque OSError from inside setsockopt."""
    with pytest.raises(ValueError, match="all IPv4 or all IPv6"):
        netimps.multicast_socket(["239.1.2.3", "ff02::fb"], bind=False)


def test_explicit_family_may_not_contradict_the_group():
    """Silently winning over the group would be the worse answer here."""
    with pytest.raises(ValueError, match="contradicts"):
        netimps.multicast_socket("239.1.2.3", ipv6=True, bind=False)
    with pytest.raises(ValueError, match="contradicts"):
        netimps.multicast_socket("ff02::fb", ipv6=False, bind=False)
