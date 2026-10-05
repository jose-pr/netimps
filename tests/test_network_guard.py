"""The suite's network guard refuses an off-host query from every backend.

`getaddrinfo` and its siblings are one road to a name server. `resolve_wire`
and `resolve_dnspython` open their own sockets, `resolve_doh` goes through
`urllib`, `resolve_nslookup` and `ping` run programs, and `connect` resolves a
name in C. Each test here sends one deliberately off-host query -- to TEST-NET-1,
which nothing answers, with a short timeout so a failure of the guard shows as
a slow test and not a hang -- and expects the guard to have stopped it.
"""

import socket
import subprocess

import pytest

import netimps

OFF_HOST = "192.0.2.53"  # TEST-NET-1, RFC 5737


def _provoke(resolver_escapes, call):
    """Run `call`, whatever it raises, and return the escapes recorded."""
    try:
        call()
    except Exception:  # noqa: BLE001 -- some backends rewrite the exception
        pass
    seen = list(resolver_escapes)
    resolver_escapes.clear()
    return seen


def test_the_wire_backend_cannot_reach_an_off_host_server(resolver_escapes):
    """`resolve_wire` opens a UDP socket to the nameserver itself."""
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve_wire("x.example", ns=OFF_HOST, timeout=0.2),
    )
    assert seen and "socket.connect" in seen[0]


def test_the_wire_backend_cannot_reach_an_off_host_server_over_tcp(resolver_escapes):
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve_wire("x.example", ns=OFF_HOST, tcp=True, timeout=0.2),
    )
    assert seen and "socket.connect" in seen[0]


def test_the_dnspython_backend_cannot_reach_an_off_host_server(resolver_escapes):
    """dnspython rewrites every exception into a ValueError, so the record the
    guard keeps is what proves it fired."""
    pytest.importorskip("dns")
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve_dnspython("x.example", ns=OFF_HOST, timeout=0.2),
    )
    assert seen and "dns.resolver" in seen[0]


def test_the_dnspython_backend_cannot_use_the_system_nameservers(resolver_escapes):
    """With no `ns` it reads the OS's own servers. Those are off-host, or a
    loopback stub on port 53 that forwards off-host (systemd-resolved's
    `127.0.0.53`); the guard has to refuse both."""
    pytest.importorskip("dns")
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve_dnspython("x.example", timeout=0.2),
    )
    assert seen and "dns.resolver" in seen[0]


def test_the_doh_backend_cannot_reach_an_off_host_endpoint(resolver_escapes):
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve_doh(
            "x.example", "https://%s/dns-query" % OFF_HOST, timeout=0.2
        ),
    )
    assert seen and "urllib.request" in seen[0]


def test_the_nslookup_backend_cannot_run_against_an_off_host_name(resolver_escapes):
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve_nslookup("x.example", timeout=0.2),
    )
    assert seen and "nslookup" in seen[0]


def test_the_default_chain_cannot_reach_a_name_server(resolver_escapes):
    """The chain a caller gets by default is covered end to end."""
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve("x.example", ns=OFF_HOST, timeout=0.2),
    )
    assert seen


def test_loopback_off_the_dns_port_is_still_allowed(resolver_escapes):
    """The DNS tests talk to a fake server on loopback at an ephemeral port;
    that must stay open."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 0))
        probe.sendto(b"x", ("127.0.0.1", probe.getsockname()[1]))
    finally:
        probe.close()
    assert resolver_escapes == []


def test_connecting_to_the_loopback_dns_port_is_allowed_and_sending_is_not(
    resolver_escapes,
):
    """A port scan of loopback connects to port 53 and sends nothing, which is
    harmless. A payload is a query, and a stub listening there would forward
    it off the host."""
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.connect(("127.0.0.1", 53))
        assert resolver_escapes == []
        seen = _provoke(resolver_escapes, lambda: sender.send(b"x"))
        assert seen and "socket.send" in seen[0]
    finally:
        sender.close()


def test_a_loopback_resolver_on_the_dns_port_is_refused(resolver_escapes):
    """`127.0.0.53:53` is a forwarder, not a destination: a query sent there
    leaves the host. Loopback at any other port is where the fake servers
    listen, and stays allowed."""
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve_wire("x.example", ns="127.0.0.53", timeout=0.2),
    )
    assert seen and "socket." in seen[0]


# --------------------------------------------------------------------------- #
# Destinations that are not name servers                                       #
# --------------------------------------------------------------------------- #


def _udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.2)
    return sock


def test_an_off_host_destination_is_refused_on_any_port(resolver_escapes):
    """A guard that looked only at ports 53 and 853 let a test connect or send
    to a stranger's machine on port 9, 80 or 443 and pass while online."""
    for port in (9, 80, 443, 5353):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            seen = _provoke(resolver_escapes, lambda: sock.connect((OFF_HOST, port)))
        finally:
            sock.close()
        assert seen and "socket.connect" in seen[0], port
    sender = _udp()
    try:
        seen = _provoke(resolver_escapes, lambda: sender.sendto(b"x", (OFF_HOST, 9)))
    finally:
        sender.close()
    assert seen and "socket.sendto" in seen[0]


def test_a_name_resolved_inside_connect_is_refused(resolver_escapes):
    """`connect(("name", port))` asks the C resolver, which no Python hook
    sees. A name the hosts file answers is the only one that may be passed."""
    sock = _udp()
    try:
        seen = _provoke(resolver_escapes, lambda: sock.connect(("x.example", 9)))
        assert seen and "socket.connect" in seen[0]
        sock.connect(("localhost", 9))
    finally:
        sock.close()
    assert resolver_escapes == []


def test_the_reverse_and_extended_lookups_are_refused_off_host(resolver_escapes):
    """`getnameinfo` and `gethostbyname_ex` reach the resolver like
    `getaddrinfo` does, and were not wrapped."""
    seen = _provoke(
        resolver_escapes, lambda: socket.getnameinfo((OFF_HOST, 0), socket.NI_NAMEREQD)
    )
    assert seen and "getnameinfo" in seen[0]
    seen = _provoke(resolver_escapes, lambda: socket.gethostbyname_ex("x.example"))
    assert seen and "gethostbyname_ex" in seen[0]


def test_a_numeric_getnameinfo_and_a_loopback_lookup_are_not_queries(resolver_escapes):
    """`NI_NUMERICHOST` prints the address and asks nobody."""
    flags = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV
    assert socket.getnameinfo((OFF_HOST, 9), flags) == (OFF_HOST, "9")
    assert socket.gethostbyname_ex("localhost")[2]
    assert resolver_escapes == []


@pytest.mark.parametrize(
    "argv",
    [
        ["nslookup", "-type=ptr", "127.0.0.1"],
        ["nslookup", "-type=a", "localhost"],
        ["nslookup", "-type=a", "localhost", "127.0.0.53"],
    ],
)
def test_a_real_nslookup_is_judged_by_the_server_it_asks(resolver_escapes, argv):
    """`nslookup <local name>` still sends the query to the configured server,
    and a server argument on port 53 may be a forwarder. Only the arguments'
    locality was checked, so a reverse lookup of 127.0.0.1 went through."""
    seen = _provoke(resolver_escapes, lambda: subprocess.Popen(argv))
    assert seen and "nslookup" in seen[0]


def test_the_nslookup_backend_cannot_ask_about_a_local_name(resolver_escapes):
    seen = _provoke(
        resolver_escapes,
        lambda: netimps.resolve_nslookup("localhost", search=False, timeout=0.2),
    )
    assert seen and "nslookup" in seen[0]


@pytest.mark.parametrize("program", ["ping", "ping6", "traceroute", "tracert"])
def test_a_real_probe_of_a_name_or_an_off_host_address_is_refused(
    resolver_escapes, program
):
    """`ping` and `traceroute` resolve a name themselves, in C. The destination
    is the last argument on every grammar the library emits."""
    for destination in ("x.example", OFF_HOST):
        seen = _provoke(
            resolver_escapes,
            lambda: subprocess.Popen([program, "-n", "1", destination]),
        )
        assert seen and program in seen[0], destination


def test_an_address_of_this_host_is_a_destination_that_stays_here(resolver_escapes):
    """Several tests bind a listener on an interface address and connect to
    it; that is delivered locally. The platform decides what is this host's:
    only an address an interface holds can be bound."""
    candidates = [
        str(address.ip)
        for iface in netimps.get_interfaces()
        for address in iface.ips
        if not address.ip.is_loopback
    ]
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    own = None
    for text in candidates:
        if ":" in text:
            continue
        try:
            probe.bind((text, 0))
        except OSError:
            continue
        own = text
        break
    if own is None:
        probe.close()
        pytest.skip("no bindable non-loopback IPv4 address on this host")
    sender = _udp()
    try:
        sender.connect((own, probe.getsockname()[1]))
        sender.send(b"x")
        assert probe.recvfrom(16)[0] == b"x"
    finally:
        sender.close()
        probe.close()
    assert resolver_escapes == []


def test_the_explicit_way_through_lets_an_unroutable_address_be_connected(
    allow_off_host_destination, resolver_escapes
):
    """A test that connects a UDP socket to a TEST-NET address, which sends
    nothing, asks for the fixture and so says why in its own signature."""
    sock = _udp()
    try:
        sock.connect((OFF_HOST, 9))
    finally:
        sock.close()
    assert resolver_escapes == []
