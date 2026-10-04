"""The suite's network guard refuses an off-host query from every backend.

The guard in `conftest.py` used to patch `getaddrinfo`, `gethostbyname` and
`gethostbyaddr` only. `resolve_wire` and `resolve_dnspython` open their own
sockets, `resolve_doh` goes through `urllib` and `resolve_nslookup` runs a
program, so a test resolving through any of them reached a real name server
unseen. Each test here sends one deliberately off-host query -- to TEST-NET-1,
which nothing answers, with a short timeout so a failure of the guard shows as
a slow test and not a hang -- and expects the guard to have stopped it.
"""

import socket

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
    assert seen and "urllib.request.urlopen" in seen[0]


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
