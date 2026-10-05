"""`Host`: the hostname-or-address value type and its resolution cache."""

import socket

import netimps
from netimps import Host

# --------------------------------------------------------------------------- #
# Host                                                                        #
# --------------------------------------------------------------------------- #


def test_host_keeps_the_original_text(no_such_host):
    """The whole point: str() is always what was given, even unresolvable."""
    host = Host("db.internal")
    assert str(host) == "db.internal"
    host.ip()  # may fail; must not change the text
    assert str(host) == "db.internal"


def test_host_literal_needs_no_dns(monkeypatch):
    def explode(_name):
        raise AssertionError("a literal must not trigger DNS")

    monkeypatch.setattr(netimps._ip._host._socket, "gethostbyname", explode)
    host = Host("10.0.0.5")
    assert host.is_address
    assert host.ip() == netimps.parse("10.0.0.5")


def test_host_caches_resolution(monkeypatch):
    calls = []

    def counting(name, *args, **kwargs):
        calls.append(name)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    # getaddrinfo, not gethostbyname: the latter is IPv4-only and no longer
    # called, so stubbing it would have quietly let this reach the real network.
    monkeypatch.setattr(netimps._ip._host._socket, "getaddrinfo", counting)
    host = Host("example.com")
    assert host.ip() == netimps.parse("93.184.216.34")
    assert host.ip() == netimps.parse("93.184.216.34")
    assert len(calls) == 1, "resolution should be cached"

    host.ip(refresh=True)
    assert len(calls) == 2, "refresh=True must retry"


def test_host_caches_failure_too(monkeypatch):
    calls = []

    def failing(name, *args, **kwargs):
        calls.append(name)
        raise socket.gaierror(socket.EAI_NONAME, "no such host")

    monkeypatch.setattr(netimps._ip._host._socket, "getaddrinfo", failing)
    host = Host("nope.invalid")
    assert host.ip() is None
    assert host.ip() is None
    assert len(calls) == 1, "a failed lookup should not be repeated by default"


def test_host_equality_and_falsiness():
    assert Host("x") == Host("x")
    assert Host("x") == "x"
    assert Host("x") != Host("y")
    assert not Host("")
    assert Host("x")
    assert Host(Host("nested")).value == "nested"
    assert hash(Host("x")) == hash(Host("x"))
