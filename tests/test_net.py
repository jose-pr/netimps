"""Tests for the network-touching helpers -- fully mocked, never hits the network."""

import subprocess
import types

import pytest

import netutils
from netutils import active_nic_addresses, nslookup, ping
from netutils import IPv4Address


# --------------------------------------------------------------------------- #
# nslookup                                                                     #
# --------------------------------------------------------------------------- #

class _FakeAnswer:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)


class _FakeResolver:
    """Stand-in for dns.resolver.Resolver with a scripted result."""

    result = None
    error = None

    def __init__(self, configure=True):
        self.configure = configure
        self.nameservers = []

    def resolve(self, query, rtype):
        if type(self).error is not None:
            raise type(self).error
        return _FakeAnswer(type(self).result)


@pytest.fixture
def fake_dns(monkeypatch):
    fake_module = types.ModuleType("dns.resolver")
    fake_module.Resolver = _FakeResolver
    dns_pkg = types.ModuleType("dns")
    dns_pkg.resolver = fake_module
    monkeypatch.setitem(__import__("sys").modules, "dns", dns_pkg)
    monkeypatch.setitem(__import__("sys").modules, "dns.resolver", fake_module)
    _FakeResolver.result = None
    _FakeResolver.error = None
    return _FakeResolver


def test_nslookup_returns_list_of_strings(fake_dns):
    fake_dns.result = ["93.184.216.34"]
    result = nslookup("example.com")
    assert result == ["93.184.216.34"]
    assert isinstance(result, list)
    assert result[0] == "93.184.216.34"  # index-0 access is the documented contract


def test_nslookup_multiple_records(fake_dns):
    fake_dns.result = ["1.2.3.4", "5.6.7.8"]
    assert nslookup("example.com") == ["1.2.3.4", "5.6.7.8"]


def test_nslookup_returns_empty_list_on_error(fake_dns):
    fake_dns.error = Exception("NXDOMAIN")
    result = nslookup("does-not-exist.invalid")
    assert result == []
    assert not result  # falsy, so `if result:` guards correctly


def test_nslookup_custom_nameserver_string(fake_dns):
    fake_dns.result = ["8.8.8.8"]
    # Should not raise when a single ns string is provided.
    assert nslookup("example.com", ns="1.1.1.1") == ["8.8.8.8"]


# --------------------------------------------------------------------------- #
# ping                                                                         #
# --------------------------------------------------------------------------- #

def test_ping_empty_hostname_is_false():
    assert ping("") is False


def test_ping_success(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(netutils, "_run", fake_run)
    assert ping("127.0.0.1") is True
    assert calls[0][0] == "ping"
    assert "127.0.0.1" in calls[0]


def test_ping_failure_exhausts_tries(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=1)

    monkeypatch.setattr(netutils, "_run", fake_run)
    assert ping("10.255.255.1", tries=3) is False
    assert len(calls) == 3


# --------------------------------------------------------------------------- #
# active_nic_addresses                                                         #
# --------------------------------------------------------------------------- #

def test_active_nic_addresses_filters_loopback(monkeypatch):
    monkeypatch.setattr(
        netutils._socket,
        "gethostbyname_ex",
        lambda host: ("host", [], ["127.0.0.1", "192.168.1.10"]),
    )
    monkeypatch.setattr(netutils._socket, "gethostname", lambda: "host")
    addrs = active_nic_addresses()
    assert addrs == [IPv4Address("192.168.1.10")]


def test_active_nic_addresses_only_loopback_is_empty(monkeypatch):
    monkeypatch.setattr(
        netutils._socket,
        "gethostbyname_ex",
        lambda host: ("host", [], ["127.0.0.1"]),
    )
    monkeypatch.setattr(netutils._socket, "gethostname", lambda: "host")
    assert active_nic_addresses() == []
