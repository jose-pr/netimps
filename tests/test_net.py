"""Tests for the network-touching helpers -- fully mocked, never hits the network."""

import subprocess
import types

import pytest

import netimps
from netimps import ping, resolve
from netimps import IPv4Address

# --------------------------------------------------------------------------- #
# resolve                                                                     #
# --------------------------------------------------------------------------- #


class _FakeAnswer:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)


class _NXDOMAIN(Exception):
    """Stand-in for dns.resolver.NXDOMAIN."""


class _NoAnswer(Exception):
    """Stand-in for dns.resolver.NoAnswer."""


class _NoNameservers(Exception):
    """Stand-in for dns.resolver.NoNameservers."""


class _LifetimeTimeout(Exception):
    """Stand-in for dns.resolver.LifetimeTimeout."""


class _FakeResolver:
    """Stand-in for dns.resolver.Resolver with a scripted result.

    Records the settings applied to it so tests can assert that timeout/port/
    tcp are actually forwarded rather than silently dropped.
    """

    result = None
    error = None
    last = None

    def __init__(self, configure=True):
        self.configure = configure
        self.nameservers = []
        self.timeout = None
        self.lifetime = None
        self.port = 53

    def resolve(self, query, rtype, tcp=False):
        type(self).last = {
            "query": query,
            "rtype": rtype,
            "tcp": tcp,
            "timeout": self.timeout,
            "lifetime": self.lifetime,
            "port": self.port,
            "nameservers": list(self.nameservers),
            "configure": self.configure,
        }
        if type(self).error is not None:
            raise type(self).error
        return _FakeAnswer(type(self).result)


@pytest.fixture
def fake_dns(monkeypatch):
    fake_module = types.ModuleType("dns.resolver")
    fake_module.Resolver = _FakeResolver
    # The lookup-failure classes netimps catches by name.
    fake_module.NXDOMAIN = _NXDOMAIN
    fake_module.NoAnswer = _NoAnswer
    fake_module.NoNameservers = _NoNameservers
    fake_module.LifetimeTimeout = _LifetimeTimeout
    dns_pkg = types.ModuleType("dns")
    dns_pkg.resolver = fake_module
    monkeypatch.setitem(__import__("sys").modules, "dns", dns_pkg)
    monkeypatch.setitem(__import__("sys").modules, "dns.resolver", fake_module)
    _FakeResolver.result = None
    _FakeResolver.error = None
    _FakeResolver.last = None
    return _FakeResolver


def test_resolve_returns_list_of_strings(fake_dns):
    fake_dns.result = ["93.184.216.34"]
    result = resolve("example.com")
    assert result == ["93.184.216.34"]
    assert isinstance(result, list)
    assert result[0] == "93.184.216.34"  # index-0 access is the documented contract


def test_resolve_multiple_records(fake_dns):
    fake_dns.result = ["1.2.3.4", "5.6.7.8"]
    assert resolve("example.com") == ["1.2.3.4", "5.6.7.8"]


@pytest.mark.parametrize(
    "exc",
    [_NXDOMAIN, _NoAnswer, _NoNameservers, _LifetimeTimeout],
)
def test_resolve_returns_empty_list_on_lookup_failure(fake_dns, exc):
    """Every genuine 'no result' outcome honours the [] contract."""
    fake_dns.error = exc("boom")
    assert resolve("does-not-exist.invalid") == []


def test_resolve_raises_on_caller_error(fake_dns):
    """A malformed query is a bug, not a lookup result -- it must not become []."""
    fake_dns.error = ValueError("unknown rdtype 'nope'")
    with pytest.raises(ValueError, match="invalid DNS query"):
        resolve("example.com", "nope")


def test_resolve_forwards_timeout_port_and_tcp(fake_dns):
    fake_dns.result = ["1.2.3.4"]
    resolve("example.com", timeout=2.5, port=5353, tcp=True)
    assert fake_dns.last["tcp"] is True
    assert fake_dns.last["port"] == 5353
    # Both must be set: timeout bounds one query, lifetime the whole
    # resolution. Setting only timeout lets dead servers run long.
    assert fake_dns.last["timeout"] == 2.5
    assert fake_dns.last["lifetime"] == 2.5


def test_resolve_takes_rdtype_second(fake_dns):
    """The record type is positional-second -- the argument callers vary."""
    fake_dns.result = ["2606:2800::1"]
    assert resolve("example.com", "aaaa") == ["2606:2800::1"]
    assert fake_dns.last["rtype"] == "aaaa"


def test_resolve_custom_nameserver_string(fake_dns):
    fake_dns.result = ["8.8.8.8"]
    # Should not raise when a single ns string is provided.
    assert resolve("example.com", ns="1.1.1.1") == ["8.8.8.8"]


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

    monkeypatch.setattr(netimps, "_run", fake_run)
    assert ping("127.0.0.1") is True
    assert calls[0][0] == "ping"
    assert "127.0.0.1" in calls[0]


def test_ping_failure_exhausts_tries(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=1)

    monkeypatch.setattr(netimps, "_run", fake_run)
    assert ping("10.255.255.1", tries=3) is False
    assert len(calls) == 3


# --------------------------------------------------------------------------- #
# get_ip / is_link_scoped / get_default_port                        #
# --------------------------------------------------------------------------- #


def test_get_ip_parses_literals_without_dns(monkeypatch):
    """A literal must never trigger a lookup."""

    def explode(_):
        raise AssertionError("gethostbyname must not be called for a literal")

    monkeypatch.setattr(netimps._socket, "gethostbyname", explode)
    assert netimps.get_ip("10.0.0.5") == IPv4Address("10.0.0.5")


def test_get_ip_falls_back_to_dns(monkeypatch):
    monkeypatch.setattr(netimps._socket, "gethostbyname", lambda h: "93.184.216.34")
    assert netimps.get_ip("example.com") == IPv4Address("93.184.216.34")


def test_get_ip_returns_none_on_failure(monkeypatch):
    def fail(_):
        raise OSError("no such host")

    monkeypatch.setattr(netimps._socket, "gethostbyname", fail)
    assert netimps.get_ip("nope.invalid") is None


@pytest.mark.parametrize(
    "addr, expected",
    [
        ("127.0.0.1", True),
        ("::1", True),
        ("169.254.1.1", True),  # IPv4 link-local
        ("fe80::1", True),  # IPv6 link-local
        ("8.8.8.8", False),
        ("10.0.0.5", False),  # private, but routable -- not link-local
        ("2606:2800::1", False),
    ],
)
def test_is_link_scoped(addr, expected):
    assert netimps.is_link_scoped(netimps.parse(addr)) is expected


@pytest.mark.parametrize(
    "scheme, expected",
    [
        ("http", 80),
        ("https", 443),
        ("HTTPS", 443),
        ("ftp", 21),
        ("socks", 1080),
        ("socks5", 1080),
    ],
)
def test_get_default_port_known(scheme, expected):
    assert netimps.get_default_port(scheme) == expected


def test_get_default_port_unknown_is_none():
    assert netimps.get_default_port("definitely-not-a-scheme") is None


# --------------------------------------------------------------------------- #
# ping options                                                                 #
# --------------------------------------------------------------------------- #


def _capture_ping(monkeypatch, returncode=0):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, returncode)

    monkeypatch.setattr(netimps, "_run", fake_run)
    return calls


def test_ping_timeout_never_rounds_down_to_zero(monkeypatch):
    """A sub-second timeout must not become 0 -- some pings read that as forever."""
    calls = _capture_ping(monkeypatch)
    netimps.ping("host", timeout=0.2)
    cmd = calls[0][0]
    flag = "-w" if netimps._os.name == "nt" else "-W"
    value = int(cmd[cmd.index(flag) + 1])
    assert value >= 1


def test_ping_stops_at_first_success(monkeypatch):
    calls = _capture_ping(monkeypatch, returncode=0)
    assert netimps.ping("host", tries=5) is True
    assert len(calls) == 1  # succeeded first go, no wasted attempts


def test_ping_retries_until_tries_exhausted(monkeypatch):
    calls = _capture_ping(monkeypatch, returncode=1)
    assert netimps.ping("host", tries=3) is False
    assert len(calls) == 3


def test_ping_treats_zero_tries_as_one(monkeypatch):
    calls = _capture_ping(monkeypatch, returncode=1)
    assert netimps.ping("host", tries=0) is False
    assert len(calls) == 1


def test_ping_family_flags(monkeypatch):
    calls = _capture_ping(monkeypatch)
    netimps.ping("host", ipv6=True)
    assert "-6" in calls[0][0]
    calls.clear()
    netimps.ping("host", ipv6=False)
    assert "-4" in calls[0][0]
    calls.clear()
    netimps.ping("host")
    assert "-6" not in calls[0][0] and "-4" not in calls[0][0]


def test_ping_has_wall_clock_timeout(monkeypatch):
    """-W bounds the reply wait, not a hung resolver -- so cap the subprocess too."""
    calls = _capture_ping(monkeypatch)
    netimps.ping("host", timeout=2.0)
    assert calls[0][1]["timeout"] > 2.0


def test_ping_returns_false_when_binary_missing(monkeypatch):
    def no_binary(cmd, **kwargs):
        raise FileNotFoundError("ping not installed")

    monkeypatch.setattr(netimps, "_run", no_binary)
    assert netimps.ping("host") is False


def test_ping_returns_false_when_subprocess_hangs(monkeypatch):
    def hang(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(netimps, "_run", hang)
    assert netimps.ping("host") is False


# --------------------------------------------------------------------------- #
# port registry                                                                #
# --------------------------------------------------------------------------- #


@pytest.fixture
def clean_ports():
    """Snapshot/restore the port tables -- registration mutates module state."""
    import netimps as n

    ports = dict(n._DEFAULT_PORTS)
    schemes = dict(n._PORT_SCHEMES)
    yield
    n._DEFAULT_PORTS.clear()
    n._DEFAULT_PORTS.update(ports)
    n._PORT_SCHEMES.clear()
    n._PORT_SCHEMES.update(schemes)


def test_port_scheme_is_inverse_of_get_default_port():
    assert netimps.port_scheme(443) == "https"
    assert netimps.port_scheme(80) == "http"
    assert netimps.get_default_port(netimps.port_scheme(443)) == 443


def test_port_scheme_returns_canonical_not_alias():
    """1080 has three schemes; the first registered wins, not whichever is last."""
    assert netimps.port_scheme(1080) == "socks"


def test_register_port_round_trips(clean_ports):
    netimps.register_port("myproto", 9999)
    assert netimps.get_default_port("myproto") == 9999
    assert netimps.port_scheme(9999) == "myproto"


def test_register_port_is_case_insensitive(clean_ports):
    netimps.register_port("MyProto", 9998)
    assert netimps.get_default_port("myproto") == 9998
    assert netimps.get_default_port("MYPROTO") == 9998


def test_register_alias_does_not_steal_canonical_name(clean_ports):
    """Adding an alias must not silently change what a port maps back to."""
    netimps.register_port("secure-web", 443)
    assert netimps.get_default_port("secure-web") == 443
    assert netimps.port_scheme(443) == "https"  # unchanged

    netimps.register_port("secure-web", 443, canonical=True)
    assert netimps.port_scheme(443) == "secure-web"  # explicit override honoured


@pytest.mark.parametrize("port", [-1, 65536, 100000])
def test_register_port_rejects_out_of_range(clean_ports, port):
    with pytest.raises(ValueError):
        netimps.register_port("bad", port)


def test_register_port_rejects_bad_input(clean_ports):
    with pytest.raises(ValueError):
        netimps.register_port("", 80)
    with pytest.raises(TypeError):
        netimps.register_port("x", "80")


def test_port_scheme_unknown_is_none():
    assert netimps.port_scheme(65000) is None
