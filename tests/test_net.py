"""Tests for the network-touching helpers -- fully mocked, never hits the network."""

import subprocess
import types

import pytest

import netimps
from netimps import _dns, _ip, _ping
from netimps import ping, resolve
from netimps import resolve_dnspython, resolve_nslookup, resolve_system
from netimps import IPv4Address, IPv6Address
from netimps import IPv4Interface, IPv6Interface, IPv4Network, IPv6Network

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
    nameservers_setter = None  # optional class-level hook; raise to simulate a bad ns

    def __init__(self, configure=True):
        self.configure = configure
        self._nameservers = []
        self.search = []
        self.timeout = None
        self.lifetime = None
        self.port = 53

    @property
    def nameservers(self):
        return self._nameservers

    @nameservers.setter
    def nameservers(self, value):
        if type(self).nameservers_setter is not None:
            type(self).nameservers_setter(value)
        self._nameservers = value

    def resolve(self, query, rtype, tcp=False, search=None):
        type(self).last = {
            "query": query,
            "rtype": rtype,
            "tcp": tcp,
            "search": search,
            "search_domains": [str(d) for d in self.search],
            "timeout": self.timeout,
            "lifetime": self.lifetime,
            "port": self.port,
            "nameservers": list(self.nameservers),
            "configure": self.configure,
        }
        if type(self).error is not None:
            raise type(self).error
        return _FakeAnswer(type(self).result)

    def resolve_address(self, ipaddr, tcp=False, search=None):
        # Real dnspython builds the reverse (in-addr.arpa/ip6.arpa) name from
        # ipaddr itself and dispatches to resolve(rdtype="ptr") -- the fake
        # just records that it was called this way, with the raw address.
        return self.resolve(ipaddr, "ptr", tcp=tcp, search=search)


@pytest.fixture
def fake_dns(monkeypatch):
    import dns.name as _real_dns_name

    fake_module = types.ModuleType("dns.resolver")
    fake_module.Resolver = _FakeResolver
    # The lookup-failure classes netimps catches by name.
    fake_module.NXDOMAIN = _NXDOMAIN
    fake_module.NoAnswer = _NoAnswer
    fake_module.NoNameservers = _NoNameservers
    fake_module.LifetimeTimeout = _LifetimeTimeout
    dns_pkg = types.ModuleType("dns")
    dns_pkg.resolver = fake_module
    # dns.name is pure name-parsing, no network dependency -- reuse the real
    # module rather than reimplementing dns.name.from_text for the fake.
    dns_pkg.name = _real_dns_name
    monkeypatch.setitem(__import__("sys").modules, "dns", dns_pkg)
    monkeypatch.setitem(__import__("sys").modules, "dns.resolver", fake_module)
    monkeypatch.setitem(__import__("sys").modules, "dns.name", _real_dns_name)
    _FakeResolver.result = None
    _FakeResolver.error = None
    _FakeResolver.last = None
    _FakeResolver.nameservers_setter = None
    return _FakeResolver


def test_resolve_returns_native_address_objects(fake_dns):
    """Address records come back as ipaddress objects, not strings."""
    fake_dns.result = ["93.184.216.34"]
    result = resolve("example.com")
    assert isinstance(result, list)
    assert result == [IPv4Address("93.184.216.34")]
    # Usable as an address without re-parsing -- the point of the change.
    assert result[0].is_global


def test_resolve_non_address_records_stay_strings(fake_dns):
    """Non-address records stay str -- with the trailing root dot removed."""
    fake_dns.result = ["10 mail.example.com."]
    assert resolve("example.com", "mx") == ["10 mail.example.com"]


def test_resolve_strips_root_dot_from_names(fake_dns):
    fake_dns.result = ["ns1.example.com."]
    assert resolve("example.com", "ns") == ["ns1.example.com"]


def test_resolve_unquotes_txt(fake_dns):
    fake_dns.result = ['"v=spf1 -all"']
    assert resolve("example.com", "txt") == ["v=spf1 -all"]


def test_resolve_multiple_records(fake_dns):
    fake_dns.result = ["1.2.3.4", "5.6.7.8"]
    assert resolve("example.com") == [
        IPv4Address("1.2.3.4"),
        IPv4Address("5.6.7.8"),
    ]


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
    assert resolve("example.com", "aaaa") == [netimps.parse("2606:2800::1")]
    assert fake_dns.last["rtype"] == "aaaa"


def test_resolve_custom_nameserver_string(fake_dns):
    fake_dns.result = ["8.8.8.8"]
    # Should not raise when a single ns string is provided.
    assert resolve("example.com", ns="1.1.1.1") == [IPv4Address("8.8.8.8")]


def test_resolve_defaults_to_system_configuration_when_ns_omitted(fake_dns):
    """No `ns=` -> dnspython reads /etc/resolv.conf (or the Windows equivalent)."""
    fake_dns.result = ["1.2.3.4"]
    resolve("example.com")
    assert fake_dns.last["configure"] is True
    assert fake_dns.last["nameservers"] == []


def test_resolve_explicit_ns_disables_system_configuration(fake_dns):
    fake_dns.result = ["1.2.3.4"]
    resolve("example.com", ns="1.1.1.1")
    assert fake_dns.last["configure"] is False
    assert fake_dns.last["nameservers"] == ["1.1.1.1"]


def test_resolve_invalid_nameserver_raises_before_querying(fake_dns):
    """A bad `ns=` is a caller error -- it must not be swallowed into []."""

    def _raise(value):
        raise ValueError("not a valid nameserver: %r" % (value,))

    fake_dns.nameservers_setter = _raise
    with pytest.raises(ValueError, match="not a valid nameserver"):
        resolve("example.com", ns="not-an-ip")
    # The query must never have been attempted.
    assert fake_dns.last is None


def test_resolve_search_defaults_to_true(fake_dns):
    """Unqualified names try the system search list by default, like ping."""
    fake_dns.result = ["1.2.3.4"]
    resolve("host")
    assert fake_dns.last["search"] is True


@pytest.mark.parametrize("flag", [True, False])
def test_resolve_search_forwarded(fake_dns, flag):
    fake_dns.result = ["1.2.3.4"]
    resolve("host", search=flag)
    assert fake_dns.last["search"] is flag


def test_resolve_search_domain_list_sets_explicit_search_and_implies_true(fake_dns):
    """A list of domains replaces the system search list, regardless of `ns`."""
    fake_dns.result = ["1.2.3.4"]
    resolve("host", ns="1.1.1.1", search=["eng.example.com", "example.com"])
    assert fake_dns.last["search"] is True
    assert fake_dns.last["search_domains"] == ["eng.example.com.", "example.com."]


# --------------------------------------------------------------------------- #
# resolve_system                                                              #
# --------------------------------------------------------------------------- #


def _fake_getaddrinfo(records):
    def _impl(host, port, family=0, type=0, proto=0, flags=0):
        return [
            (
                fam,
                type,
                0,
                "",
                (addr, 0) if fam == _dns._socket.AF_INET else (addr, 0, 0, 0),
            )
            for fam, addr in records
        ]

    return _impl


def test_resolve_system_returns_native_address_objects(monkeypatch):
    monkeypatch.setattr(
        _dns._socket,
        "getaddrinfo",
        _fake_getaddrinfo([(_dns._socket.AF_INET, "93.184.216.34")]),
    )
    assert resolve_system("example.com") == [IPv4Address("93.184.216.34")]


def test_resolve_system_aaaa(monkeypatch):
    monkeypatch.setattr(
        _dns._socket,
        "getaddrinfo",
        _fake_getaddrinfo([(_dns._socket.AF_INET6, "2606:2800::1")]),
    )
    assert resolve_system("example.com", "aaaa") == [IPv6Address("2606:2800::1")]


def test_resolve_system_dedupes_addresses(monkeypatch):
    """getaddrinfo can list the same address once per socket type (SOCK_STREAM/DGRAM/RAW)."""
    monkeypatch.setattr(
        _dns._socket,
        "getaddrinfo",
        _fake_getaddrinfo(
            [
                (_dns._socket.AF_INET, "1.2.3.4"),
                (_dns._socket.AF_INET, "1.2.3.4"),
            ]
        ),
    )
    assert resolve_system("example.com") == [IPv4Address("1.2.3.4")]


def test_resolve_system_empty_on_lookup_failure(monkeypatch):
    def _raise(*a, **k):
        raise _dns._socket.gaierror("nodename nor servname provided")

    monkeypatch.setattr(_dns._socket, "getaddrinfo", _raise)
    assert resolve_system("does-not-exist.invalid") == []


@pytest.fixture
def hung_getaddrinfo(monkeypatch):
    """Patch getaddrinfo with a lookup that never answers on its own.

    Yields nothing: the fake blocks until the fixture releases it on teardown,
    so a test asserting on the *deadline* never has to actually wait one out.
    """
    import threading

    released = threading.Event()

    def _hang(*a, **k):
        released.wait(30.0)
        return []

    monkeypatch.setattr(_dns._socket, "getaddrinfo", _hang)
    try:
        yield
    finally:
        released.set()


def test_resolve_system_timeout_bounds_wall_time(hung_getaddrinfo):
    """`timeout=` must bound how long the *caller* waits, not merely what raises.

    The regression: running the lookup inside a
    ``with ThreadPoolExecutor(...)`` block made the timeout cosmetic --
    ``__exit__`` calls ``shutdown(wait=True)``, which joins the worker thread
    still stuck inside ``getaddrinfo``, so the caller waited out the whole
    hang and only the exception type changed.
    """
    import time

    start = time.monotonic()
    with pytest.raises(_dns.ResolutionError, match="timed out"):
        resolve_system("slow.example.invalid", timeout=0.1)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0, "waited %.2fs for a lookup capped at 0.1s" % elapsed


def test_resolve_system_search_list_timeout_is_per_candidate(hung_getaddrinfo):
    """Each candidate gets its own deadline; none of them may block past it."""
    import time

    start = time.monotonic()
    with pytest.raises(_dns.ResolutionError, match="timed out"):
        resolve_system("host", timeout=0.1, search=["a.example", "b.example"])
    assert time.monotonic() - start < 2.0


def test_resolve_chain_moves_on_when_system_backend_hangs(hung_getaddrinfo):
    """A hung OS resolver must not hold the whole chain past `timeout`."""
    import time

    start = time.monotonic()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(_dns, "_run", _fake_run(stdout=_NSLOOKUP_A_BIND))
        result = resolve("example.com", timeout=0.1, backends=["system", "nslookup"])
    elapsed = time.monotonic() - start
    assert result == [IPv4Address("104.20.23.154"), IPv4Address("172.66.147.243")]
    assert elapsed < 1.0, "the chain waited %.2fs on the hung backend" % elapsed


def test_resolve_system_rejects_non_address_rdtype():
    """system has no MX/TXT/etc equivalent -- this is a caller bug, not a lookup outcome."""
    with pytest.raises(_dns.ResolutionError):
        resolve_system("example.com", "mx")


def test_resolve_system_search_true_leaves_query_unqualified(monkeypatch):
    captured = {}

    def _impl(host, port, family=0, type=0, proto=0, flags=0):
        captured["host"] = host
        return [(_dns._socket.AF_INET, type, 0, "", ("1.2.3.4", 0))]

    monkeypatch.setattr(_dns._socket, "getaddrinfo", _impl)
    resolve_system("host")
    assert captured["host"] == "host"


def test_resolve_system_search_false_qualifies_with_trailing_dot(monkeypatch):
    """A trailing dot tells getaddrinfo not to apply its own search-list expansion."""
    captured = {}

    def _impl(host, port, family=0, type=0, proto=0, flags=0):
        captured["host"] = host
        return [(_dns._socket.AF_INET, type, 0, "", ("1.2.3.4", 0))]

    monkeypatch.setattr(_dns._socket, "getaddrinfo", _impl)
    resolve_system("host", search=False)
    assert captured["host"] == "host."


def test_resolve_system_search_false_does_not_double_qualify_an_fqdn(monkeypatch):
    captured = {}

    def _impl(host, port, family=0, type=0, proto=0, flags=0):
        captured["host"] = host
        return [(_dns._socket.AF_INET, type, 0, "", ("1.2.3.4", 0))]

    monkeypatch.setattr(_dns._socket, "getaddrinfo", _impl)
    resolve_system("host.example.com.", search=False)
    assert captured["host"] == "host.example.com."


def test_resolve_system_search_list_tries_candidates_in_order(monkeypatch):
    calls = []

    def _impl(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        if host == "host.eng.example.com":
            return [(_dns._socket.AF_INET, type, 0, "", ("1.2.3.4", 0))]
        raise _dns._socket.gaierror("nodename nor servname provided")

    monkeypatch.setattr(_dns._socket, "getaddrinfo", _impl)
    result = resolve_system("host", search=["eng.example.com", "example.com"])
    assert result == [IPv4Address("1.2.3.4")]
    assert calls == ["host", "host.eng.example.com"]


def test_resolve_system_search_list_ignores_empty_entries(monkeypatch):
    calls = []

    def _impl(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        raise _dns._socket.gaierror("nodename nor servname provided")

    monkeypatch.setattr(_dns._socket, "getaddrinfo", _impl)
    resolve_system("host", search=["", ".", "example.com"])
    assert calls == ["host", "host.example.com"]


def test_resolve_system_search_list_ignored_for_already_qualified_query(monkeypatch):
    calls = []

    def _impl(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        return [(_dns._socket.AF_INET, type, 0, "", ("1.2.3.4", 0))]

    monkeypatch.setattr(_dns._socket, "getaddrinfo", _impl)
    resolve_system("host.internal.", search=["example.com"])
    assert calls == ["host.internal."]


# --------------------------------------------------------------------------- #
# resolve_nslookup                                                            #
# --------------------------------------------------------------------------- #

_NSLOOKUP_A_BIND = (
    b"Server:\t\t192.0.2.1\nAddress:\t192.0.2.1#53\n\n"
    b"Non-authoritative answer:\n"
    b"Name:\texample.com\nAddress: 104.20.23.154\n"
    b"Name:\texample.com\nAddress: 172.66.147.243\n"
)

_NSLOOKUP_AAAA_WINDOWS = (
    b"Server:  ns1.example.net\r\nAddress:  192.0.2.1\r\n\r\n"
    b"Non-authoritative answer:\r\n"
    b"Name:    example.com\r\n"
    b"Addresses:  2606:4700:10::ac42:93f3\r\n"
    b"\t  2606:4700:10::6814:179a\r\n"
)

# A single "Addresses:" block mixing both families -- seen on some resolver
# configurations even for a single -type= query. The parser must filter to
# the requested family rather than trust the query type alone.
_NSLOOKUP_A_WINDOWS_MIXED_FAMILY = (
    b"Server:  ns1.example.net\r\nAddress:  192.0.2.1\r\n\r\n"
    b"Non-authoritative answer:\r\n"
    b"Name:    example.com\r\n"
    b"Addresses:  2606:4700:10::ac42:93f3\r\n"
    b"\t  2606:4700:10::6814:179a\r\n"
    b"\t  104.20.23.154\r\n"
    b"\t  172.66.147.243\r\n"
)

_NSLOOKUP_PTR = (
    b"Server:\t\t192.0.2.1\nAddress:\t192.0.2.1#53\n\n"
    b"8.8.8.8.in-addr.arpa\tname = dns.google.\n"
)

# Windows NODATA: a name whose parent zone exists but has no record of the
# requested type. Exit 0, no error text anywhere, no Address(es): line --
# just a bare Name:. Verified against live `nslookup -type=a` output.
_NSLOOKUP_A_WINDOWS_NODATA = (
    b"Server:  ns1.example.net\r\nAddress:  192.0.2.1\r\n\r\n"
    b"Name:    nonexistent-xyz-abc.example.com\r\n\r\n"
)


def _fake_run(stdout=b"", stderr=b"", returncode=0):
    def _impl(cmd, capture_output=True, timeout=None):
        return subprocess.CompletedProcess(
            cmd, returncode, stdout=stdout, stderr=stderr
        )

    return _impl


def test_resolve_nslookup_bind_style(monkeypatch):
    monkeypatch.setattr(_dns, "_run", _fake_run(stdout=_NSLOOKUP_A_BIND))
    assert resolve_nslookup("example.com") == [
        IPv4Address("104.20.23.154"),
        IPv4Address("172.66.147.243"),
    ]


def test_resolve_nslookup_windows_style_reads_continuation_lines(monkeypatch):
    """Windows wraps extra addresses onto unlabeled indented lines -- must not drop them."""
    monkeypatch.setattr(_dns, "_run", _fake_run(stdout=_NSLOOKUP_AAAA_WINDOWS))
    result = resolve_nslookup("example.com", "aaaa")
    assert result == [
        IPv6Address("2606:4700:10::ac42:93f3"),
        IPv6Address("2606:4700:10::6814:179a"),
    ]


def test_resolve_nslookup_windows_style_filters_mixed_family_block(monkeypatch):
    """A single Addresses: block can mix families -- filter to what rdtype asked for."""
    monkeypatch.setattr(
        _dns, "_run", _fake_run(stdout=_NSLOOKUP_A_WINDOWS_MIXED_FAMILY)
    )
    assert resolve_nslookup("example.com", "a") == [
        IPv4Address("104.20.23.154"),
        IPv4Address("172.66.147.243"),
    ]
    assert resolve_nslookup("example.com", "aaaa") == [
        IPv6Address("2606:4700:10::ac42:93f3"),
        IPv6Address("2606:4700:10::6814:179a"),
    ]


def test_resolve_nslookup_ptr(monkeypatch):
    monkeypatch.setattr(_dns, "_run", _fake_run(stdout=_NSLOOKUP_PTR))
    assert resolve_nslookup("8.8.8.8", "ptr") == ["dns.google"]


def test_resolve_nslookup_nxdomain_on_stderr_is_empty_not_an_error(monkeypatch):
    """Windows nslookup prints the NXDOMAIN line on stderr, not stdout."""
    monkeypatch.setattr(
        _dns,
        "_run",
        _fake_run(
            stdout=b"Server:  x\r\nAddress:  192.0.2.1\r\n\r\n",
            stderr=b"*** x can't find nope.invalid: Non-existent domain\r\n",
        ),
    )
    assert resolve_nslookup("nope.invalid") == []


def test_resolve_nslookup_windows_nodata_is_empty_not_a_parse_error(monkeypatch):
    """A bare 'Name:' with no Address(es): line, exit 0, no error text -- NODATA."""
    monkeypatch.setattr(_dns, "_run", _fake_run(stdout=_NSLOOKUP_A_WINDOWS_NODATA))
    assert resolve_nslookup("nonexistent-xyz-abc.example.com") == []


def test_resolve_nslookup_missing_binary_raises_resolution_error(monkeypatch):
    def _raise(*a, **k):
        raise FileNotFoundError("no nslookup")

    monkeypatch.setattr(_dns, "_run", _raise)
    with pytest.raises(_dns.ResolutionError):
        resolve_nslookup("example.com")


def test_resolve_nslookup_rejects_unsupported_rdtype():
    with pytest.raises(_dns.ResolutionError):
        resolve_nslookup("example.com", "mx")


def test_resolve_nslookup_passes_ns_as_trailing_server_arg(monkeypatch):
    captured = {}

    def _impl(cmd, capture_output=True, timeout=None):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=_NSLOOKUP_A_BIND)

    monkeypatch.setattr(_dns, "_run", _impl)
    resolve_nslookup("example.com", ns="1.1.1.1")
    assert captured["cmd"][-2:] == ["example.com", "1.1.1.1"]


def test_resolve_nslookup_search_false_qualifies_with_trailing_dot(monkeypatch):
    captured = {}

    def _impl(cmd, capture_output=True, timeout=None):
        captured["query"] = cmd[2]
        return subprocess.CompletedProcess(cmd, 0, stdout=_NSLOOKUP_A_BIND)

    monkeypatch.setattr(_dns, "_run", _impl)
    resolve_nslookup("host", search=False)
    assert captured["query"] == "host."


def test_resolve_nslookup_search_true_tries_search_domains_in_order(monkeypatch):
    """First candidate NXDOMAINs (empty, no error) -> the next suffix is tried."""
    calls = []

    def _impl(cmd, capture_output=True, timeout=None):
        query = cmd[2]
        calls.append(query)
        if query == "host.eng.example.com":
            return subprocess.CompletedProcess(cmd, 0, stdout=_NSLOOKUP_A_BIND)
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout=b"",
            stderr=b"** server can't find %s: NXDOMAIN\n" % query.encode(),
        )

    monkeypatch.setattr(_dns, "_run", _impl)
    monkeypatch.setattr(
        _dns, "_system_search_domains", lambda: ["eng.example.com", "example.com"]
    )
    result = resolve_nslookup("host")
    assert result == [IPv4Address("104.20.23.154"), IPv4Address("172.66.147.243")]
    assert calls == ["host", "host.eng.example.com"]


def test_resolve_nslookup_search_list_overrides_system_list(monkeypatch):
    calls = []

    def _impl(cmd, capture_output=True, timeout=None):
        calls.append(cmd[2])
        return subprocess.CompletedProcess(
            cmd, 1, stdout=b"", stderr=b"** server can't find x: NXDOMAIN\n"
        )

    monkeypatch.setattr(_dns, "_run", _impl)
    monkeypatch.setattr(
        _dns, "_system_search_domains", lambda: ["should-not-be-used.com"]
    )
    resolve_nslookup("host", search=["only-this.example.com"])
    assert calls == ["host", "host.only-this.example.com"]


def test_resolve_nslookup_search_ignores_empty_domain_entries(monkeypatch):
    calls = []

    def _impl(cmd, capture_output=True, timeout=None):
        query = cmd[2]
        calls.append(query)
        # Every candidate NXDOMAINs, so every one actually gets tried and the
        # full candidate list -- not just whichever one happens to "win" --
        # is what's under test here.
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout=b"",
            stderr=b"** server can't find %s: NXDOMAIN\n" % query.encode(),
        )

    monkeypatch.setattr(_dns, "_run", _impl)
    resolve_nslookup("host", search=["", ".", "example.com"])
    # An empty/root entry must not produce a spurious "host." candidate
    # distinct from the plain "host" already tried first.
    assert calls == ["host", "host.example.com"]


def test_resolve_nslookup_search_ignored_for_ptr(monkeypatch):
    calls = []

    def _impl(cmd, capture_output=True, timeout=None):
        calls.append(cmd[2])
        return subprocess.CompletedProcess(cmd, 0, stdout=_NSLOOKUP_PTR)

    monkeypatch.setattr(_dns, "_run", _impl)
    monkeypatch.setattr(_dns, "_system_search_domains", lambda: ["example.com"])
    resolve_nslookup("8.8.8.8", "ptr")
    assert calls == ["8.8.8.8"]


def test_resolve_nslookup_search_ignored_for_already_qualified_query(monkeypatch):
    calls = []

    def _impl(cmd, capture_output=True, timeout=None):
        calls.append(cmd[2])
        return subprocess.CompletedProcess(cmd, 0, stdout=_NSLOOKUP_A_BIND)

    monkeypatch.setattr(_dns, "_run", _impl)
    monkeypatch.setattr(_dns, "_system_search_domains", lambda: ["example.com"])
    resolve_nslookup("host.internal.")
    assert calls == ["host.internal."]


def test_system_search_domains_falls_back_to_empty_without_dnspython(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def _blocked_import(name, *a, **k):
        if name == "dns" or name.startswith("dns."):
            raise ImportError("blocked for test")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _blocked_import)
    assert _dns._system_search_domains() == []


# --------------------------------------------------------------------------- #
# resolve -- backend chain orchestration                                     #
# --------------------------------------------------------------------------- #


def test_resolve_chain_falls_through_on_resolution_error(monkeypatch):
    """dnspython unavailable -> system is tried next."""

    def _dnspython_fails(*a, **k):
        raise _dns.ResolutionError("dnspython is not installed")

    monkeypatch.setattr(_dns, "resolve_dnspython", _dnspython_fails)
    monkeypatch.setattr(
        _dns, "resolve_system", lambda *a, **k: [IPv4Address("9.9.9.9")]
    )
    assert resolve("example.com") == [IPv4Address("9.9.9.9")]


def test_resolve_chain_stops_at_first_definitive_empty_answer(monkeypatch):
    """A real NXDOMAIN from the first backend is the answer -- not overridden by trying more."""
    calls = []

    def _dnspython_nxdomain(*a, **k):
        calls.append("dnspython")
        return []

    def _system_should_not_run(*a, **k):
        calls.append("system")
        return [IPv4Address("1.2.3.4")]

    monkeypatch.setattr(_dns, "resolve_dnspython", _dnspython_nxdomain)
    monkeypatch.setattr(_dns, "resolve_system", _system_should_not_run)
    assert resolve("does-not-exist.invalid") == []
    assert calls == ["dnspython"]


def test_resolve_chain_skips_system_for_non_address_rdtype(monkeypatch):
    calls = []

    def _dnspython(query, rdtype, **kwargs):
        calls.append("dnspython")
        return ["10 mail.example.com"]

    def _system_should_not_run(*a, **k):
        calls.append("system")
        return []

    monkeypatch.setattr(_dns, "resolve_dnspython", _dnspython)
    monkeypatch.setattr(_dns, "resolve_system", _system_should_not_run)
    assert resolve("example.com", "mx") == ["10 mail.example.com"]
    assert calls == ["dnspython"]


def test_resolve_chain_skips_system_when_ns_given(monkeypatch):
    calls = []

    def _dnspython(query, rdtype, **kwargs):
        calls.append("dnspython")
        return [IPv4Address("1.2.3.4")]

    def _system_should_not_run(*a, **k):
        calls.append("system")
        return []

    monkeypatch.setattr(_dns, "resolve_dnspython", _dnspython)
    monkeypatch.setattr(_dns, "resolve_system", _system_should_not_run)
    resolve("example.com", ns="1.1.1.1")
    assert calls == ["dnspython"]


def test_resolve_chain_tries_all_and_raises_last_error_when_all_fail(monkeypatch):
    def _dnspython_fails(*a, **k):
        raise _dns.ResolutionError("dnspython is not installed")

    def _system_fails(*a, **k):
        raise _dns.ResolutionError("getaddrinfo timed out")

    def _nslookup_fails(*a, **k):
        raise _dns.ResolutionError("nslookup binary not found")

    monkeypatch.setattr(_dns, "resolve_dnspython", _dnspython_fails)
    monkeypatch.setattr(_dns, "resolve_system", _system_fails)
    monkeypatch.setattr(_dns, "resolve_nslookup", _nslookup_fails)
    with pytest.raises(_dns.ResolutionError, match="nslookup binary not found"):
        resolve("example.com")


def test_resolve_backends_accepts_single_string():
    """backends="system" behaves like backends=["system"]."""
    assert resolve("localhost", backends="system") == resolve(
        "localhost", backends=["system"]
    )


def test_resolve_backends_restricts_and_orders_the_chain(monkeypatch):
    calls = []

    def _nslookup(query, rdtype, **kwargs):
        calls.append("nslookup")
        return [IPv4Address("5.5.5.5")]

    def _dnspython_should_not_run(*a, **k):
        calls.append("dnspython")
        return [IPv4Address("1.1.1.1")]

    monkeypatch.setattr(_dns, "resolve_nslookup", _nslookup)
    monkeypatch.setattr(_dns, "resolve_dnspython", _dnspython_should_not_run)
    assert resolve("example.com", backends=["nslookup", "dnspython"]) == [
        IPv4Address("5.5.5.5")
    ]
    assert calls == ["nslookup"]


def test_resolve_unknown_backend_name_raises_value_error():
    with pytest.raises(ValueError, match="unknown resolve backend"):
        resolve("example.com", backends=["carrier-pigeon"])


def test_resolve_raises_when_no_backend_can_serve_request(monkeypatch):
    """rdtype='mx' with backends=['system'] -- system can't do MX, nothing else to try."""
    with pytest.raises(ValueError, match="no backend"):
        resolve("example.com", "mx", backends=["system"])


# --------------------------------------------------------------------------- #
# resolve -- rdtype=None auto-selects a/ptr                                   #
# --------------------------------------------------------------------------- #


def test_resolve_auto_rdtype_hostname_is_a(fake_dns):
    fake_dns.result = ["1.2.3.4"]
    resolve("example.com")
    assert fake_dns.last["rtype"] == "a"


def test_resolve_auto_rdtype_address_is_ptr(fake_dns):
    fake_dns.result = ["dns.google."]
    result = resolve("8.8.8.8")
    assert fake_dns.last["rtype"] == "ptr"
    assert fake_dns.last["query"] == "8.8.8.8"
    assert result == ["dns.google"]


def test_resolve_auto_rdtype_ipv6_address_is_ptr(fake_dns):
    fake_dns.result = ["example.com."]
    resolve("2001:db8::1")
    assert fake_dns.last["rtype"] == "ptr"


def test_resolve_explicit_rdtype_a_on_address_is_not_overridden(fake_dns):
    """An explicit rdtype="a" on a literal address is still attempted literally."""
    fake_dns.result = []
    resolve("8.8.8.8", "a")
    assert fake_dns.last["rtype"] == "a"


def test_resolve_dnspython_auto_rdtype_matches_resolve(fake_dns):
    fake_dns.result = ["dns.google."]
    assert resolve_dnspython("8.8.8.8") == ["dns.google"]
    assert fake_dns.last["rtype"] == "ptr"


def test_resolve_accepts_address_object_as_query(fake_dns):
    fake_dns.result = ["dns.google."]
    resolve(IPv4Address("8.8.8.8"))
    assert fake_dns.last["query"] == "8.8.8.8"
    assert fake_dns.last["rtype"] == "ptr"


def test_resolve_accepts_interface_object_as_query(fake_dns):
    """The .ip is queried, not the interface stringified with its /prefix."""
    fake_dns.result = ["dns.google."]
    resolve(IPv4Interface("8.8.8.8/32"))
    assert fake_dns.last["query"] == "8.8.8.8"
    assert fake_dns.last["rtype"] == "ptr"


def test_resolve_system_auto_rdtype_ptr(monkeypatch):
    def fake_gethostbyaddr(query):
        return ("dns.google", [], ["8.8.8.8"])

    monkeypatch.setattr(_dns._socket, "gethostbyaddr", fake_gethostbyaddr)
    assert resolve_system("8.8.8.8") == ["dns.google"]


def test_resolve_system_ptr_no_data_is_empty(monkeypatch):
    def fake_gethostbyaddr(query):
        raise _dns._socket.herror("unknown host")

    monkeypatch.setattr(_dns._socket, "gethostbyaddr", fake_gethostbyaddr)
    assert resolve_system("203.0.113.1", "ptr") == []


def test_resolve_nslookup_auto_rdtype_ptr(monkeypatch):
    monkeypatch.setattr(_dns, "_run", _fake_run(stdout=_NSLOOKUP_PTR))
    assert resolve_nslookup("8.8.8.8") == ["dns.google"]


# --------------------------------------------------------------------------- #
# ping                                                                         #
# --------------------------------------------------------------------------- #


def test_ping_empty_hostname_is_false():
    assert bool(ping("")) is False


_REPLY = b"Reply from 127.0.0.1: bytes=32 time=1ms TTL=128\n"


def test_ping_accepts_interface_object(monkeypatch):
    """An IPv4Interface's .ip is pinged -- not the address stringified with /prefix."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=_REPLY)

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    result = ping(IPv4Interface("127.0.0.1/8"))
    assert bool(result) is True
    assert "127.0.0.1" in calls[0]
    assert "127.0.0.1/8" not in calls[0]


def test_ping_accepts_address_object(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=_REPLY)

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    assert bool(ping(IPv4Address("127.0.0.1"))) is True
    assert "127.0.0.1" in calls[0]


def test_ping_rejects_network():
    with pytest.raises(TypeError, match="not a network"):
        ping(IPv4Network("10.0.0.0/24"))
    with pytest.raises(TypeError, match="not a network"):
        ping(IPv6Network("2001:db8::/64"))


def test_ping_accepts_ipv6_interface_object(monkeypatch):
    calls = []
    ipv6_reply = b"Reply from ::1: bytes=32 time=1ms TTL=128\n"

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=ipv6_reply)

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    assert bool(ping(IPv6Interface("::1/128"))) is True
    assert "::1" in calls[0]
    assert "::1/128" not in calls[0]


def test_ping_unusable_src_is_falsy_not_a_crash(monkeypatch):
    """A src with no usable address must yield a falsy result, not NameError."""
    monkeypatch.setattr(netimps._ping, "_interface_address", lambda *a, **k: None)
    result = ping("8.8.8.8", src="nonexistent-adapter")
    assert bool(result) is False
    assert result.host == "8.8.8.8"


def test_ping_success(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=_REPLY)

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    assert bool(ping("127.0.0.1")) is True
    assert calls[0][0] == "ping"
    assert "127.0.0.1" in calls[0]


def test_ping_reports_rtt_and_ttl(monkeypatch):
    """The result carries the reply details, not just a boolean."""

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=_REPLY)

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    result = ping("127.0.0.1")
    assert result.ok is True
    assert result.rtt_ms == 1.0
    assert result.ttl == 128
    assert result.attempts == 1


def test_ping_zero_exit_is_not_enough_without_a_matching_reply(monkeypatch):
    """Windows exits 0 for 'TTL expired in transit' -- a router, not the target.

    The reply address is verified, so output that never names the destination
    as an answering host must not count as success.
    """

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 0, stdout=b"Reply from 192.0.2.1: TTL expired in transit.\n"
        )

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    assert bool(ping("8.8.8.8")) is False


def test_ping_result_is_boolean_compatible():
    """Existing `if ping(...)` and `== True` call sites must keep working."""
    ok = netimps.PingResult(True, "h", rtt_ms=1.0, ttl=64)
    bad = netimps.PingResult(False, "h")
    assert ok and not bad
    assert ok == True  # noqa: E712 - the compatibility being asserted
    assert bad == False  # noqa: E712
    assert bool(ok) is True and bool(bad) is False
    # rtt_ms of 0.0 (sub-millisecond) is falsy but present.
    assert netimps.PingResult(True, "h", rtt_ms=0.0).rtt_ms is not None


def test_ping_failure_exhausts_tries(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, stdout=b"")

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    assert bool(ping("10.255.255.1", tries=3)) is False
    assert len(calls) == 3


# --------------------------------------------------------------------------- #
# get_ip / is_link_scoped / get_default_port                        #
# --------------------------------------------------------------------------- #


def test_get_ip_parses_literals_without_dns(monkeypatch):
    """A literal must never trigger a lookup."""

    def explode(_):
        raise AssertionError("gethostbyname must not be called for a literal")

    monkeypatch.setattr(netimps._ip._socket, "gethostbyname", explode)
    assert netimps.get_ip("10.0.0.5") == IPv4Address("10.0.0.5")


def test_get_ip_falls_back_to_dns(monkeypatch):
    monkeypatch.setattr(netimps._ip._socket, "gethostbyname", lambda h: "93.184.216.34")
    assert netimps.get_ip("example.com") == IPv4Address("93.184.216.34")


def test_get_ip_returns_none_on_failure(monkeypatch):
    def fail(_):
        raise OSError("no such host")

    monkeypatch.setattr(netimps._ip._socket, "gethostbyname", fail)
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
        ("ws", 80),
        ("wss", 443),
        ("ftp", 21),
        ("socks", 1080),
        ("socks5", 1080),
    ],
)
def test_get_default_port_known(scheme, expected):
    assert netimps.get_default_port(scheme) == expected


def test_websocket_schemes_do_not_steal_http_canonical():
    """ws/wss share 80/443 with http/https; http/https stay canonical."""
    assert netimps.get_default_scheme(80) == "http"
    assert netimps.get_default_scheme(443) == "https"


def test_get_default_port_unknown_is_none():
    assert netimps.get_default_port("definitely-not-a-scheme") is None


# --------------------------------------------------------------------------- #
# ping options                                                                 #
# --------------------------------------------------------------------------- #


def _capture_ping(monkeypatch, returncode=0):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, returncode, stdout=b"")

    def no_dns(host):
        raise OSError("DNS disabled in tests")

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    monkeypatch.setattr(netimps._ping._socket, "gethostbyname", no_dns)
    return calls


def test_ping_timeout_never_rounds_down_to_zero(monkeypatch):
    """A sub-second timeout must not become 0 -- some pings read that as forever."""
    calls = _capture_ping(monkeypatch)
    netimps.ping("host", timeout=0.2)
    cmd = calls[0][0]
    flag = "-w" if _ping._os.name == "nt" else "-W"
    value = int(cmd[cmd.index(flag) + 1])
    assert value >= 1


def test_ping_stops_at_first_success(monkeypatch):
    calls = _capture_ping(monkeypatch, returncode=0)
    assert bool(netimps.ping("host", tries=5)) is True
    assert len(calls) == 1  # succeeded first go, no wasted attempts


def test_ping_retries_until_tries_exhausted(monkeypatch):
    calls = _capture_ping(monkeypatch, returncode=1)
    assert bool(netimps.ping("host", tries=3)) is False
    assert len(calls) == 3


def test_ping_treats_zero_tries_as_one(monkeypatch):
    calls = _capture_ping(monkeypatch, returncode=1)
    assert bool(netimps.ping("host", tries=0)) is False
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

    monkeypatch.setattr(netimps._ping, "_run", no_binary)
    assert bool(netimps.ping("host")) is False


def test_ping_returns_false_when_subprocess_hangs(monkeypatch):
    def hang(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(netimps._ping, "_run", hang)
    assert bool(netimps.ping("host")) is False


# --------------------------------------------------------------------------- #
# port registry                                                                #
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


def test_get_default_scheme_is_inverse_of_get_default_port():
    assert netimps.get_default_scheme(443) == "https"
    assert netimps.get_default_scheme(80) == "http"
    assert netimps.get_default_port(netimps.get_default_scheme(443)) == 443


def test_get_default_scheme_returns_canonical_not_alias():
    """1080 has three schemes; the first registered wins, not whichever is last."""
    assert netimps.get_default_scheme(1080) == "socks"


def test_register_port_round_trips(clean_ports):
    netimps.register_port("myproto", 9999)
    assert netimps.get_default_port("myproto") == 9999
    assert netimps.get_default_scheme(9999) == "myproto"


def test_register_port_is_case_insensitive(clean_ports):
    netimps.register_port("MyProto", 9998)
    assert netimps.get_default_port("myproto") == 9998
    assert netimps.get_default_port("MYPROTO") == 9998


def test_register_alias_does_not_steal_canonical_name(clean_ports):
    """Adding an alias must not silently change what a port maps back to."""
    netimps.register_port("secure-web", 443)
    assert netimps.get_default_port("secure-web") == 443
    assert netimps.get_default_scheme(443) == "https"  # unchanged

    netimps.register_port("secure-web", 443, canonical=True)
    assert netimps.get_default_scheme(443) == "secure-web"  # explicit override honoured


@pytest.mark.parametrize("port", [-1, 65536, 100000])
def test_register_port_rejects_out_of_range(clean_ports, port):
    with pytest.raises(ValueError):
        netimps.register_port("bad", port)


def test_register_port_rejects_bad_input(clean_ports):
    with pytest.raises(ValueError):
        netimps.register_port("", 80)
    with pytest.raises(TypeError):
        netimps.register_port("x", "80")


def test_get_default_scheme_unknown_is_none():
    assert netimps.get_default_scheme(65000) is None


def test_ping_size_is_the_payload_not_the_wire_packet(monkeypatch):
    """size= is the ICMP payload on both platforms; neither flag counts headers.

    Pinned because getting it backwards skews discover_mtu by exactly 28 bytes,
    and the two platforms use different letters (-l on Windows, -s on POSIX)
    for the same meaning.
    """
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout=_REPLY)

    monkeypatch.setattr(netimps._ping, "_run", fake_run)
    ping("127.0.0.1", size=1472)
    cmd = calls[0]
    flag = "-l" if netimps._ping._os.name == "nt" else "-s"
    assert flag in cmd
    # Passed straight through -- no header arithmetic applied here.
    assert cmd[cmd.index(flag) + 1] == "1472"
