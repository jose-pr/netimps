"""`Host` and `FQDN` resolve through `resolve()`, `ip()` and `fqdn()`.

Which calls look anything up, which backend answers when no option is passed,
what `check=` turns into an exception, and what the per-object memo does.
Every test runs under the suite's network guard, so a lookup that should not
happen fails at the call, and a name that must "not resolve" uses
`no_such_host` rather than trusting the resolver.
"""

import socket

import pytest

import netimps
from netimps import FQDN, Host, ResolutionError

DB = netimps.parse("192.0.2.9")
DB6 = netimps.parse("2001:db8::9")


def _answer(*addresses):
    """A `getaddrinfo` result for `addresses`, in the order given."""

    def getaddrinfo(name, port, family=0, type=0, *rest):
        calls.append((name, family))
        return [
            (
                socket.AF_INET6 if address.version == 6 else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (str(address), 0),
            )
            for address in addresses
        ]

    calls = getaddrinfo.calls = []
    return getaddrinfo


# -- what makes a lookup ---------------------------------------------------


def test_an_address_needs_no_lookup_to_give_its_ip():
    """The guard fails any lookup, so reaching the end is the assertion."""
    host = Host("10.0.0.5")
    assert host.ip() == netimps.parse("10.0.0.5")
    assert host.ip(check=True, ipv6=True, ns="192.0.2.53") == host.ip()
    assert Host("2001:db8::5").ip() == netimps.parse("2001:db8::5")


def test_a_name_needs_no_lookup_to_give_its_fqdn():
    assert Host("a.example").fqdn() == FQDN("a.example")
    assert Host("a.example").fqdn(check=True, ns="192.0.2.53") == FQDN("a.example")
    assert str(Host("WWW.Example.COM").fqdn()) == "WWW.Example.COM"


def test_the_guard_refuses_a_reverse_lookup_of_an_off_host_address(resolver_escapes):
    """Reverse-looking-up an address literal is a query for somebody's PTR
    record. The guard used to wave every literal through, which would let the
    `fqdn()` of an address reach a real resolver unseen."""
    with pytest.raises(AssertionError):
        socket.gethostbyaddr("192.0.2.1")
    assert len(resolver_escapes) == 1
    resolver_escapes.clear()


def test_an_address_reverses_to_a_name(monkeypatch):
    seen = []

    def gethostbyaddr(address):
        seen.append(address)
        return ("db.internal", [], [address])

    monkeypatch.setattr(socket, "gethostbyaddr", gethostbyaddr)
    assert Host("192.0.2.9").fqdn() == FQDN("db.internal")
    assert seen == ["192.0.2.9"]


def test_a_name_resolves_to_an_address(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _answer(DB))
    assert Host("db.internal").ip() == DB


# -- the pair ----------------------------------------------------------------


def test_resolve_of_a_name_is_the_name_and_a_forward_lookup(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _answer(DB))
    assert Host("db.internal").resolve() == (FQDN("db.internal"), DB)


def test_resolve_of_an_address_is_a_reverse_lookup_and_the_literal(monkeypatch):
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda address: ("db.internal", [], [address])
    )
    assert Host("192.0.2.9").resolve() == (FQDN("db.internal"), DB)


def test_resolve_is_always_a_pair(no_such_host):
    """`fqdn, ip = host.resolve()` must never fail to unpack."""
    fqdn, ip = Host("no-such.invalid").resolve()
    assert (fqdn, ip) == (FQDN("no-such.invalid"), None)
    assert Host("192.0.2.9").resolve() == (None, DB)
    assert Host("").resolve() == (None, None)


# -- check= ------------------------------------------------------------------


def test_check_raises_for_a_name_that_does_not_resolve(no_such_host):
    assert Host("no-such.invalid").ip() is None
    with pytest.raises(ResolutionError):
        Host("no-such.invalid").ip(check=True)
    with pytest.raises(ResolutionError):
        FQDN("no-such.invalid").ip(check=True)


def test_check_raises_for_an_address_with_no_reverse_name(no_such_host):
    assert Host("192.0.2.9").fqdn() is None
    with pytest.raises(ResolutionError):
        Host("192.0.2.9").fqdn(check=True)


def test_check_raises_for_an_empty_host():
    assert Host("").ip() is None
    with pytest.raises(ResolutionError):
        Host("").ip(check=True)


def test_check_raises_when_the_name_is_not_a_possible_name():
    assert Host("a..b").fqdn() is None
    with pytest.raises(ValueError):
        Host("a..b").fqdn(check=True)


def test_check_re_raises_an_outage_that_the_default_hides(monkeypatch):
    """Without `check` an unreachable resolver looks like a missing name."""

    def down(*args, **kwargs):
        raise ResolutionError("resolver unreachable")

    monkeypatch.setattr(netimps._dns, "resolve_system", down)
    assert Host("db.internal").ip() is None
    with pytest.raises(ResolutionError, match="unreachable"):
        Host("db.internal").ip(check=True)


# -- which backends answer ------------------------------------------------------


def _spy(monkeypatch, answers=()):
    """Replace `resolve` with a recorder; the methods must all go through it."""
    seen = []

    def resolve(query, rdtype=None, **kwargs):
        seen.append((query, rdtype, kwargs))
        return list(answers)

    monkeypatch.setattr(netimps._dns, "resolve", resolve)
    return seen


def test_with_no_option_only_the_os_resolver_is_asked(monkeypatch):
    seen = _spy(monkeypatch, [DB])
    assert Host("db.internal").ip() == DB
    assert seen[0][2]["backends"] == "system"


@pytest.mark.parametrize(
    "option",
    [
        {"ns": "192.0.2.53"},
        {"port": 5353},
        {"tcp": True},
        {"source": "192.0.2.1"},
    ],
)
def test_naming_a_nameserver_port_transport_or_source_selects_the_chain(
    monkeypatch, option
):
    seen = _spy(monkeypatch, [DB])
    Host("db.internal").ip(**option)
    assert seen[0][2]["backends"] is None
    for key, value in option.items():
        assert seen[0][2][key] == value


def test_an_explicit_backends_is_passed_as_it_is(monkeypatch):
    seen = _spy(monkeypatch, [DB])
    Host("db.internal").ip(backends=["wire", "system"], ns="192.0.2.53")
    assert seen[0][2]["backends"] == ["wire", "system"]
    Host("db.internal").ip(backends="nslookup")
    assert seen[1][2]["backends"] == "nslookup"


def test_the_default_does_not_touch_the_other_backends(monkeypatch):
    """The full chain costs seconds on a miss; the default must not enter it."""

    def explode(*args, **kwargs):
        raise AssertionError("a backend outside the OS resolver was asked")

    for name in ("resolve_dnspython", "resolve_wire", "resolve_nslookup"):
        monkeypatch.setattr(netimps._dns, name, explode)
    monkeypatch.setattr(socket, "getaddrinfo", _answer(DB))
    assert Host("db.internal").ip() == DB


@pytest.mark.parametrize(
    ("ipv6", "rdtype"),
    [(True, "aaaa"), (False, "a"), (None, ("a", "aaaa"))],
)
def test_ipv6_chooses_the_record_type(monkeypatch, ipv6, rdtype):
    seen = _spy(monkeypatch, [DB])
    Host("db.internal").ip(ipv6=ipv6)
    assert seen[0][1] == rdtype


def test_timeout_and_search_reach_the_resolver(monkeypatch):
    seen = _spy(monkeypatch, [DB])
    Host("db.internal").ip(timeout=2.5, search=False)
    assert seen[0][2]["timeout"] == 2.5
    assert seen[0][2]["search"] is False


def test_check_is_strict_for_the_resolver(monkeypatch):
    seen = _spy(monkeypatch, [DB])
    Host("db.internal").ip()
    Host("db.internal").ip(check=True)
    assert [call[2]["strict"] for call in seen] == [False, True]


def test_a_reverse_lookup_asks_for_ptr(monkeypatch):
    seen = _spy(monkeypatch, ["db.internal"])
    assert Host("192.0.2.9").fqdn(ns="192.0.2.53") == FQDN("db.internal")
    assert seen[0][:2] == ("192.0.2.9", "ptr")


def test_fqdn_ip_goes_through_the_same_helper(monkeypatch):
    seen = _spy(monkeypatch, [DB])
    assert FQDN("db.internal.").ip(ipv6=False, tcp=True) == DB
    assert seen[0][0] == "db.internal."
    assert seen[0][1] == "a"
    assert seen[0][2]["tcp"] is True


# -- ("a", "aaaa") on resolve() ----------------------------------------------


def test_the_os_resolver_is_asked_for_both_families_in_one_call(monkeypatch):
    """One `getaddrinfo`, left in the OS's own order: v6 first here."""
    lookup = _answer(DB6, DB)
    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    found = netimps.resolve("db.internal", ("a", "aaaa"), backends="system")
    assert found == [DB6, DB]
    assert lookup.calls == [("db.internal", socket.AF_UNSPEC)]


def test_other_backends_are_asked_once_per_family_and_joined(monkeypatch):
    asked = []

    def wire(query, rdtype=None, **kwargs):
        asked.append(rdtype)
        return [DB] if rdtype == "a" else [DB6]

    monkeypatch.setattr(netimps._dns, "resolve_wire", wire)
    found = netimps.resolve(
        "db.internal", ("a", "aaaa"), ns="192.0.2.53", backends="wire"
    )
    assert found == [DB, DB6]
    assert asked == ["a", "aaaa"]


def test_one_family_failing_to_ask_is_not_an_empty_answer(monkeypatch):
    """A resolver that timed out on AAAA says nothing about AAAA records."""

    def wire(query, rdtype=None, **kwargs):
        if rdtype == "aaaa":
            raise ResolutionError("timed out")
        return [DB]

    monkeypatch.setattr(netimps._dns, "resolve_wire", wire)
    assert netimps.resolve(
        "x.example", ("a", "aaaa"), ns="192.0.2.53", backends="wire"
    ) == [DB]

    def none(query, rdtype=None, **kwargs):
        raise ResolutionError("timed out")

    monkeypatch.setattr(netimps._dns, "resolve_wire", none)
    with pytest.raises(ResolutionError):
        netimps.resolve(
            "x.example", ("a", "aaaa"), ns="192.0.2.53", backends="wire", strict=True
        )


@pytest.mark.parametrize(
    "rdtype", [("a", "mx"), ("a", "a"), (), ("ptr",), ["txt", "a"]]
)
def test_the_dual_rdtype_only_names_address_records(rdtype):
    with pytest.raises(ValueError):
        netimps.resolve("db.internal", rdtype, backends="system")


# -- the memo --------------------------------------------------------------------


def test_a_plain_call_memoises_and_an_option_does_not(monkeypatch):
    lookup = _answer(DB)
    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    host = Host("db.internal")
    host.ip()
    host.ip()
    assert len(lookup.calls) == 1

    host.ip(ipv6=False)
    host.ip(timeout=1.0)
    host.ip(check=True)
    assert len(lookup.calls) == 4, "an option must neither read the memo"

    host.ip()
    assert len(lookup.calls) == 4, "nor have overwritten it"


def test_refresh_asks_again_and_leaves_the_memo_alone(monkeypatch):
    first = _answer(DB)
    monkeypatch.setattr(socket, "getaddrinfo", first)
    host = Host("db.internal")
    assert host.ip() == DB

    second = _answer(netimps.parse("192.0.2.77"))
    monkeypatch.setattr(socket, "getaddrinfo", second)
    assert host.ip(refresh=True) == netimps.parse("192.0.2.77")
    assert host.ip() == DB, "refresh must not write the memo"
    assert second.calls and len(first.calls) == 1


def test_fqdn_has_no_memo(monkeypatch):
    lookup = _answer(DB)
    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    name = FQDN("db.internal")
    name.ip()
    name.ip()
    assert len(lookup.calls) == 2


# -- the shape of the API ---------------------------------------------------------


def test_the_options_are_keyword_only():
    with pytest.raises(TypeError):
        Host("db.internal").ip(True)  # type: ignore[misc]
    with pytest.raises(TypeError):
        Host("db.internal").fqdn(True)  # type: ignore[misc]
    with pytest.raises(TypeError):
        Host("db.internal").resolve(True)  # type: ignore[misc]
    with pytest.raises(TypeError):
        FQDN("db.internal").ip(True)  # type: ignore[misc]


def test_fqdn_is_a_method_on_host_and_no_property_is_left_behind():
    assert callable(Host("a.example").fqdn)
    assert not isinstance(Host.__dict__["fqdn"], property)
