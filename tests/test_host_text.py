"""Host text and locality: the helpers four or five repositories wrote by hand.

Each test pins the difference from the hand-rolled version: stripping brackets
and ``%zone`` before ``try_parse``, a ``(host, port)`` pair with a default port,
and "does this host string name this machine" with a ``localhost`` shortcut.
"""

import socket

import pytest

import netimps
from netimps import (
    FQDN,
    Host,
    IPv6Address,
    MACAddress,
    is_local_host,
    split_host,
    split_zone,
    try_parse,
)

# --------------------------------------------------------------------------- #
# split_zone                                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text, expected",
    [
        ("fe80::1%eth0", ("fe80::1", "eth0")),
        ("fe80::1%12", ("fe80::1", "12")),
        ("fe80::1", ("fe80::1", None)),
        ("10.0.0.5", ("10.0.0.5", None)),
        ("example.com", ("example.com", None)),
    ],
)
def test_split_zone_separates_the_zone(text, expected):
    """``try_parse("fe80::1%eth0")`` keeps the zone in the address, so it equals
    nothing an interface reports; callers split it by hand first."""
    assert split_zone(text) == expected


def test_split_zone_lets_a_scoped_address_be_compared():
    host, zone = split_zone("fe80::1%eth0")
    assert try_parse(host, netimps.IPAddress) == IPv6Address("fe80::1")
    assert zone == "eth0"


def test_split_zone_takes_the_loose_host_union():
    assert split_zone(IPv6Address("fe80::1%7")) == ("fe80::1", "7")
    assert split_zone(Host("fe80::1%eth0")) == ("fe80::1", "eth0")
    assert split_zone(FQDN("example.com")) == ("example.com", None)
    with pytest.raises(netimps.NetimpsValueError):
        split_zone(None)


def test_split_zone_refuses_an_empty_zone():
    with pytest.raises(netimps.NetimpsValueError):
        split_zone("fe80::1%")


# --------------------------------------------------------------------------- #
# split_host                                                                   #
# --------------------------------------------------------------------------- #


def test_split_host_takes_a_bare_bracketed_literal():
    """``try_parse("[::1]")`` is ``None``; a caller wanting the address from a
    bracketed host splits it here first."""
    assert split_host("[::1]") == ("::1", None)
    assert split_host("[fe80::1%eth0]") == ("fe80::1%eth0", None)
    assert split_host("[::1]", default_port=69) == ("::1", 69)


def test_split_host_takes_a_host_port_pair():
    """Callers branched on ``isinstance(x, tuple)`` and applied the default port
    to a ``None`` themselves."""
    assert split_host(("h", None), default_port=69) == ("h", 69)
    assert split_host(("h", 8080), default_port=69) == ("h", 8080)
    assert split_host(("h", None)) == ("h", None)
    assert split_host(("[::1]", 80)) == ("::1", 80)
    assert split_host(("::1", None), default_port=7) == ("::1", 7)
    assert split_host((IPv6Address("::1"), 80)) == ("::1", 80)
    assert split_host(("h", "80")) == ("h", 80)


def test_a_pair_that_names_a_port_twice_must_agree():
    assert split_host(("h:80", 80)) == ("h", 80)
    assert split_host(("h:80", None), default_port=9) == ("h", 80)
    with pytest.raises(netimps.NetimpsValueError, match="two ports"):
        split_host(("h:80", 81))


@pytest.mark.parametrize(
    "pair", [("h", True), ("h", 1.5), ("h", 70000), ("h", -1), ("h",), ("h", 1, 2)]
)
def test_a_malformed_pair_is_refused(pair):
    with pytest.raises(netimps.NetimpsValueError):
        split_host(pair)


# --------------------------------------------------------------------------- #
# is_local_host                                                                #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST",
        "localhost.",
        "app.localhost",
        "127.0.0.1",
        "127.0.0.2",
        "::1",
        "[::1]",
        "[::1]:22",
        "localhost:8080",
        "::ffff:127.0.0.1",
    ],
)
def test_loopback_forms_are_local_without_touching_the_resolver(host):
    """Callers compared against a literal set, or resolved the name first. Run
    under the suite's network guard: any lookup fails."""
    assert is_local_host(host) is True


def test_the_machines_own_name_is_local():
    name = socket.gethostname()
    assert is_local_host(name) is True
    assert is_local_host(name.upper()) is True
    assert is_local_host(name + ".") is True


def test_an_address_held_by_an_interface_is_local():
    held = next(
        (
            ip.ip
            for iface in netimps.get_interfaces()
            for ip in iface.ips
            if not ip.ip.is_loopback and not ip.ip.is_link_local
        ),
        None,
    )
    if held is None:
        pytest.skip("no routable address is assigned on this host")
    assert is_local_host(str(held)) is True
    assert is_local_host(held) is True


@pytest.mark.parametrize(
    "host",
    ["example.com", "192.0.2.1", "2001:db8::1", "", "  ", "not a host:x:y"],
)
def test_other_hosts_are_not_local_and_are_not_looked_up(host):
    assert is_local_host(host) is False


def test_a_non_host_is_not_local_rather_than_an_error():
    assert is_local_host(None) is False  # type: ignore[arg-type]
    assert is_local_host(42) is False  # type: ignore[arg-type]
    assert is_local_host(("h", 1)) is False  # type: ignore[arg-type]


def test_an_unknown_name_is_resolved_only_when_asked(monkeypatch):
    answers = {"svc.test": "127.0.0.1", "far.test": "192.0.2.1"}
    calls = []

    def fake_getaddrinfo(name, *args, **kwargs):
        calls.append(name)
        if name not in answers:
            raise socket.gaierror(socket.EAI_NONAME, "no such name")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers[name], 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(socket, "getfqdn", lambda *a: "box.test")

    assert is_local_host("svc.test") is False
    assert calls == [], "no resolution unless asked"

    assert is_local_host("svc.test", resolve=True) is True
    assert is_local_host("far.test", resolve=True) is False
    assert is_local_host("missing.test", resolve=True) is False
    assert is_local_host("BOX.test", resolve=True) is True, "own fully qualified name"


# --------------------------------------------------------------------------- #
# MACAddress                                                                   #
# --------------------------------------------------------------------------- #


def test_the_mac_pattern_is_not_reachable_from_the_class():
    """The class docstring told callers to use ``MACAddress._VALID_MAC``; two
    did. ``is_valid`` is the supported route."""
    assert not hasattr(MACAddress, "_VALID_MAC")
    assert MACAddress.is_valid("aa:bb:cc:dd:ee:ff")
