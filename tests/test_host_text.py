"""Host text and locality: the helpers four or five repositories wrote by hand.

Each test pins the difference from the hand-rolled version: stripping brackets
and ``%zone`` before ``try_parse``, a ``(host, port)`` pair with a default port,
and "does this host string name this machine" with a ``localhost`` shortcut.
``join_host`` and the input types ``split_host`` takes are tested here too.
"""

import ipaddress as _ipaddress
import ipaddress
import os
import socket

import pytest

import netimps
from netimps import (
    FQDN,
    Host,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
    MACAddress,
    format_address,
    is_local_host,
    join_host,
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
    with pytest.raises(TypeError):
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


@pytest.mark.parametrize("pair", [("h", 70000), ("h", -1), ("h",), ("h", 1, 2)])
def test_a_malformed_pair_is_refused(pair):
    with pytest.raises(netimps.NetimpsValueError):
        split_host(pair)


@pytest.mark.parametrize("pair", [("h", True), ("h", 1.5)])
def test_a_pair_with_a_port_of_the_wrong_type_is_a_type_error(pair):
    with pytest.raises(TypeError):
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


@pytest.mark.parametrize(
    "value",
    [None, 5, 5.5, b"h", ["h"], object()],
)
def test_a_value_that_is_not_a_host_type_is_a_type_error(value):
    """CONVERSIONS: the wrong type is a caller's bug, not text that does not
    parse."""
    for call in (
        lambda: netimps.split_host(value),
        lambda: netimps.split_zone(value),
        lambda: netimps.join_host(value, 80),
        lambda: netimps.join_host(value),
    ):
        with pytest.raises(TypeError) as caught:
            call()
        assert not isinstance(caught.value, netimps.NetimpsError)


@pytest.mark.parametrize(
    "network",
    [_ipaddress.ip_network("10.0.0.0/24"), _ipaddress.ip_network("fd00::/64")],
)
def test_a_network_names_no_host_in_either_direction(network):
    with pytest.raises(TypeError):
        netimps.split_host(network)
    with pytest.raises(TypeError):
        netimps.join_host(network, 80)


@pytest.mark.parametrize("port", [80.9, True, "80", {}, [80]])
def test_join_host_takes_an_int_port(port):
    with pytest.raises(TypeError):
        netimps.join_host("h", port)


@pytest.mark.parametrize("port", [-1, 65536, 10**6])
def test_join_host_refuses_an_out_of_range_port(port):
    with pytest.raises(netimps.NetimpsValueError):
        netimps.join_host("h", port)


@pytest.mark.parametrize(
    "text",
    [
        "example.com:8_0",
        "example.com:+80",
        "example.com: 80",
        "example.com:80 x",
        "example.com:٨٠",  # Arabic-Indic digits
        "example.com:８０",  # fullwidth digits
        "example.com:-1",
        "example.com:0x50",
        "example.com:",
        "[::1]:8_0",
        "[::1]:٨٠",
        "example.com:65536",
    ],
)
def test_port_text_is_ascii_digits_in_range(text):
    """RFC 3986 section 3.2.3: port = *DIGIT. `int()` read `8_0`, `+80`, a
    leading space and every script's digits as port 80."""
    with pytest.raises(netimps.NetimpsValueError):
        split_host(text)


def test_a_pair_port_goes_through_the_same_gate():
    assert split_host(("h", "80")) == ("h", 80)
    for bad in ("8_0", "+80", " 80", "٨٠"):
        with pytest.raises(netimps.NetimpsValueError):
            split_host(("h", bad))
    for wrong in (True, 1.5, b"80"):
        with pytest.raises(TypeError):
            split_host(("h", wrong))
    with pytest.raises(netimps.NetimpsValueError):
        split_host(("h", 70000))


@pytest.mark.parametrize(
    "text",
    ["[not an address]:80", "[10.0.0.5]:80", "[10.0.0.5]", "[example.com]:80", "[]"],
)
def test_brackets_hold_an_ipv6_literal(text):
    """RFC 3986 section 3.2.2. `join_host` refused what `split_host` handed
    back, so the pair was not inverse."""
    with pytest.raises(netimps.NetimpsValueError):
        split_host(text)
    with pytest.raises(netimps.NetimpsValueError):
        netimps.join_host(text, 80)


@pytest.mark.parametrize(
    "host, port",
    [
        ("example.com", 80),
        ("example.com", None),
        ("10.0.0.5", 0),
        ("10.0.0.5", 65535),
        ("::1", 8080),
        ("fe80::1%eth0", 80),
        ("2001:db8::1", None),
        ("localhost", 22),
    ],
)
def test_split_inverts_join(host, port):
    assert split_host(netimps.join_host(host, port)) == (host, port)
    for given in (
        _ipaddress.ip_address("10.0.0.5"),
        _ipaddress.ip_interface("10.0.0.5/8"),
        _ipaddress.ip_address("::1"),
        FQDN("example.com"),
        Host("example.com"),
    ):
        text = netimps.join_host(given, port)
        assert split_host(text)[1] == port


IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# join_host, the inverse of split_host                                        #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host, port, expected",
    [
        ("example.com", 8080, "example.com:8080"),
        ("10.0.0.5", 8080, "10.0.0.5:8080"),
        ("::1", 8080, "[::1]:8080"),
        ("fe80::1%eth0", 80, "[fe80::1%eth0]:80"),
        ("2001:db8::1", 53, "[2001:db8::1]:53"),
        ("::1", None, "::1"),
        ("example.com", None, "example.com"),
        ("10.0.0.5", None, "10.0.0.5"),
        ("[::1]", 443, "[::1]:443"),
        ("0.0.0.0", 0, "0.0.0.0:0"),
    ],
)
def test_join_host_brackets_only_an_ipv6_literal(host, port, expected):
    assert join_host(host, port) == expected


@pytest.mark.parametrize(
    "host, port",
    [
        ("example.com", 8080),
        ("10.0.0.5", 8080),
        ("::1", 8080),
        ("fe80::1%eth0", 80),
        ("2001:db8::1", 53),
        ("::1", None),
        ("example.com", None),
        ("0.0.0.0", 0),
    ],
)
def test_join_host_round_trips_through_normalize_host(host, port):
    """The law that makes the pair trustworthy, in both directions.

    This is why a port-less IPv6 comes back *unbracketed*: with no port there
    is nothing to disambiguate, and `split_host` returns the bare form.
    """
    assert split_host(join_host(host, port)) == (host, port)


def test_join_host_accepts_the_types_a_caller_already_has():
    assert join_host(ipaddress.IPv4Address("1.2.3.4"), 53) == "1.2.3.4:53"
    assert join_host(ipaddress.IPv6Address("2001:db8::1"), 53) == "[2001:db8::1]:53"
    assert join_host(FQDN("www.example.com"), 443) == "www.example.com:443"
    # An interface carries a prefix; a socket address wants only the address.
    assert join_host(ipaddress.IPv4Interface("10.0.0.5/24"), 69) == "10.0.0.5:69"
    assert (
        join_host(ipaddress.IPv6Interface("2001:db8::1/64"), 69) == "[2001:db8::1]:69"
    )


def test_join_host_never_brackets_a_name():
    """Brackets in a URI authority mean "the inside is an address".

    Bracketing a hostname would produce something no resolver accepts, however
    many colons someone has managed to put in it.
    """
    assert join_host("example.com", 80) == "example.com:80"
    assert "[" not in join_host(FQDN("a.b.c.example.com"), 80)


@pytest.mark.parametrize(
    "host, port, match",
    [
        ("", 80, "must not be empty"),
        ("example.com", 99999, "0-65535"),
        ("example.com", -1, "0-65535"),
        ("[::1", 80, "mismatched brackets"),
        ("::1]", 80, "mismatched brackets"),
        ("[notanaddress]", 80, "not an IPv6 address"),
    ],
)
def test_join_host_rejects_bad_input(host, port, match):
    """A mismatched bracket must raise, not fall through.

    `"[::1"` is not an IPv6 literal, so without the check it would emerge
    unbracketed as `"[::1:80"` -- garbage the caller cannot detect.
    `split_host` rejects the same input, and the pair has to agree.
    """
    with pytest.raises(ValueError, match=match):
        join_host(host, port)


def test_join_host_rejects_none():
    with pytest.raises(TypeError):
        join_host(None, 80)


# --------------------------------------------------------------------------- #
# split_host() takes the package's usual loose union                          #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "label, value, expected",
    [
        ("str", "example.com:80", ("example.com", 80)),
        ("IPv4Address", ipaddress.IPv4Address("1.2.3.4"), ("1.2.3.4", None)),
        ("IPv6Address", ipaddress.IPv6Address("::1"), ("::1", None)),
        ("IPv4Interface", ipaddress.IPv4Interface("10.0.0.5/24"), ("10.0.0.5", None)),
    ],
)
def test_normalize_host_accepts_more_than_a_string(label, value, expected):
    """`join_host`, its inverse, already did -- this rejected the values a caller
    holding "the host" most often has."""
    assert netimps.split_host(value) == expected


def test_normalize_host_accepts_host_and_fqdn():
    assert netimps.split_host(netimps.Host("example.com")) == ("example.com", None)
    # An FQDN keeps its trailing dot, which is identity-bearing for a name.
    assert netimps.split_host(netimps.FQDN("b.com.")) == ("b.com.", None)


@pytest.mark.parametrize("bad", [None, 42, [], b"x", object()])
def test_normalize_host_uses_an_allowlist_not_a_str_fallback(bad):
    """`str(None)` is the hostname "None" -- a plausible answer that is wrong.

    An earlier version of this widening fell back to `str()` for anything
    unrecognised, which accepted `None`, an int and a list and turned each into a
    hostname a caller could not detect as bogus. The allowlist is the point.
    """
    with pytest.raises((ValueError, TypeError)):
        netimps.split_host(bad)


def test_normalize_host_still_refuses_a_network_and_an_empty_string():
    with pytest.raises(TypeError, match="not a network"):
        netimps.split_host(ipaddress.ip_network("10.0.0.0/24"))
    with pytest.raises(ValueError):
        netimps.split_host("")


@pytest.mark.parametrize(
    "host, port",
    [
        (ipaddress.IPv6Address("::1"), 69),
        (ipaddress.IPv4Address("10.0.0.1"), 80),
        ("example.com", 443),
    ],
)
def test_the_round_trip_law_survives_the_widening(host, port):
    """`split_host(join_host(h, p))` must still come back equal.

    The pair are inverses, and widening one input must not break that -- which is
    why this is asserted against the *parsed* forms the widening added, not only
    against strings.
    """
    assert netimps.split_host(netimps.join_host(host, port)) == (str(host), port)


# --------------------------------------------------------------------------- #
# format_address: one text for an address on every Python                      #
# --------------------------------------------------------------------------- #

#: Each address, spelled every way the standard library accepts, and the one
#: text it must print as. ``str(IPv6Address)`` of a v4-mapped address is the
#: hex form before Python 3.13 and the mixed form from it; this table is the
#: same on every interpreter.
_ADDRESS_TEXT = [
    (IPv6Address("::ffff:1.2.3.4"), "::ffff:1.2.3.4"),
    (IPv6Address("::ffff:102:304"), "::ffff:1.2.3.4"),
    (IPv6Address("0:0:0:0:0:ffff:102:304"), "::ffff:1.2.3.4"),
    (IPv6Address("::FFFF:0A00:0005"), "::ffff:10.0.0.5"),
    (IPv6Address("::ffff:0.0.0.0"), "::ffff:0.0.0.0"),
    (IPv6Address("::ffff:1.2.3.4%eth0"), "::ffff:1.2.3.4%eth0"),
    (IPv6Address("fe80::1%eth0"), "fe80::1%eth0"),
    (IPv6Address("fe80::1%3"), "fe80::1%3"),
    (IPv6Address("2001:db8::1"), "2001:db8::1"),
    (IPv6Address("::1"), "::1"),
    (IPv6Address("::"), "::"),
    (IPv6Address("::1.2.3.4"), "::102:304"),
    (IPv6Address("64:ff9b::1.2.3.4"), "64:ff9b::102:304"),
    (ipaddress.IPv4Address("1.2.3.4"), "1.2.3.4"),
    (ipaddress.IPv4Address("0.0.0.0"), "0.0.0.0"),
    (IPv6Interface("::ffff:1.2.3.4/96"), "::ffff:1.2.3.4/96"),
    (IPv6Interface("2001:db8::1/64"), "2001:db8::1/64"),
    (IPv4Interface("10.0.0.5/24"), "10.0.0.5/24"),
]


@pytest.mark.parametrize(("address", "text"), _ADDRESS_TEXT)
def test_format_address_is_the_same_text_on_every_python(address, text):
    assert format_address(address) == text


def test_format_address_agrees_with_str_where_str_is_the_mixed_form():
    """From 3.13 ``str`` writes the form this function writes on every Python,
    so it is the interpreter's own answer there and nothing to second-guess."""
    import sys

    if sys.version_info < (3, 13):
        pytest.skip("str() of a v4-mapped address is the hex form before 3.13")
    for address, _ in _ADDRESS_TEXT:
        assert format_address(address) == str(address)


def test_format_address_keeps_the_family_and_the_zone():
    mapped = IPv6Address("::ffff:1.2.3.4%eth0")
    text = format_address(mapped)
    assert text.endswith("%eth0")
    assert isinstance(ipaddress.ip_address(text.split("%")[0]), IPv6Address)
    assert netimps.parse(text.split("%")[0], netimps.IPAddress) == IPv6Address(
        "::ffff:1.2.3.4"
    )


@pytest.mark.parametrize(
    "value",
    ["::ffff:1.2.3.4", 5, None, b"x", Host("::1"), ipaddress.ip_network("10.0.0.0/8")],
)
def test_format_address_takes_address_objects_only(value):
    """Text is parsed first (``parse``): a function that formats guesses nothing."""
    with pytest.raises(TypeError):
        format_address(value)


@pytest.mark.parametrize(
    ("host", "port", "text"),
    [
        (IPv6Address("::ffff:1.2.3.4"), 80, "[::ffff:1.2.3.4]:80"),
        (IPv6Address("::ffff:102:304"), 80, "[::ffff:1.2.3.4]:80"),
        (IPv6Address("::ffff:1.2.3.4"), None, "::ffff:1.2.3.4"),
        (IPv6Address("fe80::1%eth0"), 80, "[fe80::1%eth0]:80"),
        (IPv6Interface("::ffff:1.2.3.4/96"), 80, "[::ffff:1.2.3.4]:80"),
        (ipaddress.IPv4Address("1.2.3.4"), 80, "1.2.3.4:80"),
    ],
)
def test_join_host_prints_an_address_object_the_same_on_every_python(host, port, text):
    assert join_host(host, port) == text
    assert split_host(text)[0] == format_address(
        host.ip if isinstance(host, (IPv4Interface, IPv6Interface)) else host
    )


def test_a_host_made_from_an_address_object_keeps_the_same_text_on_every_python():
    assert str(Host(IPv6Address("::ffff:102:304"))) == "::ffff:1.2.3.4"
    assert str(Host(IPv6Interface("::ffff:1.2.3.4/96"))) == "::ffff:1.2.3.4"


def test_a_route_shows_its_addresses_the_same_on_every_python():
    route = netimps.Route(
        IPv6Address("::ffff:102:304"),
        src=IPv6Address("::ffff:1.2.3.5"),
        gateway=IPv6Address("::ffff:1.2.3.1"),
    )
    assert repr(route) == (
        "Route(dst='::ffff:1.2.3.4', src='::ffff:1.2.3.5', "
        "gateway='::ffff:1.2.3.1', on_link=False)"
    )


# --------------------------------------------------------------------------- #
# A name the IDNA codec refuses                                                #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", ["a..b", "x" * 70 + ".test", ".leading.test"])
def test_is_local_host_never_raises_for_a_name_the_codec_refuses(name, allow_resolver):
    """``getaddrinfo`` encodes the name before asking, and an empty label or
    one over 63 octets came out of ``is_local_host(..., resolve=True)`` as a
    ``UnicodeEncodeError``.

    The real ``getaddrinfo`` is what refuses, so the guard is lifted; the codec
    fails before anything is asked of a resolver.
    """
    assert netimps.is_local_host(name, resolve=True) is False
