"""The `listen` grammar, as a table: every accepted form, every refused one.

`parse_listen` is a pure reading of what a user wrote: it resolves no name and
looks no interface up, so every example here runs without a network or a host
that has the adapters it names.
"""

from __future__ import annotations

import socket
import typing as ty

import pytest

import netimps
from netimps import (
    IPv4Address,
    IPv6Address,
    ListenAddress,
    MACAddress,
    NetimpsValueError,
    parse_listen,
)

DEFAULTS = 67
MAC = MACAddress("aa:bb:cc:dd:ee:ff")
ADAPTER = netimps.Interface("aabbccddeeff", 7, mac=None, ips=[])


def _flat(result: "ty.Sequence[ListenAddress]") -> "list[tuple[str, int]]":
    return [(str(entry.address), entry.port) for entry in result]


def _full(
    result: "ty.Sequence[ListenAddress]",
) -> "list[tuple[str, int, tuple[ty.Any, ...]]]":
    return [(str(e.address), e.port, tuple(e.interfaces)) for e in result]


#: spec -> the (address, port) pairs it names, with 67 as the default port.
ACCEPTED: "list[tuple[ty.Any, list[tuple[str, int]]]]" = [
    # nothing, and the wildcard in every spelling
    (None, [("0.0.0.0", 67)]),
    ("*", [("0.0.0.0", 67)]),
    ("0.0.0.0", [("0.0.0.0", 67)]),
    ("*:6767", [("0.0.0.0", 6767)]),
    (":6767", [("0.0.0.0", 6767)]),
    ("0.0.0.0:6767", [("0.0.0.0", 6767)]),
    (IPv4Address("0.0.0.0"), [("0.0.0.0", 67)]),
    ((None, 6767), [("0.0.0.0", 6767)]),
    (("", 6767), [("0.0.0.0", 6767)]),
    (("*", 6767), [("0.0.0.0", 6767)]),
    ((None, None), [("0.0.0.0", 67)]),
    ([None], [("0.0.0.0", 67)]),
    # text
    ("127.0.0.1", [("127.0.0.1", 67)]),
    ("127.0.0.1:6767", [("127.0.0.1", 6767)]),
    (" 127.0.0.1:6767 ", [("127.0.0.1", 6767)]),
    ("127.0.0.1:6767,127.0.0.2:6768", [("127.0.0.1", 6767), ("127.0.0.2", 6768)]),
    ("127.0.0.1:6767, ,127.0.0.1:6767", [("127.0.0.1", 6767)]),
    ("127.0.0.1:0", [("127.0.0.1", 0)]),
    ("127.0.0.1:65535", [("127.0.0.1", 65535)]),
    # an address object
    (IPv4Address("127.0.0.1"), [("127.0.0.1", 67)]),
    # a pair, as a tuple and as the list a configuration file delivers
    (("127.0.0.1", 6767), [("127.0.0.1", 6767)]),
    (["127.0.0.1", 6767], [("127.0.0.1", 6767)]),
    (("127.0.0.1", "6767"), [("127.0.0.1", 6767)]),
    (["127.0.0.1", "6767"], [("127.0.0.1", 6767)]),
    ((IPv4Address("127.0.0.1"), 6767), [("127.0.0.1", 6767)]),
    (("127.0.0.1", None), [("127.0.0.1", 67)]),
    (("127.0.0.1:6767", None), [("127.0.0.1", 6767)]),
    (("127.0.0.1:6767", 6767), [("127.0.0.1", 6767)]),
    (("127.0.0.1", 0), [("127.0.0.1", 0)]),
    # a pair with several ports
    (("127.0.0.1", [6767, 6768]), [("127.0.0.1", 6767), ("127.0.0.1", 6768)]),
    (["127.0.0.1", ["6767", 6768]], [("127.0.0.1", 6767), ("127.0.0.1", 6768)]),
    (("127.0.0.1", (6767,)), [("127.0.0.1", 6767)]),
    # a sequence of bindings of every kind, in order and without repeats
    (
        [("127.0.0.1", 6767), ("127.0.0.2", 6768)],
        [("127.0.0.1", 6767), ("127.0.0.2", 6768)],
    ),
    (
        [["127.0.0.1", 6767], ["127.0.0.2", 6768]],
        [("127.0.0.1", 6767), ("127.0.0.2", 6768)],
    ),
    (
        ["127.0.0.1:6767", "127.0.0.2:6768"],
        [("127.0.0.1", 6767), ("127.0.0.2", 6768)],
    ),
    (
        ("127.0.0.1:6767", "127.0.0.2:6768"),
        [("127.0.0.1", 6767), ("127.0.0.2", 6768)],
    ),
    (["127.0.0.1", "127.0.0.2"], [("127.0.0.1", 67), ("127.0.0.2", 67)]),
    (
        ["127.0.0.1", ["127.0.0.2", 6768], "127.0.0.3:6769,127.0.0.4"],
        [
            ("127.0.0.1", 67),
            ("127.0.0.2", 6768),
            ("127.0.0.3", 6769),
            ("127.0.0.4", 67),
        ],
    ),
    (
        [("127.0.0.1", 6767), ("127.0.0.1", 6767), "127.0.0.1:6767"],
        [("127.0.0.1", 6767)],
    ),
    # IPv6: bare text, brackets with a port, objects, pairs
    ("::", [("::", 67)]),
    ("::1", [("::1", 67)]),
    ("[::1]", [("::1", 67)]),
    ("[::1]:69", [("::1", 69)]),
    ("[::]:69", [("::", 69)]),
    ("[::1]:0", [("::1", 0)]),
    (IPv6Address("::1"), [("::1", 67)]),
    (("::1", 69), [("::1", 69)]),
    (["::1", "69"], [("::1", 69)]),
    ((IPv6Address("::1"), 69), [("::1", 69)]),
    (("[::1]:69", None), [("::1", 69)]),
    (("[::1]:69", 69), [("::1", 69)]),
    (("::1", [69, 70]), [("::1", 69), ("::1", 70)]),
    # a zone is kept
    ("fe80::1%eth0", [("fe80::1%eth0", 67)]),
    ("[fe80::1%eth0]:69", [("fe80::1%eth0", 69)]),
    (("fe80::1%7", 69), [("fe80::1%7", 69)]),
    # both families, in the order written
    ("::1,127.0.0.1:68", [("::1", 67), ("127.0.0.1", 68)]),
    (["[::1]:69", "127.0.0.1"], [("::1", 69), ("127.0.0.1", 67)]),
]

#: spec -> (the exception class, a word in its message). Every one of them is
#: also a ValueError or a TypeError, as the class says.
REFUSED: "list[tuple[ty.Any, type, str]]" = [
    # names no address
    ("", NetimpsValueError, "names no address"),
    ("  ", NetimpsValueError, "names no address"),
    (" , ", NetimpsValueError, "names no address"),
    ([], NetimpsValueError, "names no address"),
    ((), NetimpsValueError, "names no address"),
    ([""], NetimpsValueError, "names no address"),
    (("127.0.0.1", []), NetimpsValueError, "names no port"),
    # a bool or a bare number is not an address, and a bool is not a port
    (True, TypeError, "bool"),
    (6767, TypeError, "int"),
    (6767.0, TypeError, "float"),
    ([6767], TypeError, "int"),
    (("127.0.0.1", True), TypeError, "bool"),
    (("127.0.0.1", False), TypeError, "bool"),
    (["127.0.0.1", True], TypeError, "bool"),
    (("127.0.0.1", 6767.5), TypeError, "float"),
    (b"127.0.0.1", TypeError, "bytes"),
    ({"host": "127.0.0.1"}, TypeError, "dict"),
    (["127.0.0.1", 6767, 1], TypeError, "int"),
    (("::1", True), TypeError, "bool"),
    # a port out of range, malformed, or written twice and different
    (("127.0.0.1", 70000), NetimpsValueError, "out of range"),
    (("127.0.0.1", -1), NetimpsValueError, "out of range"),
    ("127.0.0.1:70000", NetimpsValueError, "out of range"),
    ("[::1]:70000", NetimpsValueError, "out of range"),
    ("127.0.0.1:+6767", NetimpsValueError, "invalid port"),
    ("127.0.0.1: 6767", NetimpsValueError, "invalid port"),
    ("127.0.0.1:8_0", NetimpsValueError, "invalid port"),
    ("127.0.0.1:port", NetimpsValueError, "invalid port"),
    ("[::1]:port", NetimpsValueError, "invalid port"),
    (("127.0.0.1", "+67"), NetimpsValueError, "invalid port"),
    (("127.0.0.1", " 67"), NetimpsValueError, "invalid port"),
    (("127.0.0.1", ""), NetimpsValueError, "invalid port"),
    (("127.0.0.1:+6767", 67), NetimpsValueError, "invalid port"),
    (("127.0.0.1", ["67", 70000]), NetimpsValueError, "out of range"),
    (("*:6767", 6868), NetimpsValueError, "two ports"),
    (("127.0.0.1:6767", 6868), NetimpsValueError, "two ports"),
    (("[::1]:69", 70), NetimpsValueError, "two ports"),
    # brackets around anything but an IPv6 address, and stray colons
    ("[127.0.0.1]:6767", NetimpsValueError, "bracketed"),
    ("127.0.0.1:67:68", NetimpsValueError, "colon"),
]

#: spec -> (the (address, port, interfaces) it names).
#: Text that is no address is read as a MAC, then as an adapter name; a host
#: name is never resolved.
WILD = ("0.0.0.0", 6767)
W67 = ("0.0.0.0", 67)
INTERFACES: "list[tuple[ty.Any, list[tuple[str, int, tuple[ty.Any, ...]]]]]" = [
    # an adapter name, with and without a port
    ("eth1", [(*W67, ("eth1",))]),
    ("eth1:6767", [(*WILD, ("eth1",))]),
    (" eth1:6767 ", [(*WILD, ("eth1",))]),
    ("eth1:0", [("0.0.0.0", 0, ("eth1",))]),
    ("Wi-Fi 2:6767", [(*WILD, ("Wi-Fi 2",))]),
    ("vEthernet (WSL):6767", [(*WILD, ("vEthernet (WSL)",))]),
    ("eth0.100:6767", [(*WILD, ("eth0.100",))]),
    ("lo:6767", [(*WILD, ("lo",))]),
    # a name that is also a host name, or looks like one, is still an adapter
    ("localhost:6767", [(*WILD, ("localhost",))]),
    ("example.com:6767", [(*WILD, ("example.com",))]),
    ("1.2.3:6767", [(*WILD, ("1.2.3",))]),
    ("123456:6767", [(*WILD, ("123456",))]),
    # a name with a trailing colon-number is a port: `eth0:1` is eth0 on port 1
    ("eth0:1", [("0.0.0.0", 1, ("eth0",))]),
    # a MAC in every spelling, the colon one without a port in text
    ("aa:bb:cc:dd:ee:ff", [(*W67, (MAC,))]),
    ("AA:BB:CC:DD:EE:FF", [(*W67, (MAC,))]),
    ("aa-bb-cc-dd-ee-ff", [(*W67, (MAC,))]),
    ("aa-bb-cc-dd-ee-ff:6767", [(*WILD, (MAC,))]),
    ("AA-BB-CC-DD-EE-FF:6767", [(*WILD, (MAC,))]),
    ("aabb.ccdd.eeff", [(*W67, (MAC,))]),
    ("aabb.ccdd.eeff:6767", [(*WILD, (MAC,))]),
    ("aa.bb.cc.dd.ee.ff:6767", [(*WILD, (MAC,))]),
    ("aabbccddeeff", [(*W67, (MAC,))]),
    ("aabbccddeeff:6767", [(*WILD, (MAC,))]),
    # objects
    (MAC, [(*W67, (MAC,))]),
    (ADAPTER, [(*W67, (ADAPTER,))]),
    # pairs, as a tuple and as the list a configuration file delivers
    (("eth1", 6767), [(*WILD, ("eth1",))]),
    (["eth1", 6767], [(*WILD, ("eth1",))]),
    (["eth1", "6767"], [(*WILD, ("eth1",))]),
    (("eth1:6767", None), [(*WILD, ("eth1",))]),
    (("eth1", None), [(*W67, ("eth1",))]),
    (("aa:bb:cc:dd:ee:ff", 6767), [(*WILD, (MAC,))]),
    (["aa:bb:cc:dd:ee:ff", "6767"], [(*WILD, (MAC,))]),
    ((MAC, 6767), [(*WILD, (MAC,))]),
    ((ADAPTER, 6767), [(*WILD, (ADAPTER,))]),
    (
        ("eth1", [6767, 6768]),
        [(*WILD, ("eth1",)), ("0.0.0.0", 6768, ("eth1",))],
    ),
    # several interfaces share one socket; the wildcard on that port or an
    # address does not, and a wildcard named plainly has no limit
    ("eth1:6767,eth2:6767", [(*WILD, ("eth1", "eth2"))]),
    (
        ["eth1:6767", ("eth2", 6767), (MAC, 6767)],
        [(*WILD, ("eth1", "eth2", MAC))],
    ),
    (["eth1:6767", "eth1:6767"], [(*WILD, ("eth1",))]),
    (
        "eth1:6767,127.0.0.1:6768",
        [(*WILD, ("eth1",)), ("127.0.0.1", 6768, ())],
    ),
    ("eth1:6767,*:6767", [(*WILD, ())]),
    ("*:6767,eth1:6767", [(*WILD, ())]),
    ("0.0.0.0:6767,eth1:6767", [(*WILD, ())]),
    (
        "eth1:6767,eth2:6768",
        [(*WILD, ("eth1",)), ("0.0.0.0", 6768, ("eth2",))],
    ),
]

REFUSED_INTERFACES: "list[tuple[ty.Any, type, str]]" = [
    ("eth1:", NetimpsValueError, "invalid port"),
    ("eth1:70000", NetimpsValueError, "out of range"),
    ("eth1:port", NetimpsValueError, "invalid port"),
    ("eth0:1:67", NetimpsValueError, "colon"),
    ("aa:bb:cc:dd:ee:ff:67", NetimpsValueError, "colon"),
    ("eth/1", NetimpsValueError, "not an interface name"),
    ("eth1/24", NetimpsValueError, "not an interface name"),
    (("eth1", True), TypeError, "bool"),
    (("eth1", 6767.5), TypeError, "float"),
    (("eth1", 70000), NetimpsValueError, "out of range"),
    (("eth1", []), NetimpsValueError, "names no port"),
    (("eth1:6767", 6868), NetimpsValueError, "two ports"),
    (("aa:bb:cc:dd:ee:ff", True), TypeError, "bool"),
]


def _ids(table: "list[ty.Any]") -> "list[str]":
    return [repr(row[0]) for row in table]


@pytest.mark.parametrize("spec, expected", ACCEPTED, ids=_ids(ACCEPTED))
def test_an_accepted_form_names_exactly_these_addresses(
    spec: ty.Any, expected: "list[tuple[str, int]]"
) -> None:
    assert _flat(parse_listen(spec, DEFAULTS)) == expected


@pytest.mark.parametrize("spec, expected", ACCEPTED, ids=_ids(ACCEPTED))
def test_an_accepted_form_limits_nothing(
    spec: ty.Any, expected: "list[tuple[str, int]]"
) -> None:
    assert all(entry.interfaces == () for entry in parse_listen(spec, DEFAULTS))


@pytest.mark.parametrize("spec, error, word", REFUSED, ids=_ids(REFUSED))
def test_a_refused_form_is_refused_with_the_right_error(
    spec: ty.Any, error: type, word: str
) -> None:
    with pytest.raises(error) as raised:
        parse_listen(spec, DEFAULTS)
    assert word in str(raised.value), str(raised.value)


@pytest.mark.parametrize("spec, expected", INTERFACES, ids=_ids(INTERFACES))
def test_an_interface_form_names_one_wildcard_socket_limited_to_it(
    spec: ty.Any, expected: "list[tuple[str, int, tuple[ty.Any, ...]]]"
) -> None:
    assert _full(parse_listen(spec, DEFAULTS)) == expected


@pytest.mark.parametrize(
    "spec, error, word", REFUSED_INTERFACES, ids=_ids(REFUSED_INTERFACES)
)
def test_an_interface_form_that_is_malformed_is_refused(
    spec: ty.Any, error: type, word: str
) -> None:
    with pytest.raises(error) as raised:
        parse_listen(spec, DEFAULTS)
    assert word in str(raised.value), str(raised.value)


def test_a_refusal_quotes_what_was_written() -> None:
    with pytest.raises(NetimpsValueError, match="eth/1"):
        parse_listen("eth/1")
    with pytest.raises(TypeError, match="6767.5"):
        parse_listen(("127.0.0.1", 6767.5))


def test_the_refusals_are_value_errors_and_type_errors() -> None:
    assert issubclass(NetimpsValueError, ValueError)
    with pytest.raises(ValueError):
        parse_listen("127.0.0.1:70000", 67)


# -- the result ------------------------------------------------------------------


def test_the_result_is_a_tuple_of_named_tuples() -> None:
    result = parse_listen("eth1:6767,127.0.0.1:68")
    assert isinstance(result, tuple)
    first, second = result
    assert isinstance(first, ListenAddress) and isinstance(second, ListenAddress)
    assert first == (IPv4Address("0.0.0.0"), 6767, ("eth1",))
    assert first.address == IPv4Address("0.0.0.0")
    assert first.port == 6767
    assert first.interfaces == ("eth1",)
    assert second == (IPv4Address("127.0.0.1"), 68, ())
    assert isinstance(second.address, IPv4Address)
    assert isinstance(parse_listen("::1")[0].address, IPv6Address)


def test_a_listen_address_has_no_interfaces_by_default() -> None:
    assert ListenAddress(IPv4Address("127.0.0.1"), 67).interfaces == ()


def test_a_zone_is_kept_on_the_address() -> None:
    (entry,) = parse_listen("[fe80::1%eth0]:69")
    assert entry.address == IPv6Address("fe80::1%eth0")
    assert entry.address.scope_id == "eth0"


# -- the default ports -------------------------------------------------------------


def test_the_default_port_defaults_to_zero() -> None:
    assert _flat(parse_listen("127.0.0.1")) == [("127.0.0.1", 0)]
    assert _flat(parse_listen(None)) == [("0.0.0.0", 0)]


def test_default_ports_as_a_sequence_give_each_port_to_a_binding_without_one() -> None:
    assert _flat(parse_listen("127.0.0.1,127.0.0.2:5", (67, 68))) == [
        ("127.0.0.1", 67),
        ("127.0.0.1", 68),
        ("127.0.0.2", 5),
    ]
    assert _flat(parse_listen("eth1", [67, 68])) == [
        ("0.0.0.0", 67),
        ("0.0.0.0", 68),
    ]


def test_an_empty_default_ports_refuses_only_a_binding_without_a_port() -> None:
    assert _flat(parse_listen("127.0.0.1:67", ())) == [("127.0.0.1", 67)]
    with pytest.raises(NetimpsValueError, match="no port"):
        parse_listen("127.0.0.1", ())
    with pytest.raises(NetimpsValueError, match="no port"):
        parse_listen(None, [])


@pytest.mark.parametrize(
    "ports, error",
    [
        (True, TypeError),
        ("67", TypeError),
        (6.5, TypeError),
        ([67, True], TypeError),
        ([67, "68"], TypeError),
        (70000, NetimpsValueError),
        (-1, NetimpsValueError),
        ([67, 65536], NetimpsValueError),
    ],
    ids=repr,
)
def test_a_default_port_must_be_a_port(ports: ty.Any, error: type) -> None:
    with pytest.raises(error):
        parse_listen("127.0.0.1", ports)


# -- the family --------------------------------------------------------------------

INET = socket.AF_INET
INET6 = socket.AF_INET6

FAMILIES: "list[tuple[ty.Any, ty.Any, list[tuple[str, int, tuple[ty.Any, ...]]]]]" = [
    # the wildcard forms are IPv4's unless the family says otherwise
    (None, None, [("0.0.0.0", 67, ())]),
    (None, INET, [("0.0.0.0", 67, ())]),
    (None, INET6, [("::", 67, ())]),
    ("*", INET6, [("::", 67, ())]),
    ("*:6767", INET6, [("::", 6767, ())]),
    (":6767", INET6, [("::", 6767, ())]),
    (("", 6767), INET6, [("::", 6767, ())]),
    ((None, 6767), INET6, [("::", 6767, ())]),
    ("*:6767", INET, [("0.0.0.0", 6767, ())]),
    # an interface binding takes the family's wildcard
    ("eth1", None, [("0.0.0.0", 67, ("eth1",))]),
    ("eth1", INET, [("0.0.0.0", 67, ("eth1",))]),
    ("eth1:6767", INET6, [("::", 6767, ("eth1",))]),
    (MAC, INET6, [("::", 67, (MAC,))]),
    (ADAPTER, INET6, [("::", 67, (ADAPTER,))]),
    # an address in its own family
    ("::1", None, [("::1", 67, ())]),
    ("::1", INET6, [("::1", 67, ())]),
    ("127.0.0.1", None, [("127.0.0.1", 67, ())]),
    ("127.0.0.1", INET, [("127.0.0.1", 67, ())]),
    ("::", INET6, [("::", 67, ())]),
    ("0.0.0.0", INET, [("0.0.0.0", 67, ())]),
]

FAMILY_REFUSED: "list[tuple[ty.Any, ty.Any]]" = [
    ("::1", INET),
    ("[::1]:69", INET),
    (IPv6Address("::1"), INET),
    ("fe80::1%eth0", INET),
    (("::1", 69), INET),
    ("::", INET),
    ("127.0.0.1", INET6),
    ("127.0.0.1:67", INET6),
    (IPv4Address("127.0.0.1"), INET6),
    (("127.0.0.1", 67), INET6),
    ("0.0.0.0", INET6),
]


@pytest.mark.parametrize("spec, family, expected", FAMILIES, ids=repr)
def test_the_family_decides_the_wildcard_and_the_interface_binding(
    spec: ty.Any, family: ty.Any, expected: "list[tuple[str, int, tuple[ty.Any, ...]]]"
) -> None:
    assert _full(parse_listen(spec, 67, family=family)) == expected


@pytest.mark.parametrize("spec, family", FAMILY_REFUSED, ids=repr)
def test_a_family_refuses_an_address_of_the_other(spec: ty.Any, family: int) -> None:
    with pytest.raises(NetimpsValueError, match="family"):
        parse_listen(spec, 67, family=family)


@pytest.mark.parametrize(
    "family", [4, 6, 0, "inet", getattr(socket, "AF_UNIX", 1), True]
)
def test_any_other_family_is_refused(family: ty.Any) -> None:
    with pytest.raises(NetimpsValueError, match="family"):
        parse_listen("127.0.0.1", 67, family=family)


def test_the_family_applies_to_every_binding_of_a_sequence() -> None:
    with pytest.raises(NetimpsValueError, match="family"):
        parse_listen(["::1", "127.0.0.1"], 67, family=INET6)


# -- a result is a specification -----------------------------------------------------

ROUND_TRIPS = (
    [spec for spec, _ in ACCEPTED]
    + [spec for spec, _ in INTERFACES]
    + [spec for spec, _, _ in FAMILIES]
)


@pytest.mark.parametrize("spec", ROUND_TRIPS, ids=repr)
def test_parsing_a_result_gives_the_result(spec: ty.Any) -> None:
    once = parse_listen(spec, DEFAULTS)
    assert parse_listen(once) == once
    assert parse_listen(once, DEFAULTS) == once
    assert parse_listen(list(once), ()) == once
    for entry in once:
        assert parse_listen(entry) == (entry,)


@pytest.mark.parametrize("spec, family, expected", FAMILIES, ids=repr)
def test_parsing_a_result_with_its_family_gives_the_result(
    spec: ty.Any, family: ty.Any, expected: ty.Any
) -> None:
    once = parse_listen(spec, 67, family=family)
    assert parse_listen(once, family=family) == once


def test_a_result_is_refused_by_the_other_family() -> None:
    with pytest.raises(NetimpsValueError, match="family"):
        parse_listen(parse_listen("::1", 67), family=INET)


# -- nothing is looked up --------------------------------------------------------------


@pytest.mark.parametrize("spec", ROUND_TRIPS, ids=repr)
def test_reading_a_specification_resolves_no_name_and_lists_no_adapter(
    spec: ty.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: ty.Any, **kwargs: ty.Any) -> ty.NoReturn:
        raise AssertionError("the grammar asked the host")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr"):
        monkeypatch.setattr(socket, name, refuse)
    monkeypatch.setattr(netimps, "iter_interfaces", refuse)
    monkeypatch.setattr(netimps, "get_interfaces", refuse)
    monkeypatch.setattr(netimps, "get_interface", refuse)
    before = netimps.interface_enumerations()
    parse_listen(spec, DEFAULTS)
    assert netimps.interface_enumerations() == before


def test_importing_the_grammar_pulls_in_no_asyncio_and_no_extra() -> None:
    import subprocess
    import sys

    code = (
        "import sys, netimps; "
        "bad = [m for m in ('asyncio', 'duho', 'dns') if m in sys.modules]; "
        "assert not bad, bad"
    )
    import os

    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(path for path in sys.path if path)
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env
    )
    assert done.returncode == 0, done.stderr
