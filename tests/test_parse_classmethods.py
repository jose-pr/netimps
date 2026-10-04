"""`MACAddress`, `FQDN` and `Host` each parse text through `Type.parse`.

The classmethods take text only and answer a wrong-typed argument with
`TypeError`; the generic `netimps.parse` / `try_parse` keep answering for any
object. Round-trip checks run over a seeded random corpus because the suite
carries no property-testing dependency.
"""

import ipaddress
import random
import string

import pytest

import netimps
from netimps import FQDN, Host, MACAddress, NetimpsValueError

TYPES = [MACAddress, FQDN, Host]
GOOD = {
    MACAddress: "aa:bb:cc:dd:ee:ff",
    FQDN: "www.example.com",
    Host: "db.internal",
}
BAD = {MACAddress: "not a mac", FQDN: "a..b", Host: "   "}


def _macs(rng: random.Random, count: int = 200):
    for _ in range(count):
        yield MACAddress(bytes(rng.randrange(256) for _ in range(6)))


def _names(rng: random.Random, count: int = 200):
    alphabet = string.ascii_lowercase + string.digits + "-"
    for _ in range(count):
        labels = [
            "a" + "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 12)))
            for _ in range(rng.randrange(1, 5))
        ]
        yield FQDN(".".join(labels) + ("." if rng.random() < 0.3 else ""))


def _hosts(rng: random.Random, count: int = 200):
    for name in _names(rng, count):
        yield Host(str(name))
    for _ in range(count):
        yield Host(str(ipaddress.IPv4Address(rng.getrandbits(32))))
        yield Host(str(ipaddress.IPv6Address(rng.getrandbits(128))))


CORPUS = {MACAddress: _macs, FQDN: _names, Host: _hosts}


@pytest.mark.parametrize("kind", TYPES)
def test_parse_of_the_text_form_gives_back_the_value(kind):
    """`Type.parse(str(v)) == v`: the canonical text is accepted by `parse`."""
    for value in CORPUS[kind](random.Random(20261004)):
        again = kind.parse(str(value))
        assert again == value
        assert type(again) is kind


@pytest.mark.parametrize("kind", TYPES)
def test_parse_raises_the_value_error_for_bad_text(kind):
    """Bad text is `NetimpsValueError`, which is still a `ValueError`."""
    with pytest.raises(NetimpsValueError):
        kind.parse(BAD[kind])
    with pytest.raises(ValueError):
        kind.parse(BAD[kind])


@pytest.mark.parametrize("kind", TYPES)
@pytest.mark.parametrize("wrong", [None, 3.5, [], 12, b"abcdef", True])
def test_parse_and_try_parse_raise_type_error_for_non_text(kind, wrong):
    """A non-`str` argument is the caller's bug and must not read as "invalid"."""
    with pytest.raises(TypeError):
        kind.parse(wrong)
    with pytest.raises(TypeError):
        kind.try_parse(wrong)


@pytest.mark.parametrize("kind", TYPES)
def test_try_parse_answers_none_or_the_default_for_bad_text(kind):
    """Bad text gives `None`, or the caller's `default`; good text parses."""
    assert kind.try_parse(BAD[kind]) is None
    sentinel = object()
    assert kind.try_parse(BAD[kind], sentinel) is sentinel
    assert kind.try_parse(BAD[kind], default=sentinel) is sentinel
    assert kind.try_parse(GOOD[kind]) == kind.parse(GOOD[kind])


@pytest.mark.parametrize("kind", [MACAddress, FQDN])
def test_is_valid_never_raises(kind):
    """`is_valid` is a predicate: any object, a `bool` back, no exception."""
    for value in (GOOD[kind], BAD[kind], None, 3.5, [], object(), b""):
        assert isinstance(kind.is_valid(value), bool)


def test_a_host_parses_an_address_and_a_name_alike():
    """`Host` keeps whatever text it was given; only nothing at all is refused."""
    assert Host.parse("10.0.0.5").is_address
    assert not Host.parse("db.internal").is_address
    assert str(Host.parse("  db.internal ")) == "db.internal"
    with pytest.raises(NetimpsValueError):
        Host.parse("")


def test_the_generic_try_parse_still_answers_the_default_for_any_object():
    """Only the classmethods are strict about the argument type.

    `Host` is left out: its constructor accepts any object and keeps its text,
    so there is no "not a host" to answer the default for.
    """
    for kind in (MACAddress, FQDN):
        assert netimps.try_parse(None, kind) is None
        assert netimps.try_parse(3.5, kind) is None
        assert netimps.try_parse([], kind, "fallback") == "fallback"
        assert netimps.is_valid(None, kind) is False


def test_the_generic_parse_calls_the_types_own_parse_for_text():
    """The spellings a type accepts live in `Type.parse`, not in a second copy.

    A subclass overriding `parse` is the probe: if the generic function went
    straight to the constructor it would never see the override.
    """

    class Marked(MACAddress):
        @classmethod
        def parse(cls, text):
            return "from Marked.parse"

    assert netimps.parse("aa:bb:cc:dd:ee:ff", Marked) == "from Marked.parse"
    assert netimps.parse("aa:bb:cc:dd:ee:ff", MACAddress) == MACAddress(
        "aa:bb:cc:dd:ee:ff"
    )


def test_the_generic_parse_still_builds_a_mac_from_bytes_and_an_int():
    """`bytes` and `int` are not text, so they go to the constructor.

    Interface lookup recognises a packed 6-byte MAC through this route.
    """
    packed = bytes.fromhex("aabbccddeeff")
    expected = MACAddress("aa:bb:cc:dd:ee:ff")
    assert netimps.parse(packed, MACAddress) == expected
    assert netimps.parse(0xAABBCCDDEEFF, MACAddress) == expected
    assert netimps.try_parse(packed, MACAddress) == expected


def test_parse_on_a_subclass_returns_the_subclass():
    """A consumer's subclass must come back as itself, not as the base."""

    class Mine(FQDN):
        pass

    assert type(Mine.parse("a.example")) is Mine
    assert type(netimps.parse("a.example", Mine)) is Mine
