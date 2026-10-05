import operator
import os
import typing

import pytest

import netimps
from netimps import MACAddress, MACAddressLike


@pytest.mark.parametrize(
    "text",
    [
        "AA:BB:CC:DD:EE:FF",
        "aa-bb-cc-dd-ee-ff",
        "AABB.CCDD.EEFF",
        "aa.bb.cc.dd.ee.ff",
        "aabbccddeeff",
        "AABBCCDDEEFF",
    ],
)
def test_accepts_all_separator_forms(text):
    mac = MACAddress(text)
    assert mac.format(":") == "aa:bb:cc:dd:ee:ff"


def test_is_valid_screens_text_without_a_private_pattern():
    """A caller pre-screened text with ``MACAddress._VALID_MAC``, which the class
    docstring invited; ``is_valid`` is the public way and no pattern is on the
    class."""
    assert not hasattr(MACAddress, "_VALID_MAC")
    assert MACAddress.is_valid("AA:BB:CC:DD:EE:FF")
    assert MACAddress.is_valid("aabb.ccdd.eeff")
    assert MACAddress.is_valid("aa.bb.cc.dd.ee.ff")
    assert MACAddress.is_valid("aabbccddeeff")
    assert not MACAddress.is_valid("not a mac")
    assert not MACAddress.is_valid("AA:BB:CC:DD:EE")  # too short


@pytest.mark.parametrize(
    "text",
    [
        "00-11:22-33:44-55",
        "00:11-22:33:44:55",
        "00.11:22.33.44.55",
        "aabb.ccdd:eeff",
        "aabb:ccdd.eeff",
    ],
)
def test_mixed_separators_are_rejected(text):
    """One separator per address -- a mixed spelling is a typo, not a form."""
    assert not MACAddress.is_valid(text)
    with pytest.raises(ValueError):
        MACAddress(text)


def test_format_default_and_custom_separator():
    mac = MACAddress("AA:BB:CC:DD:EE:FF")
    assert mac.format() == "aa:bb:cc:dd:ee:ff"
    assert mac.format("-") == "aa-bb-cc-dd-ee-ff"
    assert mac.format("") == "aabbccddeeff"
    # "." separates octets like every other separator; the Cisco triplet form
    # is an accepted *input* spelling, never an output one.
    assert mac.format(".") == "aa.bb.cc.dd.ee.ff"


@pytest.mark.parametrize("sep", [":", "-", ".", ""])
def test_every_rendered_separator_parses_back(sep):
    """What format prints, the constructor accepts -- in both cases."""
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert MACAddress(mac.format(sep)) == mac
    assert MACAddress(mac.format(sep, upper=True)) == mac


def test_format_upper():
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert mac.format(upper=True) == "AA:BB:CC:DD:EE:FF"
    assert mac.format("-", upper=True) == "AA-BB-CC-DD-EE-FF"
    assert mac.format("", upper=True) == "AABBCCDDEEFF"
    # Explicit upper=False is the documented default.
    assert mac.format("-", upper=False) == "aa-bb-cc-dd-ee-ff"


def test_case_does_not_affect_identity():
    """Rendering case is presentational only -- it must not leak into equality."""
    lower = MACAddress("aa:bb:cc:dd:ee:ff")
    upper = MACAddress("AA:BB:CC:DD:EE:FF")
    assert lower == upper
    assert hash(lower) == hash(upper)
    assert str(lower) == str(upper) == "aa:bb:cc:dd:ee:ff"
    assert lower.format(upper=True) == upper.format(upper=True)


def test_str_and_repr():
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert str(mac) == "aa:bb:cc:dd:ee:ff"
    assert repr(mac) == "MACAddress('aa:bb:cc:dd:ee:ff')"


def test_equality_across_forms_and_types():
    a = MACAddress("AA:BB:CC:DD:EE:FF")
    b = MACAddress("aa-bb-cc-dd-ee-ff")
    assert a == b
    assert a != MACAddress("00:11:22:33:44:55")
    assert (a == 123) is False  # unrelated type
    assert (a == b"\xaa\xbb\xcc\xdd\xee\xff") is False  # not even its own bytes


def test_text_is_never_equal_to_a_mac():
    """BREAKING in 0.3.0: __eq__ no longer coerces a str.

    It cannot: every spelling of one address would compare equal while
    ``str.__hash__`` -- not ours to change -- hashes each differently, so
    ``==`` and ``in`` would disagree. ``try_parse`` is the migration.
    """
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    for text in ("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabb.ccdd.eeff"):
        assert mac != text
        assert text != mac  # the reflected comparison agrees
        assert MACAddress.try_parse(text) == mac  # the documented replacement
    assert mac != "garbage"  # invalid text is unequal, not an error
    assert MACAddress.try_parse("garbage") != mac
    # The invariant the coercion used to break, now holding.
    assert mac not in {"aa:bb:cc:dd:ee:ff"}
    assert mac in {MACAddress("aa:bb:cc:dd:ee:ff")}


def test_hash_eq_invariant_across_every_accepted_spelling():
    """a == b implies hash(a) == hash(b), for every form the type accepts."""
    values = [
        MACAddress(v)
        for v in (
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "aabb.ccdd.eeff",
            "aa.bb.cc.dd.ee.ff",
            "AABBCCDDEEFF",
            0xAABBCCDDEEFF,
            b"\xaa\xbb\xcc\xdd\xee\xff",
            bytearray(b"\xaa\xbb\xcc\xdd\xee\xff"),
            MACAddress("aa:bb:cc:dd:ee:ff"),
        )
    ]
    for value in values:
        assert value == values[0]
        assert hash(value) == hash(values[0])
    assert len(set(values)) == 1
    assert {values[0]: "device"}[MACAddress(0xAABBCCDDEEFF)] == "device"


def test_hashable_as_dict_key():
    a = MACAddress("AA:BB:CC:DD:EE:FF")
    b = MACAddress("aa:bb:cc:dd:ee:ff")
    d = {a: "device"}
    assert d[b] == "device"
    assert len({a, b}) == 1


def test_construct_from_int_bytes_and_instance():
    assert MACAddress(0xAABBCCDDEEFF).format() == "aa:bb:cc:dd:ee:ff"
    assert MACAddress(bytes.fromhex("aabbccddeeff")).format() == "aa:bb:cc:dd:ee:ff"
    original = MACAddress("aa:bb:cc:dd:ee:ff")
    assert MACAddress(original) == original


def test_bytearray_is_accepted_and_copied():
    """bytearray is accepted, and the mutable source cannot move the value."""
    buf = bytearray(b"\xaa\xbb\xcc\xdd\xee\xff")
    mac = MACAddress(buf)
    buf[0] = 0x00
    assert mac == MACAddress("aa:bb:cc:dd:ee:ff")
    assert isinstance(mac.packed, bytes)


def test_maclike_lists_what_the_constructor_accepts():
    """The annotation and the runtime must agree, bytearray included.

    ``MACAddress`` is a forward reference in the alias (it is defined below
    it), so compare by name rather than by class.
    """
    args = {
        arg.__forward_arg__ if isinstance(arg, typing.ForwardRef) else arg
        for arg in typing.get_args(MACAddressLike)
    }
    assert args == {str, int, bytes, bytearray, "MACAddress"}


def test_int_boundaries_accepted():
    assert MACAddress(0).format() == "00:00:00:00:00:00"
    assert MACAddress(0xFFFFFFFFFFFF).format() == "ff:ff:ff:ff:ff:ff"


@pytest.mark.parametrize("value", [-1, -0xAABBCCDDEEFF, 0x1000000000000, 2**64])
def test_out_of_range_int_rejected(value):
    with pytest.raises(ValueError):
        MACAddress(value)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"\x00\x01",
        b"\x00\x01\x02\x03\x04",  # one octet short
        b"\x00\x01\x02\x03\x04\x05\x06",  # one octet long
        bytearray(b"\x00\x01"),
    ],
)
def test_wrong_byte_length_rejected(value):
    with pytest.raises(ValueError):
        MACAddress(value)


@pytest.mark.parametrize(
    "text",
    [
        "not-a-mac",
        "",
        "AA:BB:CC:DD:EE",  # five octets
        "AA:BB:CC:DD:EE:FF:00",  # seven octets
        "aa:bb:cc:dd:ee:gg",  # not hex
        "aabbccddeef",  # eleven bare digits
        "aabbccddeeff0",  # thirteen bare digits
    ],
)
def test_malformed_text_rejected(text):
    with pytest.raises(ValueError):
        MACAddress(text)


def test_invalid_inputs_raise():
    with pytest.raises(ValueError):
        MACAddress("not-a-mac")
    with pytest.raises(ValueError):
        MACAddress(-1)
    with pytest.raises(ValueError):
        MACAddress(b"\x00\x01")  # wrong byte length
    with pytest.raises(TypeError):
        MACAddress(1.5)
    with pytest.raises(TypeError):
        MACAddress(None)


def test_bool_is_not_an_integer_mac():
    """bool is an int subclass, so it would otherwise mint 00:00:00:00:00:01."""
    with pytest.raises(TypeError):
        MACAddress(True)
    with pytest.raises(TypeError):
        MACAddress(False)
    assert MACAddress.is_valid(True) is False
    with pytest.raises(TypeError):
        MACAddress.try_parse(False)  # type: ignore[call-overload]


def test_classification_bits():
    """The U/L and group bits are read from the first octet."""
    # 0x01 set -> multicast; 0x02 set -> locally administered.
    assert MACAddress("01:00:5e:00:00:01").is_multicast
    assert not MACAddress("00:00:5e:00:53:02").is_multicast
    assert MACAddress("02:00:00:00:00:01").is_local
    assert MACAddress("02:00:00:00:00:01").is_universal is False
    assert MACAddress("00:00:5e:00:53:01").is_universal
    assert not MACAddress("00:00:5e:00:53:01").is_local
    # Broadcast is both multicast and locally administered.
    bcast = MACAddress("ff:ff:ff:ff:ff:ff")
    assert bcast.is_multicast and bcast.is_local


def test_oui_is_first_three_bytes():
    assert MACAddress("00:00:5e:00:53:01").oui == b"\x00\x00\x5e"


def test_oui_keeps_the_flag_bits_as_documented():
    """.oui is the wire prefix, flags included -- not a registry lookup key."""
    group = MACAddress("01:00:5e:00:00:01")
    assert group.oui == b"\x01\x00\x5e"  # I/G set: not the assigned OUI
    assert bytes([group.oui[0] & 0xFC]) + group.oui[1:] == b"\x00\x00\x5e"
    local = MACAddress("02:00:5e:00:00:01")
    assert local.oui == b"\x02\x00\x5e"  # U/L set: likewise
    assert local.is_local and group.is_multicast


def test_ordering_and_sorting():
    low = MACAddress("00:00:00:00:00:01")
    high = MACAddress("ff:ff:ff:ff:ff:ff")
    assert low < high and high > low
    assert low <= low and high >= high
    assert sorted([high, low]) == [low, high]


def test_ordering_is_total_and_agrees_with_equality():
    """Every pair is ordered one way only, and equals compare both ways."""
    ordered = [
        MACAddress("00:00:00:00:00:00"),
        MACAddress("00:00:00:00:00:01"),
        MACAddress("01:00:5e:00:00:01"),
        MACAddress("ff:ff:ff:ff:ff:ff"),
    ]
    for i, low in enumerate(ordered):
        assert low <= low and low >= low
        assert not (low < low or low > low)
        for high in ordered[i + 1 :]:
            assert low < high and high > low
            assert low <= high and high >= low
            assert not (low > high or high < low)
            assert low != high
    assert sorted(reversed(ordered)) == ordered


@pytest.mark.parametrize("other", ["00:00:00:00:00:02", 5, b"\x00" * 6, None])
@pytest.mark.parametrize("op", [operator.lt, operator.le, operator.gt, operator.ge])
def test_ordering_against_a_non_mac_raises(op, other):
    """Ordering against a non-MAC is undefined, not a crash-by-coercion."""
    with pytest.raises(TypeError):
        op(MACAddress("00:00:00:00:00:01"), other)


def test_is_valid_mac_never_raises():
    from netimps import MACAddress, is_valid

    assert is_valid("aa:bb:cc:dd:ee:ff", MACAddress)
    assert is_valid(0xAABBCCDDEEFF, MACAddress)
    assert not is_valid("not a mac", MACAddress)
    assert not is_valid("", MACAddress)
    assert not is_valid(None, MACAddress)
    assert not is_valid(object(), MACAddress)


def test_is_valid_returns_a_plain_bool():
    """No TypeGuard: proving text parses must not narrow the text itself.

    A ``TypeGuard[MACAddress]`` would let a checker certify ``value.packed``
    inside the True branch, on an object that is still a ``str``.
    """
    assert MACAddress.is_valid("aa:bb:cc:dd:ee:ff") is True
    assert MACAddress.is_valid("nope") is False
    assert typing.get_type_hints(MACAddress.is_valid)["return"] is bool


def test_packed_roundtrip():
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert MACAddress(mac.packed) == mac
    assert MACAddress(int(mac)) == mac


def test_classmethod_validators():
    """The type-local spellings agree with the generic combinators."""
    from netimps import MACAddress, is_valid, try_parse

    for value in [
        "aa:bb:cc:dd:ee:ff",
        "AABB.CCDD.EEFF",
        "nope",
        "",
        None,
        12,
        True,
        object(),
    ]:
        assert MACAddress.is_valid(value) == is_valid(value, MACAddress)
        if isinstance(value, str):
            assert (MACAddress.try_parse(value) is None) == (
                try_parse(value, MACAddress) is None
            )
        else:
            # The classmethod takes text only; the generic answers for any object.
            with pytest.raises(TypeError):
                MACAddress.try_parse(value)  # type: ignore[call-overload]


def test_classmethod_validators_bind_to_subclass():
    """classmethod, not staticmethod -- a subclass validates against itself."""

    class Vendor(MACAddress):
        pass

    parsed = Vendor.try_parse("aa:bb:cc:dd:ee:ff")
    assert isinstance(parsed, Vendor)
    assert Vendor.is_valid("aa:bb:cc:dd:ee:ff")
    assert not Vendor.is_valid("nope")


IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------- #
# MACAddress subclassing -- a documented guarantee                            #
# --------------------------------------------------------------------------- #


class _WireMAC(netimps.MACAddress):
    """A subclass overriding only __str__, as a caller would."""

    def __str__(self):
        return self.format("-", upper=True)

    def hex(self, *args):
        return self.packed.hex(*args)


def test_mac_subclass_can_change_str_only():
    mac = _WireMAC("aa:bb:cc:dd:ee:ff")
    assert str(mac) == "AA-BB-CC-DD-EE-FF"
    # Everything else is inherited unchanged.
    assert mac.packed == bytes.fromhex("aabbccddeeff")
    assert mac.format() == "aa:bb:cc:dd:ee:ff"
    assert mac.oui == b"\xaa\xbb\xcc"


def test_mac_subclass_keeps_equality_and_hashing():
    """A subclass must interoperate with the base type, or dicts break."""
    base = netimps.MACAddress("aa:bb:cc:dd:ee:ff")
    sub = _WireMAC("AA-BB-CC-DD-EE-FF")
    assert sub == base and base == sub
    assert hash(sub) == hash(base)
    # The pair must collapse to one key, not two.
    assert len({base, sub}) == 1
    assert {base: "x"}[sub] == "x"


def test_mac_subclass_keeps_ordering_and_validation():
    low = _WireMAC("00:00:00:00:00:01")
    high = _WireMAC("ff:ff:ff:ff:ff:ff")
    assert low < high
    assert sorted([high, low]) == [low, high]
    with pytest.raises(ValueError):
        _WireMAC("00-11-22")  # too short


def test_mac_subclass_classmethods_bind_to_the_subclass():
    parsed = _WireMAC.try_parse("aa:bb:cc:dd:ee:ff")
    assert isinstance(parsed, _WireMAC)
    assert str(parsed) == "AA-BB-CC-DD-EE-FF"
    assert _WireMAC.is_valid("aa:bb:cc:dd:ee:ff")
    assert not _WireMAC.is_valid("nope")


def test_mac_subclass_hex_passthrough():
    """.hex() is the one bytes method a caller may need to re-add."""
    assert _WireMAC("aa:bb:cc:dd:ee:ff").hex("-").upper() == "AA-BB-CC-DD-EE-FF"


# --------------------------------------------------------------------------- #
# MACAddress.hex                                                              #
# --------------------------------------------------------------------------- #


def test_mac_hex_matches_bytes_hex():
    """A pure passthrough -- the reason callers subclassed this type."""
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert mac.hex() == "aabbccddeeff" == mac.packed.hex()
    assert mac.hex(":") == mac.packed.hex(":") == "aa:bb:cc:dd:ee:ff"
    assert mac.hex("-", 2) == mac.packed.hex("-", 2) == "aabb-ccdd-eeff"


def test_mac_hex_is_lowercase_like_str_and_unlike_format_upper():
    mac = MACAddress("AA:BB:CC:DD:EE:FF")
    assert mac.hex(":") == "aa:bb:cc:dd:ee:ff"
    assert mac.format(":", upper=True) == "AA:BB:CC:DD:EE:FF"
