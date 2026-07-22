import re

import pytest

from netimps import MACAddress


@pytest.mark.parametrize(
    "text",
    [
        "AA:BB:CC:DD:EE:FF",
        "aa-bb-cc-dd-ee-ff",
        "AABB.CCDD.EEFF",
        "aabbccddeeff",
        "AABBCCDDEEFF",
    ],
)
def test_accepts_all_separator_forms(text):
    mac = MACAddress(text)
    assert mac.as_str(":") == "aa:bb:cc:dd:ee:ff"


def test_valid_mac_is_compiled_pattern():
    assert isinstance(MACAddress._VALID_MAC, re.Pattern)
    assert MACAddress._VALID_MAC.match("AA:BB:CC:DD:EE:FF")
    assert MACAddress._VALID_MAC.match("aabb.ccdd.eeff")
    assert MACAddress._VALID_MAC.match("aabbccddeeff")
    assert not MACAddress._VALID_MAC.match("not a mac")
    assert not MACAddress._VALID_MAC.match("AA:BB:CC:DD:EE")  # too short


def test_as_str_default_and_custom_separator():
    mac = MACAddress("AA:BB:CC:DD:EE:FF")
    assert mac.as_str() == "aa:bb:cc:dd:ee:ff"
    assert mac.as_str("-") == "aa-bb-cc-dd-ee-ff"
    assert mac.as_str("") == "aabbccddeeff"
    assert mac.as_str(".") == "aa.bb.cc.dd.ee.ff"


def test_as_str_upper():
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert mac.as_str(upper=True) == "AA:BB:CC:DD:EE:FF"
    assert mac.as_str("-", upper=True) == "AA-BB-CC-DD-EE-FF"
    assert mac.as_str("", upper=True) == "AABBCCDDEEFF"
    # Explicit upper=False is the documented default.
    assert mac.as_str("-", upper=False) == "aa-bb-cc-dd-ee-ff"


def test_case_does_not_affect_identity():
    """Rendering case is presentational only -- it must not leak into equality."""
    lower = MACAddress("aa:bb:cc:dd:ee:ff")
    upper = MACAddress("AA:BB:CC:DD:EE:FF")
    assert lower == upper
    assert hash(lower) == hash(upper)
    assert str(lower) == str(upper) == "aa:bb:cc:dd:ee:ff"
    assert lower.as_str(upper=True) == upper.as_str(upper=True)


def test_str_and_repr():
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert str(mac) == "aa:bb:cc:dd:ee:ff"
    assert repr(mac) == "MACAddress('aa:bb:cc:dd:ee:ff')"


def test_equality_across_forms_and_types():
    a = MACAddress("AA:BB:CC:DD:EE:FF")
    b = MACAddress("aa-bb-cc-dd-ee-ff")
    assert a == b
    assert a == "aabb.ccdd.eeff"  # compares against a string form
    assert a != MACAddress("00:11:22:33:44:55")
    assert a != "garbage"  # invalid string is unequal, not an error
    assert (a == 123) is False  # unrelated type


def test_hashable_as_dict_key():
    a = MACAddress("AA:BB:CC:DD:EE:FF")
    b = MACAddress("aa:bb:cc:dd:ee:ff")
    d = {a: "device"}
    assert d[b] == "device"
    assert len({a, b}) == 1


def test_construct_from_int_bytes_and_instance():
    assert MACAddress(0xAABBCCDDEEFF).as_str() == "aa:bb:cc:dd:ee:ff"
    assert MACAddress(bytes.fromhex("aabbccddeeff")).as_str() == "aa:bb:cc:dd:ee:ff"
    original = MACAddress("aa:bb:cc:dd:ee:ff")
    assert MACAddress(original) == original


def test_invalid_inputs_raise():
    with pytest.raises(ValueError):
        MACAddress("not-a-mac")
    with pytest.raises(ValueError):
        MACAddress("AA:BB:CC:DD:EE")
    with pytest.raises(ValueError):
        MACAddress(-1)
    with pytest.raises(ValueError):
        MACAddress(b"\x00\x01")  # wrong byte length
    with pytest.raises(TypeError):
        MACAddress(1.5)


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


def test_ordering_and_sorting():
    low = MACAddress("00:00:00:00:00:01")
    high = MACAddress("ff:ff:ff:ff:ff:ff")
    assert low < high and high > low
    assert low <= low and high >= high
    assert sorted([high, low]) == [low, high]
    # Ordering against a non-MAC is undefined, not a crash-by-coercion.
    with pytest.raises(TypeError):
        low < "00:00:00:00:00:02"


def test_is_valid_mac_never_raises():
    from netimps import MACAddress, is_valid

    assert is_valid("aa:bb:cc:dd:ee:ff", MACAddress)
    assert is_valid(0xAABBCCDDEEFF, MACAddress)
    assert not is_valid("not a mac", MACAddress)
    assert not is_valid("", MACAddress)
    assert not is_valid(None, MACAddress)
    assert not is_valid(object(), MACAddress)


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
        object(),
    ]:
        assert MACAddress.is_valid(value) == is_valid(value, MACAddress)
        assert (MACAddress.try_parse(value) is None) == (
            try_parse(value, MACAddress) is None
        )


def test_classmethod_validators_bind_to_subclass():
    """classmethod, not staticmethod -- a subclass validates against itself."""

    class Vendor(MACAddress):
        pass

    parsed = Vendor.try_parse("aa:bb:cc:dd:ee:ff")
    assert isinstance(parsed, Vendor)
    assert Vendor.is_valid("aa:bb:cc:dd:ee:ff")
    assert not Vendor.is_valid("nope")
