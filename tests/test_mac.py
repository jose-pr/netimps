import re

import pytest

from netutils import MACAddress


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


def test_str_and_repr():
    mac = MACAddress("aa:bb:cc:dd:ee:ff")
    assert str(mac) == "aa:bb:cc:dd:ee:ff"
    assert repr(mac) == "MACAddress('aa:bb:cc:dd:ee:ff')"


def test_equality_across_forms_and_types():
    a = MACAddress("AA:BB:CC:DD:EE:FF")
    b = MACAddress("aa-bb-cc-dd-ee-ff")
    assert a == b
    assert a == "aabb.ccdd.eeff"        # compares against a string form
    assert a != MACAddress("00:11:22:33:44:55")
    assert a != "garbage"                # invalid string is unequal, not an error
    assert (a == 123) is False           # unrelated type


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
