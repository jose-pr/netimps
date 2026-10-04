"""Text and wire forms: `MACAddress.format` / `__format__` / `__bytes__`,
and `FQDN.encode` / `decode` / `decode_at` / `__bytes__`.

The wire tests build messages by hand rather than through the encoder under
test, so a defect shared by `encode` and `decode` cannot cancel out.
"""

import random
import string

import pytest

import netimps
from netimps import DNSDecodeError, FQDN, MACAddress

# ---------------------------------------------------------------- MACAddress


MAC = MACAddress("aa:bb:cc:dd:ee:ff")


def test_format_defaults_to_lowercase_colons():
    assert MAC.format() == "aa:bb:cc:dd:ee:ff"
    assert MAC.format("-") == "aa-bb-cc-dd-ee-ff"
    assert MAC.format("", upper=True) == "AABBCCDDEEFF"


def test_upper_is_keyword_only():
    """`format("-", True)` reads as nothing; the flag must be named."""
    with pytest.raises(TypeError):
        MAC.format("-", True)  # type: ignore[misc]


@pytest.mark.parametrize("sep", [":", "-", ".", "", "_", " "])
def test_the_format_spec_is_the_separator_and_a_trailing_x_is_upper_case(sep):
    """`format(mac, "-X")` equals `mac.format("-", upper=True)`."""
    assert format(MAC, sep) == (MAC.format(sep) if sep else str(MAC))
    assert format(MAC, sep + "X") == MAC.format(sep, upper=True)
    assert f"{MAC:{sep}X}" == MAC.format(sep, upper=True)


def test_an_empty_spec_is_str_and_follows_a_subclass_override():
    """`f"{mac}"` must agree with `str(mac)`, including for a subclass that
    changes `__str__`; a spec that bypassed it would print a different text."""

    class Shouting(MACAddress):
        def __str__(self):
            return "SHOUT"

    assert f"{MAC}" == str(MAC) == "aa:bb:cc:dd:ee:ff"
    assert f"{Shouting('aa:bb:cc:dd:ee:ff')}" == "SHOUT"


def test_bytes_is_the_six_octets():
    assert bytes(MAC) == bytes.fromhex("aabbccddeeff") == MAC.packed
    assert MACAddress(bytes(MAC)) == MAC


@pytest.mark.parametrize("sep", [":", "-", ".", ""])
def test_the_formatted_text_parses_back(sep):
    rng = random.Random(7)
    for _ in range(100):
        mac = MACAddress(bytes(rng.randrange(256) for _ in range(6)))
        assert MACAddress.parse(mac.format(sep)) == mac
        assert MACAddress.parse(mac.format(sep, upper=True)) == mac


def test_as_str_is_gone():
    """No alias is kept for the old spelling."""
    assert not hasattr(MACAddress, "as_str")


# ---------------------------------------------------------------------- FQDN


def _names(rng: random.Random, count: int = 200):
    alphabet = string.ascii_lowercase + string.digits + "-_"
    for _ in range(count):
        labels = [
            "a" + "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 20)))
            for _ in range(rng.randrange(1, 6))
        ]
        yield FQDN(".".join(labels) + ".")


def test_encode_is_the_length_prefixed_form():
    assert FQDN("www.example.com").encode() == b"\x03www\x07example\x03com\x00"
    assert bytes(FQDN("www.example.com")) == FQDN("www.example.com").encode()


def test_decode_inverts_encode_for_every_name():
    """`FQDN.decode(v.encode()) == v` over a seeded random corpus.

    The wire has no relative form, so the names are fully qualified; a relative
    one decodes to its `fully_qualified()` twin, which the second assertion pins.
    """
    for name in _names(random.Random(20261004)):
        assert FQDN.decode(name.encode()) == name
        assert FQDN.decode(bytes(name)) == name
        relative = name.relative()
        assert FQDN.decode(relative.encode()) == relative.fully_qualified()


def test_decode_accepts_a_buffer_of_any_bytes_like_type():
    wire = FQDN("a.example.").encode()
    assert FQDN.decode(bytearray(wire)) == FQDN("a.example.")
    assert FQDN.decode(memoryview(wire)) == FQDN("a.example.")


def test_decode_keeps_the_case_it_was_given():
    wire = b"\x03WwW\x07Example\x03com\x00"
    assert str(FQDN.decode(wire)) == "WwW.Example.com."
    assert FQDN.decode(wire) == FQDN("www.example.com.")


def test_decode_at_follows_a_pointer_and_reports_the_end_in_the_record():
    """The returned offset is past the two-byte pointer, not past the target."""
    # offset 0: example.com ; offset 13: "www" + pointer to 0 ; then a marker byte
    message = b"\x07example\x03com\x00" + b"\x03www\xc0\x00" + b"\xee"
    name, end = FQDN.decode_at(message, 13)
    assert name == FQDN("www.example.com.")
    assert end == 13 + 4 + 2
    assert message[end] == 0xEE

    plain, end = FQDN.decode_at(message, 0)
    assert plain == FQDN("example.com.")
    assert end == 13


def test_a_pointer_loop_raises_dns_decode_error():
    """A pointer to itself, or two pointers to each other, must terminate."""
    with pytest.raises(DNSDecodeError):
        FQDN.decode_at(b"\xc0\x00", 0)
    with pytest.raises(DNSDecodeError):
        FQDN.decode_at(b"\x01a\xc0\x04\x01b\xc0\x00", 0)
    with pytest.raises(DNSDecodeError):
        FQDN.decode(b"\xc0\x00")


@pytest.mark.parametrize(
    "wire",
    [
        b"",  # nothing at all
        b"\x03ww",  # label runs off the end
        b"\x03www",  # no root terminator
        b"\xc0",  # half a pointer
        b"\x40a\x00",  # reserved label type, longer than 63
        b"\x00",  # the root has no labels
        b"\x03w.w\x00",  # a dot inside a label cannot be an FQDN label
        b"\x03w w\x00",  # nor can a space or control byte
        b"\x01\xc3\x00",  # nor a non-ASCII byte
        b"\x03www\x00\x00",  # bytes left after the name
    ],
)
def test_malformed_wire_data_raises_dns_decode_error(wire):
    with pytest.raises(DNSDecodeError):
        FQDN.decode(wire)


def test_a_name_over_255_octets_raises():
    wire = (b"\x3f" + b"a" * 63) * 4 + b"\x00"  # 4 * 64 + 1 = 257 octets
    with pytest.raises(DNSDecodeError):
        FQDN.decode(wire)
    ok = (b"\x3f" + b"a" * 63) * 3 + b"\x3d" + b"a" * 61 + b"\x00"  # 255 octets
    assert len(ok) == 255
    assert len(str(FQDN.decode(ok))) == 253 + 1


def test_decode_at_rejects_an_offset_outside_the_message():
    for offset in (-1, 99):
        with pytest.raises(DNSDecodeError):
            FQDN.decode_at(b"\x01a\x00", offset)


def test_dns_decode_error_is_a_value_error():
    with pytest.raises(ValueError):
        FQDN.decode(b"")


def test_decode_on_a_subclass_returns_the_subclass():
    class Mine(FQDN):
        pass

    assert type(Mine.decode(b"\x01a\x00")) is Mine


def test_the_old_wire_forms_are_gone():
    """No alias is kept for `wire`, `unicode` or `as_fully_qualified`."""
    name = FQDN("example.com")
    for old in ("wire", "unicode", "as_fully_qualified"):
        assert not hasattr(name, old)


def test_to_unicode_and_fully_qualified_are_methods():
    name = FQDN("münchen.de")
    assert name.to_unicode() == "münchen.de"
    assert str(name.fully_qualified()) == "xn--mnchen-3ya.de."
    assert name.fully_qualified().fully_qualified() == name.fully_qualified()


def test_the_codec_in_resolve_wire_reads_names_through_the_same_reader():
    """`_dnswire` and `FQDN.decode_at` share one reader, so a pointer loop is
    refused identically in a resolver reply."""
    from netimps._dns import _dnswire

    with pytest.raises(DNSDecodeError):
        _dnswire._read_name(b"\xc0\x00", 0)
    assert netimps.DNSDecodeError is DNSDecodeError


# ------------------------------------------- one rule for what a label holds


def _wider_corpus():
    rng = random.Random(20261005)
    seeds = [
        "WWW.Example.COM.",
        "MiXeD.CaSe.example.",
        "münchen.de.",
        "例え.テスト.",
        "xn--mnchen-3ya.de.",
        "_dmarc.example.com.",
        "*.example.com.",
        "1.2.3.4.sub.",
        "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61 + ".",
        "example。com。",
    ]
    for text in seeds:
        yield FQDN(text)
    for name in _names(rng, 100):
        yield FQDN(
            ".".join(
                label.upper() if rng.random() < 0.5 else label for label in name.labels
            )
            + "."
        )
    base = FQDN("1.2.3.4.sub.")
    yield base.reverse()
    yield from base.domains
    yield FQDN("example.com.") / "www"
    yield FQDN("example.com.").with_hostname("MAIL")


def test_decode_inverts_encode_over_mixed_case_derived_and_non_ascii_names():
    for name in _wider_corpus():
        absolute = name.fully_qualified()
        assert FQDN.decode(absolute.encode()) == absolute


def test_whatever_the_constructor_accepts_the_wire_entry_accepts():
    """A fuzz over characters that cross the label rule: construction either
    refuses, or the result survives encode, decode and parse."""
    rng = random.Random(7)
    alphabet = "ab1-_ .:/\n\x00\x7f。１ü*@"
    accepted = 0
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 12)))
        try:
            v = FQDN(text)
        except (ValueError, TypeError):
            continue
        accepted += 1
        assert FQDN.decode(v.fully_qualified().encode()) == v.fully_qualified()
        assert FQDN.parse(str(v)) == v
    assert accepted > 50
