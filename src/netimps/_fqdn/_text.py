"""What a name's text may hold: the label limits, the IDNA encoding and the delimiters it refuses."""

from __future__ import annotations

from .._exceptions import NetimpsValueError

#: RFC 1035 2.3.4. 253 rather than 255: the wire form spends one octet on each
#: label's length prefix and one on the root, so the printable form caps lower
#: than the oft-quoted 255.
MAX_NAME_LENGTH = 253


#: RFC 1035 2.3.4, per label.
MAX_LABEL_LENGTH = 63


#: The characters IDNA reads as a dot besides ``.`` (U+3002, U+FF0E, U+FF61).
_IDEOGRAPHIC_DOTS = {0x3002: ".", 0xFF0E: ".", 0xFF61: "."}


#: RFC 3986 section 2.2 general delimiters. The wire carries any printable
#: byte in a label, but text holding one of these is a URL or an address, not
#: a name, so `FQDN("http://example.com")` is refused rather than kept.
_URI_DELIMITERS = frozenset(":/?#[]@")


def _idna_encode(label: str) -> str:
    """ASCII-encode one label, via IDNA where it is not already ASCII.

    Uses the standard library's ``str.encode("idna")``, which is **IDNA 2003**
    -- not the newer IDNA 2008 that the third-party ``idna`` package
    implements. The difference matters for a handful of names (notably the
    handling of ``ß`` and final sigma), and taking a dependency to fix that is
    not a trade this package makes. Documented rather than hidden.
    """
    if not label:
        return label
    try:
        label.encode("ascii")
        return label
    except UnicodeEncodeError:
        pass
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NetimpsValueError("label %r is not encodable as IDNA: %s" % (label, exc))


def is_label(label: bytes) -> bool:
    """Whether ``label`` is a label an :class:`netimps.FQDN` can hold: one or
    more printable ASCII bytes (0x21 to 0x7E) and no dot.

    The one rule the text and the wire entries of ``FQDN`` share.
    """
    return bool(label) and all(0x21 <= byte <= 0x7E and byte != 0x2E for byte in label)
