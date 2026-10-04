"""The name codec: a name as DNS labels, and the labels of a name in a message."""

from __future__ import annotations

from typing import List, Tuple
from .._exceptions import DNSDecodeError

#: Compression pointers one name may follow. A real name uses one or two; the
#: cap keeps a hostile reply from making every record walk a long chain.
MAX_POINTERS = 32


def encode_name(name: str) -> bytes:
    """``name`` as DNS labels (IDNA for a non-ASCII label), at most 255 octets
    on the wire."""
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            raise DNSDecodeError("empty label in %r" % name)
        raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if len(raw) > 63:
            raise DNSDecodeError("label longer than 63 bytes in %r" % name)
        out += bytes([len(raw)]) + raw
    if len(out) + 1 > 255:
        raise DNSDecodeError("name longer than 255 bytes in %r" % name)
    return out + b"\x00"


def read_labels(data: bytes, pos: int) -> Tuple[List[bytes], int]:
    """The labels of the name at ``pos``, compression pointers followed, and
    the offset just past the name in the record.

    A pointer to an offset already visited is a loop, and a name follows at most
    :data:`MAX_POINTERS` pointers. The name is capped at 255 octets (RFC 1035
    3.1) and a label at 63, so a hostile message cannot make this run long or
    allocate much.
    """
    labels: List[bytes] = []
    end = None
    visited = set()
    pointers = 0
    size = 1  # the root's length byte
    while True:
        if pos >= len(data):
            raise DNSDecodeError("name runs past the message")
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DNSDecodeError("truncated compression pointer")
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            if pos in visited:
                raise DNSDecodeError("compression loop")
            visited.add(pos)
            pointers += 1
            if pointers > MAX_POINTERS:
                raise DNSDecodeError(
                    "name follows more than %d compression pointers" % MAX_POINTERS
                )
            continue
        if length > 63:
            raise DNSDecodeError("label longer than 63 bytes")
        if length == 0:
            return labels, (end if end is not None else pos + 1)
        if pos + 1 + length > len(data):
            raise DNSDecodeError("name runs past the message")
        size += 1 + length
        if size > 255:
            raise DNSDecodeError("name longer than 255 bytes")
        labels.append(data[pos + 1 : pos + 1 + length])
        pos += 1 + length
