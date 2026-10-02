"""The DNS message format (internal): enough of RFC 1035 to ask one question
and read the answer, with no dependency.

Used by :func:`netimps.resolve_wire` (UDP/TCP to explicit nameservers) and
:func:`netimps.resolve_doh` (RFC 8484, the same bytes over HTTPS). Records
come back as the native types the other backends return: ``A``/``AAAA`` as
:mod:`ipaddress` objects, names (``CNAME``/``PTR``/``NS``) as ``str`` without
the root dot, ``MX``/``SRV`` as their presentation text, ``TXT`` unquoted.
"""

from __future__ import annotations

import ipaddress
import struct
from typing import Any, Dict, List, Optional, Tuple

#: The record types this codec reads, by the name ``resolve()`` takes.
RDTYPES: Dict[str, int] = {
    "a": 1,
    "ns": 2,
    "cname": 5,
    "ptr": 12,
    "mx": 15,
    "txt": 16,
    "aaaa": 28,
    "srv": 33,
}
_NAMES = {code: name for name, code in RDTYPES.items()}

NOERROR, SERVFAIL, NXDOMAIN, REFUSED = 0, 2, 3, 5

#: The EDNS(0) UDP payload size advertised: the DNS flag-day value, which
#: avoids fragmentation on any path.
EDNS_PAYLOAD = 1232


class WireError(ValueError):
    """Bytes that are not a DNS message this codec can read."""


def encode_name(name: str) -> bytes:
    """``name`` as DNS labels (IDNA for a non-ASCII label)."""
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            raise WireError("empty label in %r" % name)
        raw = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if len(raw) > 63:
            raise WireError("label longer than 63 bytes in %r" % name)
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def reverse_name(address: str) -> str:
    """The ``in-addr.arpa`` / ``ip6.arpa`` name a PTR lookup of ``address``
    asks for."""
    return ipaddress.ip_address(address).reverse_pointer


def build_query(name: str, rdtype: str, ident: int, edns: bool = True) -> bytes:
    """One question for ``name``/``rdtype``, recursion desired, with an
    EDNS(0) OPT record unless ``edns`` is false."""
    code = RDTYPES.get(rdtype.lower())
    if code is None:
        raise WireError("record type %r is not one this codec reads" % rdtype)
    header = struct.pack("!HHHHHH", ident & 0xFFFF, 0x0100, 1, 0, 0, 1 if edns else 0)
    question = encode_name(name) + struct.pack("!HH", code, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, EDNS_PAYLOAD, 0, 0) if edns else b""
    return header + question + opt


def _read_name(data: bytes, pos: int) -> Tuple[str, int]:
    """The name at ``pos`` (compression pointers followed) and the offset just
    past it in the record."""
    labels: List[str] = []
    end = None
    jumps = 0
    while True:
        if pos >= len(data):
            raise WireError("name runs past the message")
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise WireError("truncated compression pointer")
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            jumps += 1
            if jumps > 64:
                raise WireError("compression loop")
            continue
        if length == 0:
            return ".".join(labels), (end if end is not None else pos + 1)
        labels.append(data[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length


def _rdata(data: bytes, rtype: int, start: int, length: int) -> Any:
    raw = data[start : start + length]
    if rtype == 1 and length == 4:
        return ipaddress.IPv4Address(raw)
    if rtype == 28 and length == 16:
        return ipaddress.IPv6Address(raw)
    if rtype in (2, 5, 12):
        return _read_name(data, start)[0]
    if rtype == 15:
        return "%d %s" % (
            struct.unpack("!H", raw[:2])[0],
            _read_name(data, start + 2)[0],
        )
    if rtype == 33:
        priority, weight, port = struct.unpack("!HHH", raw[:6])
        return "%d %d %d %s" % (priority, weight, port, _read_name(data, start + 6)[0])
    if rtype == 16:
        parts, pos = [], 0
        while pos < len(raw):
            size = raw[pos]
            parts.append(raw[pos + 1 : pos + 1 + size].decode("utf-8", "replace"))
            pos += 1 + size
        return "".join(parts)
    return None


class Response(object):
    """A parsed reply: ``ident``, ``rcode``, ``truncated`` and the answer
    section as ``(owner, type name, value)`` tuples (types this codec does not
    read are left out)."""

    def __init__(
        self,
        ident: int,
        rcode: int,
        truncated: bool,
        answers: "List[Tuple[str, str, Any]]",
    ):
        self.ident = ident
        self.rcode = rcode
        self.truncated = truncated
        self.answers = answers

    def records(self, name: str, rdtype: str) -> "List[Any]":
        """The ``rdtype`` values for ``name``, following any CNAME chain the
        answer carries (owner names compared case-blind)."""
        wanted = name.rstrip(".").lower()
        seen = set()
        rdtype = rdtype.lower()
        while wanted not in seen:
            seen.add(wanted)
            found = [
                v
                for owner, t, v in self.answers
                if owner.lower() == wanted and t == rdtype
            ]
            if found or rdtype == "cname":
                return found
            alias = [
                v
                for owner, t, v in self.answers
                if owner.lower() == wanted and t == "cname"
            ]
            if not alias:
                return []
            wanted = str(alias[0]).rstrip(".").lower()
        return []


def parse_response(data: bytes, ident: Optional[int] = None) -> Response:
    """Read a reply; ``ident``, when given, must match the query's."""
    if len(data) < 12:
        raise WireError("shorter than a DNS header")
    got, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
    if ident is not None and got != ident & 0xFFFF:
        raise WireError("reply id %d does not match query id %d" % (got, ident))
    if not flags & 0x8000:
        raise WireError("not a reply")
    pos = 12
    for _ in range(qdcount):
        pos = _read_name(data, pos)[1] + 4
    answers = []
    for _ in range(ancount):
        owner, pos = _read_name(data, pos)
        if pos + 10 > len(data):
            raise WireError("record header runs past the message")
        rtype, _cls, _ttl, length = struct.unpack("!HHIH", data[pos : pos + 10])
        pos += 10
        if pos + length > len(data):
            raise WireError("record data runs past the message")
        name = _NAMES.get(rtype)
        if name is not None:
            value = _rdata(data, rtype, pos, length)
            if value is not None:
                answers.append((owner, name, value))
        pos += length
    return Response(got, flags & 0x000F, bool(flags & 0x0200), answers)
