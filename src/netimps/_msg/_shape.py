"""Re-laying the IPv4 pktinfo payload between the Windows and POSIX field orders."""

from __future__ import annotations

import socket as _socket
import struct as _struct
from typing import Iterable, List, Tuple

from .._pktinfo import _PKTINFO_V4_POSIX as _POSIX_PKTINFO_V4
from .._pktinfo import _PKTINFO_V4_WINDOWS as _WIN_PKTINFO_V4
from ._dispatch import _IS_WINDOWS

#: ``IP_PKTINFO`` as this platform spells it. 19 on Windows, 8 on Linux, 26 on
#: macOS -- so a caller comparing against ``socket.IP_PKTINFO`` matches the
#: local number, which is why the *type* is left alone while the payload is
#: reshaped.
_LOCAL_IP_PKTINFO = getattr(_socket, "IP_PKTINFO", 19 if _IS_WINDOWS else None)

#: Whether the patched methods must reshape anything. Only Windows differs; the
#: v6 ``in6_pktinfo`` layout (``{addr; ifindex}``, 20 bytes) is identical on all
#: three, so v6 is never touched.
_NEEDS_POSIX_SHAPE = _IS_WINDOWS


def _to_posix_shape(
    ancdata: "List[Tuple[int, int, bytes]]",
) -> "List[Tuple[int, int, bytes]]":
    """Re-lay a Windows ``IP_PKTINFO`` payload into the POSIX field order.

    Used **only** by the patched :meth:`socket.socket.recvmsg`, never by
    :func:`recvmsg`. That split is the point: a caller who asked for
    ``netimps.recvmsg`` gets the platform's own bytes, while a caller reaching
    ``sock.recvmsg`` is reaching for a method that exists on POSIX and should
    therefore get what POSIX would have put there. Installing the name without
    the layout is a half-impersonation, and the half that is missing is the one
    that makes POSIX-shaped parsing code wrong.

    ``ipi_spec_dst`` is filled with **zero**, because Windows does not report
    it and inventing it would be worse than leaving it empty:

    - Zero is also what **macOS** puts there -- measured on a CI runner,
      ``01000000 00000000 7f000001`` for a unicast to ``127.0.0.1``. So this
      makes Windows behave like the platform that already answers this way,
      rather than like a fourth thing.
    - Copying ``ipi_addr`` into it would be a *plausible wrong address* in the
      case that matters most. Measured on Linux: for a broadcast the two fields
      genuinely differ -- ``ipi_spec_dst`` is the local interface address
      (``172.18.120.118``) while ``ipi_addr`` is ``255.255.255.255``. Code that
      reads ``spec_dst`` reads it precisely to get the local address, so handing
      it the broadcast address would silently corrupt exactly the field it
      wanted. Zero is visibly wrong; ``255.255.255.255`` is not.

    So a caller reading ``ipi_addr`` (field 3) gets the right answer, and one
    reading ``ipi_spec_dst`` (field 2) gets ``0.0.0.0`` -- the same answer it
    already gets on macOS today. Neither silently misreads a different address,
    and neither raises ``struct.error`` on an 8-byte buffer any more.
    """
    if not _NEEDS_POSIX_SHAPE or _LOCAL_IP_PKTINFO is None:
        return ancdata
    out: "List[Tuple[int, int, bytes]]" = []
    for level, ctype, cdata in ancdata:
        if (
            level == _socket.IPPROTO_IP
            and ctype == _LOCAL_IP_PKTINFO
            and len(cdata) == _struct.calcsize(_WIN_PKTINFO_V4)
        ):
            address, index = _struct.unpack(_WIN_PKTINFO_V4, cdata)
            cdata = _struct.pack(_POSIX_PKTINFO_V4, index, b"\x00" * 4, address)
        out.append((level, ctype, cdata))
    return out


def _from_posix_shape(
    ancdata: "Iterable[Tuple[int, int, bytes]]",
) -> "List[Tuple[int, int, bytes]]":
    """Accept either layout on send, chosen by length.

    The mirror of :func:`_to_posix_shape`, so POSIX-shaped code that builds a
    12-byte ``in_pktinfo`` to pin a source is understood as well as code that
    builds the native 8-byte one. Unambiguous, because the two sizes differ and
    neither is a valid length for the other.

    ``ipi_spec_dst`` is the field POSIX uses to select the source address, so it
    wins when set; ``ipi_addr`` is the fallback. That is the opposite of the
    receive direction, and it is what POSIX itself does -- on receive
    ``ipi_addr`` is the destination that arrived, on send it is ignored.
    """
    items = [(int(level), int(ctype), bytes(data)) for level, ctype, data in ancdata]
    if not _NEEDS_POSIX_SHAPE or _LOCAL_IP_PKTINFO is None:
        return items
    out: "List[Tuple[int, int, bytes]]" = []
    posix_size = _struct.calcsize(_POSIX_PKTINFO_V4)
    for level, ctype, cdata in items:
        if (
            level == _socket.IPPROTO_IP
            and ctype == _LOCAL_IP_PKTINFO
            and len(cdata) == posix_size
        ):
            index, spec_dst, address = _struct.unpack(_POSIX_PKTINFO_V4, cdata)
            source = spec_dst if spec_dst != b"\x00" * 4 else address
            cdata = _struct.pack(_WIN_PKTINFO_V4, source, index)
        out.append((level, ctype, cdata))
    return out
