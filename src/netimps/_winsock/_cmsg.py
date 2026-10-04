"""Control-message sizes, and the walk and build of a control buffer."""

from __future__ import annotations

import ctypes as _ctypes
from typing import Any, Iterable, List, Tuple

from ._abi import _ALIGN, _CMSGHDR_SIZE, _WSACMSGHDR


def _align(n: int) -> int:
    return (n + _ALIGN - 1) & ~(_ALIGN - 1)


def CMSG_LEN(length: int) -> int:
    """Bytes a cmsg of ``length`` payload occupies, header included.

    The POSIX counterpart, for a caller sizing one ancillary item. Note the
    data offset is pointer-aligned on Windows, which is why this is not simply
    ``header + length``.
    """
    if length < 0:
        raise ValueError("length must not be negative")
    return _align(_CMSGHDR_SIZE) + length


def CMSG_SPACE(length: int) -> int:
    """Buffer space a cmsg of ``length`` payload needs, padding included.

    Use this, not :func:`CMSG_LEN`, to size a control buffer: the difference is
    the trailing pad that lets a *following* header start aligned, and
    omitting it is how a second cmsg gets silently truncated.
    """
    if length < 0:
        raise ValueError("length must not be negative")
    return _align(_CMSGHDR_SIZE) + _align(length)


def _parse_control(buffer: "Any", used: int) -> "List[Tuple[int, int, bytes]]":
    """Walk a control buffer into CPython's ``ancdata`` list.

    Each entry is ``(cmsg_level, cmsg_type, cmsg_data)``. A header claiming a
    length below its own size, or running past what the kernel said it wrote,
    stops the walk rather than being trusted -- a malformed buffer should yield
    fewer items, never an out-of-bounds read.
    """
    out: "List[Tuple[int, int, bytes]]" = []
    raw = bytes(buffer)
    # Never trust `used` past what was actually allocated. Winsock reports the
    # size it *wanted* in `Control.len`, not the size it wrote: a 1-byte control
    # buffer came back claiming 24, and walking that reads off the end of the
    # ctypes buffer. The caller clamps as well; this is the backstop, because an
    # out-of-bounds read is not an acceptable failure mode for a bad length.
    used = min(used, len(raw))
    offset = 0
    while offset + _CMSGHDR_SIZE <= used:
        header = _WSACMSGHDR.from_buffer_copy(raw, offset)
        length = header.cmsg_len
        if length < _CMSGHDR_SIZE or offset + length > used:
            break
        start = offset + _align(_CMSGHDR_SIZE)
        end = offset + length
        out.append((header.cmsg_level, header.cmsg_type, raw[start:end]))
        step = _align(length)
        if step <= 0:
            break
        offset += step
    return out


def _build_control(ancdata: "Iterable[Tuple[int, int, bytes]]") -> "Any":
    """Pack ``ancdata`` into a control buffer laid out as Winsock expects."""
    items = [(int(level), int(ctype), bytes(data)) for level, ctype, data in ancdata]
    if not items:
        return None
    total = sum(CMSG_SPACE(len(data)) for _, _, data in items)
    buffer = _ctypes.create_string_buffer(total)
    offset = 0
    for level, ctype, data in items:
        header = _WSACMSGHDR(
            cmsg_len=CMSG_LEN(len(data)),
            cmsg_level=level,
            cmsg_type=ctype,
        )
        _ctypes.memmove(
            _ctypes.byref(buffer, offset), _ctypes.byref(header), _CMSGHDR_SIZE
        )
        if data:
            _ctypes.memmove(
                _ctypes.byref(buffer, offset + _align(_CMSGHDR_SIZE)), data, len(data)
            )
        offset += CMSG_SPACE(len(data))
    return buffer
