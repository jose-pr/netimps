"""The ``sockaddr`` header and address overlays, in the layout the host's kernel uses."""

from __future__ import annotations

from ctypes import Structure
from ctypes import c_uint16
from ctypes import c_uint32
from ctypes import c_uint8
import sys as _sys
from typing import Any, List, Tuple

#: True on macOS and the BSDs, whose ``sockaddr`` carries a leading ``sa_len``
#: byte that Linux does not have. See ``_SockaddrHeader`` below -- this single
#: flag is the difference between reading the address family correctly and
#: silently skipping every address on those platforms.
_HAS_SA_LEN = _sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd"))


#: Annotated as ``Any``-valued because the two branches have different field
#: types, and ctypes' own ``_fields_`` signature is a union of several shapes.
_sockaddr_header_fields: "List[Tuple[str, Any]]"

if _HAS_SA_LEN:
    # macOS / BSD: 1-byte length, then 1-byte family.
    _sockaddr_header_fields = [("sa_len", c_uint8), ("sa_family", c_uint8)]
else:
    # Linux: 2-byte family, no length byte.
    _sockaddr_header_fields = [("sa_family", c_uint16)]


class _SockaddrHeader(Structure):
    """Just enough of ``struct sockaddr`` to read the family portably."""

    _fields_ = _sockaddr_header_fields


class _SockaddrIn(Structure):
    _fields_ = _sockaddr_header_fields + [
        ("sin_port", c_uint16),
        ("sin_addr", c_uint8 * 4),
    ]


class _SockaddrIn6(Structure):
    _fields_ = _sockaddr_header_fields + [
        ("sin6_port", c_uint16),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", c_uint8 * 16),
        ("sin6_scope_id", c_uint32),
    ]
