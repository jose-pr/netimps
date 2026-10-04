"""``recvmsg`` / ``sendmsg`` on Windows, via ``WSARecvMsg`` and ``WSASendMsg``.

CPython ships neither method on Windows, on any version -- it is not a missing
constant but a missing feature, so ``getattr(socket, ...)`` probing cannot
rescue it. Winsock does provide both, one as a documented export and one only
through a runtime-queried extension pointer, and this module binds them with
``ctypes`` so that :mod:`netimps._msg` can present a single cross-platform
call.

**This module is Windows-only and must not be imported elsewhere.** Importing
it on POSIX raises, because :class:`ctypes.WinDLL` does not exist there. Reach
it through :mod:`netimps._msg`, which imports it lazily inside its own
platform branch; that indirection is the whole reason the split exists.

Shapes match CPython's exactly -- ``recvmsg`` returns
``(data, ancdata, msg_flags, address)`` and ``sendmsg`` takes
``(buffers, ancdata, flags, address)`` -- so a caller cannot tell ours from the
native one apart from the platform it is running on. That is deliberate: the
alternative is every caller growing its own ``if win32`` fork.

Things measured on real sockets rather than assumed, each of which contradicts
what a reader would reasonably guess from the POSIX equivalents:

- ``WSARecvMsg`` has **no export**. It is fetched per socket with
  ``WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`` and the ``WSAID_WSARECVMSG``
  GUID. ``WSASendMsg`` *is* a plain ``ws2_32`` export.
- ``WSACMSGHDR`` is ``{SIZE_T len; INT level; INT type}``, and **both** the
  offset to a cmsg's data and the step to the next header are aligned to
  ``sizeof(void*)`` -- not to 4, and not to the header size.
- ``IN_PKTINFO`` is ``{IN_ADDR; ULONG}``: the address comes **first** and there
  is no ``spec_dst``, so it is 8 bytes against Linux's 12. ``IN6_PKTINFO``
  agrees with Linux at ``{IN6_ADDR; ULONG}``. Layouts stay native here; the
  translation table lives in :mod:`netimps._udp`.
- An empty read on a non-blocking socket surfaces as :class:`BlockingIOError`,
  because ``ctypes.WinError`` maps ``WSAEWOULDBLOCK`` through ``errno``.
- A socket with a timeout is non-blocking underneath, so both calls wait for
  readiness themselves and raise ``socket.timeout`` when it runs out, as the
  stdlib methods do. Without that wait a 0.3 s timeout failed in 0.000 s.

``DWORD``/``ULONG`` are spelled ``c_uint32`` rather than taken from
:mod:`ctypes.wintypes` on purpose. ``import ctypes.wintypes`` fails outright on
POSIX, which would make even a guarded import of this module a hazard, and
``c_ulong`` is 32-bit on Windows but 64-bit on 64-bit Linux -- an exact width
removes both questions from the struct layouts.
"""

from __future__ import annotations

from ._abi import available
from ._calls import recvmsg, sendmsg
from ._cmsg import CMSG_LEN, CMSG_SPACE
from ._ioctl import SIO_UDP_CONNRESET, set_udp_connreset

__all__ = [
    "recvmsg",
    "sendmsg",
    "CMSG_LEN",
    "CMSG_SPACE",
    "available",
    "set_udp_connreset",
    "SIO_UDP_CONNRESET",
]
