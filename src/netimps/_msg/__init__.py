"""Cross-platform ``recvmsg`` / ``sendmsg``, and the optional stdlib patch.

Two layers, and the first does not depend on the second:

1. **Functions that always work** -- :func:`recvmsg`, :func:`sendmsg`,
   :func:`CMSG_LEN`, :func:`CMSG_SPACE`. Call them on any platform. On POSIX
   they delegate to CPython's own methods; on Windows they go through
   :mod:`netimps._winsock` and ``WSARecvMsg``/``WSASendMsg``. This is the
   supported surface, and it is complete without anything being patched.
2. **An optional patch** -- :func:`patch_socket_module` installs the same
   behaviour onto :class:`socket.socket` and the :mod:`socket` module, so that
   ordinary ``sock.recvmsg(...)`` code written for POSIX runs unchanged on
   Windows. netimps installs it on import; see the opt-out below.

Both families are supported throughout. ``AF_INET6`` senders come back as the
4-tuple ``(host, port, flowinfo, scope_id)`` that ``recvfrom`` returns, and a
v6 destination may be given as a 2-, 3- or 4-tuple with an optional ``%zone``
suffix -- the same latitude ``sendto`` allows.

**Why the patch also installs ``CMSG_LEN``/``CMSG_SPACE``.** Windows has
neither. The standard POSIX idiom is to feature-detect, then size a control
buffer, then receive::

    if hasattr(sock, "recvmsg"):
        data, anc, flags, addr = sock.recvmsg(1500, socket.CMSG_SPACE(64))

Patching only ``recvmsg`` would let that detection succeed and then fail on the
*next* line, turning "this platform cannot do it" into "this library is
broken". The patch is all four names or none.

**Byte layouts.** The cmsg payloads genuinely differ by platform -- Windows'
``IN_PKTINFO`` is ``{addr; ifindex}`` at 8 bytes, Linux's is ``{ifindex;
spec_dst; addr}`` at 12, and ``IP_PKTINFO`` is 19 on Windows against 8 on Linux.
:func:`recvmsg` and :func:`sendmsg` pass the platform's own bytes through. The
patched ``sock.recvmsg`` is for POSIX-shaped code, so it re-lays the IPv4
``IP_PKTINFO`` payload into the 12-byte POSIX layout (``ipi_spec_dst`` is zero,
as on macOS), and the patched ``sock.sendmsg`` accepts either layout. Every
other payload is left as the platform produced it, since POSIX-shaped parsing
code reading a *plausible wrong address* is worse than failing honestly. Socket
constants are not portable on any other platform pair either.
:mod:`netimps._pktinfo` owns the per-platform layout table; consult it rather than
assuming.

**Opting out.** Set ``NETIMPS_SOCKET_PATCH=0`` in the environment before the
first ``import netimps``, or call ``patch_socket_module(False)`` afterwards to
undo it. The environment variable exists because the decision has to be
expressible *before* import, which a function call cannot be. The patch only
ever **adds** names it finds missing: it never replaces a method the platform
already provides, so if CPython ever ships ``recvmsg`` on Windows this stands
down by itself.
"""

from __future__ import annotations

from ._dispatch import CMSG_LEN, CMSG_SPACE, has_recvmsg, recvmsg, sendmsg

__all__ = ["recvmsg", "sendmsg", "CMSG_LEN", "CMSG_SPACE", "has_recvmsg"]
