"""UDP receive with arrival-interface information (internal).

A server bound to the wildcard address cannot tell which interface a datagram
arrived on -- ``recvfrom`` reports the *sender*, not the local adapter. For
broadcast protocols (DHCP being the canonical case) that is exactly the thing
you need, because the reply depends on which network the request came from.

The answer is the ``PKTINFO`` family of socket options: the kernel attaches the
receiving interface index and local address as ancillary data, read back with
``recvmsg``.

Re-exported from :mod:`netimps`.

One option per address family
-----------------------------
``IP_PKTINFO`` is the **IPv4** option and is not a spelling of the v6 one.
Setting it on an ``AF_INET6`` socket *succeeds* on Linux -- so a guard that
only watches for ``OSError`` sees nothing wrong -- and then no cmsg ever
arrives, because an IPv6 datagram carries ``IPV6_PKTINFO`` instead. The family
therefore selects the option, the cmsg type **and** the struct layout, and all
three differ:

- ``AF_INET``: set ``IP_PKTINFO``, match ``IP_PKTINFO``, unpack
  ``struct in_pktinfo`` -- **whose layout is not the same everywhere**; see
  below.
- ``AF_INET6``: set ``IPV6_RECVPKTINFO`` (Linux 49, macOS 61) or, where that
  does not exist, ``IPV6_PKTINFO`` itself; match ``IPV6_PKTINFO`` (Linux 50,
  macOS 46, Windows 19); unpack ``=16sI`` (``struct in6_pktinfo``: the 16-byte
  **address first**, then the index). This layout the three platforms agree on.

Note the v6 asymmetry -- the option you *set* is not the cmsg type you
*match* -- and the reversed field order. Neither is a detail you can guess.
**Windows has no ``IPV6_RECVPKTINFO`` at all**, and setting ``IPV6_PKTINFO``
is what enables receipt there; asking only for the former silently disables
IPv6 pktinfo on that platform.

The v4 struct, which is three different things
----------------------------------------------
Measured on CI runners, one datagram to ``127.0.0.1`` on each:

=========  ====  =====  ==========================================
platform   type  bytes  layout
=========  ====  =====  ==========================================
Linux         8     12  ``{ifindex; spec_dst; addr}`` -- ``=I4s4s``
macOS        26     12  ``{ifindex; spec_dst; addr}`` -- same as Linux
Windows      19      8  ``{addr; ifindex}`` -- ``=4sI``, no ``spec_dst``
=========  ====  =====  ==========================================

So macOS **does** have ``IP_PKTINFO`` (26) and needs no ``IP_RECVDSTADDR``/
``IP_RECVIF`` fallback, contrary to the usual "BSD has no IP_PKTINFO" advice.
Windows is the odd one, and reversing its two fields does not raise -- it
yields a plausible wrong address and index ``0``, which is why the layout is a
table rather than a literal.

Dual stack
----------
A v4 arrival on an ``AF_INET6`` socket is reported differently again:

- **Linux** accepts ``IP_PKTINFO`` here and sends *both* cmsgs; the v6 one
  already carries the v4-mapped address, so it needs nothing extra.
- **macOS** refuses ``IP_PKTINFO`` on an ``AF_INET6`` socket (``EINVAL``) and
  reports the v4-mapped address in the v6 cmsg anyway.
- **Windows** accepts it, and it is the *only* way the arrival is visible: the
  v6 option delivers no cmsg for a v4 arrival. It then carries the **plain**
  v4 address, while the same datagram's ``sender`` is already
  ``::ffff:127.0.0.1`` -- the two halves disagree.

Hence the option is set with the error ignored, and a plain v4 address decoded
on an ``AF_INET6`` socket is normalised to ``::ffff:`` form, so
``destination`` means one thing everywhere. A v6-only socket (``IPV6_V6ONLY``)
refuses ``IP_PKTINFO`` on both macOS and Windows, which the same ignore covers.

Platform reality
----------------
``recvmsg``/``sendmsg`` do not exist in CPython on Windows, so this module goes
through :mod:`netimps._msg`, which supplies them from Winsock there and
delegates to CPython elsewhere. It calls that module **directly** rather than
the ``socket.socket`` methods ``_msg`` can patch in, so declining the patch
(``NETIMPS_SOCKET_PATCH=0``) does not cost this module anything.

Where a platform still cannot serve a request, this degrades to plain
``recvfrom``/``sendto`` and reports ``interface=None`` rather than failing --
the same policy :func:`netimps.get_pmtu` uses for the missing ``IP_MTU``. Check
:attr:`UDPEndpoint.has_pktinfo` (receiving) and
:attr:`UDPEndpoint.has_src_pinning` (sending) to know which mode you are
in -- both are decided once, at construction, from the socket's own family.

One asymmetry has no degrade available: **Windows sends a zero source address
literally**, where POSIX reads zero as "kernel chooses". Pinning by interface
index alone, or by ``0.0.0.0`` or ``::``, therefore raises :class:`ValueError`
there instead of quietly sending from the zero address. On a dual-stack
endpoint an IPv4 source goes as an ``IPPROTO_IP`` message there.

IPv4 on FreeBSD has no ``IP_PKTINFO``; :mod:`netimps._udp._freebsd` carries it with
``IP_RECVDSTADDR``, ``IP_RECVIF`` and ``IP_SENDSRCADDR``.
"""

from __future__ import annotations

from ._datagram import Datagram, SocketAddress
from ._endpoint import UDPEndpoint
from ._support import has_pktinfo

__all__ = ["UDPEndpoint", "Datagram"]
