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
is what enables receipt there; asking only for the former silently disabled
IPv6 pktinfo on that platform until it was measured on CI.

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
``local_address`` means one thing everywhere. A v6-only socket (``IPV6_V6ONLY``)
refuses ``IP_PKTINFO`` on both macOS and Windows, which the same ignore covers.

Platform reality
----------------
``recvmsg``/``sendmsg`` do not exist in CPython on Windows, so this module goes
through :mod:`netimps._msg`, which supplies them from Winsock there and
delegates to CPython elsewhere. It calls that module **directly** rather than
the ``socket.socket`` methods ``_msg`` can patch in, so declining the patch
(``NETIMPS_SOCKET_PATCH=1``) does not cost this module anything.

Where a platform still cannot serve a request, this degrades to plain
``recvfrom``/``sendto`` and reports ``interface=None`` rather than failing --
the same policy :func:`netimps.get_pmtu` uses for the missing ``IP_MTU``. Check
:attr:`UDPEndpoint.has_pktinfo` (receiving) and
:attr:`UDPEndpoint.has_src_pinning` (sending) to know which mode you are
in -- both are decided once, at construction, from the socket's own family.

One asymmetry has no degrade available: **Windows sends a zero source address
literally**, where POSIX reads zero as "kernel chooses". Pinning by interface
index alone therefore raises :class:`ValueError` there instead of quietly
sending from ``0.0.0.0``.
"""

from __future__ import annotations

import functools as _functools
import socket as _socket
import struct as _struct
import sys as _sys
import time as _time
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    NamedTuple,
    Optional,
    Tuple,
    TypeVar,
    Union,
    cast,
)

from ._iface_spec import InterfaceLike
from ._ifaddrs import INTERFACE_CACHE_TTL, Interface
from ._ip import HostLike, IPAddress, IPv4Address, IPv6Address, _dst_argument
from ._msg import CMSG_SPACE as _cmsg_space
from ._msg import recvmsg as _recvmsg
from ._msg import sendmsg as _sendmsg
from ._msg import has_recvmsg as _supports_recvmsg
from ._multicast import is_multicast
from ._parse import parse, try_parse

__all__ = ["UDPEndpoint", "Datagram"]

#: Distinguishes "not cached" from "cached as None", since a negative result is a
#: real answer worth keeping.
_MISSING = object()

_IS_WINDOWS = _sys.platform == "win32"

_F = TypeVar("_F", bound=Callable[..., Any])


def _builtin_timeout(method: _F) -> _F:
    """Re-raise ``socket.timeout`` as the builtin ``TimeoutError``.

    From 3.10 they are one class and this changes nothing; on the 3.9 floor
    ``socket.timeout`` is only an ``OSError``, so a caller catching
    ``TimeoutError`` would otherwise miss it.
    """

    @_functools.wraps(method)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return method(*args, **kwargs)
        except _socket.timeout as exc:
            if isinstance(exc, TimeoutError):
                raise
            raise TimeoutError(*exc.args) from exc

    return cast(_F, wrapper)


#: Documented kernel ABI values, used when CPython does not export the name.
#:
#: **``socket.IP_PKTINFO`` only arrived in CPython 3.12.** On 3.9, 3.10 and 3.11
#: it is absent on *every* platform, so a bare ``getattr`` left IPv4 pktinfo --
#: the arrival-interface feature this module exists for -- silently off for half
#: the supported interpreter range, on Linux and macOS as well as Windows.
#: Measured on the CI matrix: 3.9/3.10/3.11 failed the pinning test while
#: 3.12/3.13/3.14 passed, with the platform held constant.
#:
#: These are stable parts of each kernel's ABI, not guesses -- every value here
#: was read back from a live socket by `.github/probe/capture.py` -- and the repo
#: rule for exactly this case is to use the literal and let ``OSError`` from
#: ``setsockopt`` be the real "unsupported" signal. There is no single literal
#: because the three platforms genuinely disagree.
#:
#: ``(IP_PKTINFO, IPV6_PKTINFO, IPV6_RECVPKTINFO)``; ``None`` where the platform
#: has no such option at all.
#: Declared before the branches so mypy does not type the tuple from whichever
#: platform it happens to be checking as the target.
_PKTINFO_FALLBACK: "Tuple[Optional[int], Optional[int], Optional[int]]"

if _IS_WINDOWS:
    # IPV6_PKTINFO is both the request and the carrier here; there is no
    # IPV6_RECVPKTINFO.
    _PKTINFO_FALLBACK = (19, 19, None)
elif _sys.platform.startswith("linux"):
    _PKTINFO_FALLBACK = (8, 50, 49)
elif _sys.platform == "darwin" or "bsd" in _sys.platform:
    # macOS really does have IP_PKTINFO (26), with Linux's exact 12-byte layout.
    # The widespread "BSD has no IP_PKTINFO, use IP_RECVDSTADDR + IP_RECVIF"
    # advice is out of date for Darwin, and was measured wrong on a runner.
    _PKTINFO_FALLBACK = (26, 46, 61)
else:  # pragma: no cover - an unmeasured platform gets no guesses
    _PKTINFO_FALLBACK = (None, None, None)

#: Probed per family, because a platform can have one and not the other.
_IP_PKTINFO = getattr(_socket, "IP_PKTINFO", None) or _PKTINFO_FALLBACK[0]
_IPV6_PKTINFO = getattr(_socket, "IPV6_PKTINFO", None) or _PKTINFO_FALLBACK[1]
_IPV6_RECVPKTINFO = getattr(_socket, "IPV6_RECVPKTINFO", None) or _PKTINFO_FALLBACK[2]

#: Windows reports 512, Linux 8, macOS 32 -- there is no portable literal, and
#: a missing constant means the flag can never be set, so 0 is the safe default.
_MSG_CTRUNC = getattr(_socket, "MSG_CTRUNC", 0)

#: ``MSG_TRUNC``: the *payload* did not fit. Values differ per platform -- 32 on
#: Linux, 16 on macOS, 256 on Windows -- so there is no portable literal to fall
#: back to, and a missing constant means the flag can never be set, which makes
#: 0 the only safe default. Separate from ``MSG_CTRUNC`` deliberately: the two
#: answer different questions and a caller acts differently on each.
_MSG_TRUNC = getattr(_socket, "MSG_TRUNC", 0)

#: ``struct in_pktinfo``, and it is **not one layout across platforms** -- the
#: field order differs, not merely the size, so a single string cannot serve
#: both. Native byte order; this never leaves the host.
#:
#: - POSIX ``in_pktinfo``: ``{ipi_ifindex; ipi_spec_dst; ipi_addr}``, 12 bytes.
#: - Windows ``IN_PKTINFO``: ``{ipi_addr; ipi_ifindex}``, 8 bytes, and there is
#:   no ``spec_dst`` at all.
#:
#: Measured 2026-10-02 on loopback: Linux delivered ``cmsg_type`` 8 with 12
#: bytes, Windows ``cmsg_type`` 19 with 8 bytes. Parsing one with the other's
#: layout does not raise -- it yields a *plausible wrong address* and index 0,
#: which is exactly the failure this table exists to prevent.
_PKTINFO_V4 = "=4sI" if _IS_WINDOWS else "=I4s4s"

#: Whether :data:`_PKTINFO_V4` puts the address before the index. Kept as its
#: own flag because the struct string alone cannot tell the unpacker which
#: field it is looking at.
_PKTINFO_V4_ADDR_FIRST = _IS_WINDOWS

#: ``struct in6_pktinfo``: the 16-byte address **first**, then the interface
#: index. The opposite field order from ``in_pktinfo``, which is why the two
#: cannot share one layout string.
_PKTINFO_V6 = "=16sI"

#: Cmsg types that carry pktinfo, per level. ``IPV6_RECVPKTINFO`` is matched
#: alongside ``IPV6_PKTINFO`` because the two are distinct constants on Linux
#: (49 and 50) and need not be everywhere; accepting both costs nothing and
#: survives a platform that gives them one value.
_V4_PKTINFO_TYPES = frozenset(t for t in (_IP_PKTINFO,) if t is not None)
_V6_PKTINFO_TYPES = frozenset(
    t for t in (_IPV6_PKTINFO, _IPV6_RECVPKTINFO) if t is not None
)

#: Ancillary-buffer sizing. Room for exactly one cmsg is the wrong answer: the
#: caller owns the raw socket and may have enabled ``SO_TIMESTAMP`` or
#: ``IPV6_RECVHOPLIMIT`` on it, and a one-cmsg buffer then drops whichever
#: arrives second. Measured on Linux with both ``SO_TIMESTAMP`` and
#: ``IP_PKTINFO`` enabled: a one-slot buffer kept the timestamp, discarded the
#: pktinfo and set ``MSG_CTRUNC``; a four-slot buffer delivered both. Four
#: 64-byte slots cost 320 bytes per receive, and ``MSG_CTRUNC`` is reported as
#: :attr:`Datagram.control_truncated` for the cases that still overflow.
_CMSG_SLOTS = 4
_CMSG_SLOT_BYTES = 64

#: What ``recvfrom``/``recvmsg`` report as the peer: ``(address, port)`` for
#: IPv4, ``(address, port, flowinfo, scope_id)`` for IPv6. Kept out of the
#: public surface -- like ``InterfaceLike`` it documents an established shape
#: rather than something a caller constructs.
SocketAddress = Union[Tuple[str, int], Tuple[str, int, int, int]]


def _pktinfo_options(family: int) -> "Tuple[int, Optional[int], Optional[int], str]":
    """``(level, receive option, send cmsg type, struct layout)`` for *family*.

    The receive option and the send cmsg type are the *same* constant for
    IPv4 and two *different* ones for IPv6 on POSIX (``IPV6_RECVPKTINFO``
    requests the data, ``IPV6_PKTINFO`` carries it), so they are returned
    separately rather than collapsed into one "the option" value.

    **Windows has no ``IPV6_RECVPKTINFO`` at all**: there ``IPV6_PKTINFO`` (19)
    is both the request and the carrier, and setting it is what enables receipt.
    Asking only for ``IPV6_RECVPKTINFO`` therefore found ``None`` and silently
    turned IPv6 pktinfo off on Windows -- measured on a CI runner, where
    ``UDPEndpoint(bind("::", 0)).has_pktinfo`` was ``False`` while a raw
    ``recvmsg`` on the same socket delivered the cmsg perfectly well. The
    round-trip test passed anyway, by taking its own `not has_pktinfo`
    early-exit branch, which is why the fallback below is explicit rather than
    left to a reader to infer.

    Either may be ``None`` where the platform exports neither; the caller
    turns that into a ``supports_*`` flag rather than an error.
    """
    if family == _socket.AF_INET6:
        receive = _IPV6_RECVPKTINFO if _IPV6_RECVPKTINFO is not None else _IPV6_PKTINFO
        return _socket.IPPROTO_IPV6, receive, _IPV6_PKTINFO, _PKTINFO_V6
    return _socket.IPPROTO_IP, _IP_PKTINFO, _IP_PKTINFO, _PKTINFO_V4


def _unpack_pktinfo(
    level: int, ctype: int, cdata: bytes
) -> "Optional[Tuple[int, Optional[IPAddress]]]":
    """Decode one ancillary message into ``(interface index, local address)``.

    Dispatches on ``cmsg_level`` rather than assuming the socket's family, so
    a dual-stack socket -- or one the caller has configured further -- is read
    correctly instead of being unpacked with the wrong layout.

    Returns ``None`` for anything that is not pktinfo, and for a pktinfo cmsg
    too short to be one: a truncated struct is treated as absent rather than
    guessed at, and the caller keeps scanning the remaining messages.
    """

    if level == _socket.IPPROTO_IP and ctype in _V4_PKTINFO_TYPES:
        size = _struct.calcsize(_PKTINFO_V4)
        if len(cdata) < size:
            return None
        fields = _struct.unpack(_PKTINFO_V4, cdata[:size])
        if _PKTINFO_V4_ADDR_FIRST:
            destination, index = fields
        else:
            index, _local_if, destination = fields
        return int(index), try_parse(destination)

    if level == _socket.IPPROTO_IPV6 and ctype in _V6_PKTINFO_TYPES:
        size = _struct.calcsize(_PKTINFO_V6)
        if len(cdata) < size:
            return None
        destination, index = _struct.unpack(_PKTINFO_V6, cdata[:size])
        return int(index), try_parse(destination)

    return None


class Datagram(NamedTuple):
    """One received datagram and where it came from.

    Attributes:
        data: the payload.
        sender: ``(address, port)`` of the peer, as ``recvfrom`` reports it --
            a four-tuple for an IPv6 socket.
        local_address: the address the datagram was sent *to*, or ``None``.
            For a broadcast this is the broadcast address, not the interface's
            own address -- use ``interface`` to identify the adapter. On a
            dual-stack IPv6 socket an IPv4 arrival reports the v4-mapped form
            (``::ffff:10.0.0.1``), matching what ``sender`` shows.
        interface_index: receiving interface index, or ``0`` when unknown.
        interface: the resolved :class:`Interface`, or ``None`` when
            unavailable (no pktinfo, or no matching adapter).
        control_truncated: the kernel had more ancillary data than the buffer
            held (``MSG_CTRUNC``). When this is ``True`` and the interface
            fields are empty, they are empty because something was dropped --
            not because the kernel had nothing to say.
        truncated: the **payload** did not fit ``bufsize`` and ``data`` is the
            leading part of a longer datagram (``MSG_TRUNC``). A different
            question from ``control_truncated``, and the one that silently
            corrupts a decode: a protocol parser handed a message cut
            mid-field reports a malformed packet rather than a short read.
            Measured on Linux with ``bufsize=576``: a 1102-octet datagram
            arrived with ``MSG_TRUNC`` set and the flag discarded, leaving the
            caller nothing to check. Reported, not raised -- deciding that a
            short datagram is fatal belongs to the protocol, not here.
    """

    data: bytes
    sender: "SocketAddress"
    local_address: "Optional[IPAddress]" = None
    interface_index: int = 0
    interface: "Optional[Interface]" = None
    control_truncated: bool = False
    truncated: bool = False

    @property
    def reply_address(self) -> "SocketAddress":
        """``sender``, in the family a :meth:`UDPEndpoint.reply_socket` will use.

        **Use this, not ``sender``, to answer a datagram.** On a dual-stack
        ``AF_INET6`` listener a v4 client's ``sender`` is the v6 4-tuple
        ``('::ffff:127.0.0.1', port, 0, 0)``, while ``reply_socket`` correctly
        hands back an ``AF_INET`` socket -- and so the documented
        ``reply.sendto(answer, packet.sender)`` raised ``TypeError: AF_INET
        address must be a pair (host, port)``. Every caller had to unmap the
        sender itself to match a family the library had chosen for them, which
        is work the library should do::

            with endpoint.reply_socket(packet) as reply:
                reply.sendto(answer, packet.reply_address)

        A v4-mapped sender becomes the plain ``(host, port)`` pair; everything
        else is returned unchanged, so this is the right thing to pass on a
        single-family listener too.
        """
        from ._ip import unmap

        sender = self.sender
        if not isinstance(sender, tuple) or len(sender) < 2:
            return sender
        host = sender[0]
        if not isinstance(host, str):
            return sender
        parsed = try_parse(host.split("%")[0], IPAddress)
        if parsed is None or parsed.version != 6:
            return sender
        plain = unmap(parsed)
        if plain.version != 4:
            return sender
        # Drop flowinfo and scope id along with the mapping: they are v6
        # sockaddr fields and an AF_INET sendto rejects a 4-tuple outright.
        return (str(plain), sender[1])


class UDPEndpoint:
    """A UDP socket that can report which interface each datagram arrived on.

    ::

        endpoint = UDPEndpoint(netimps.bind("", 67, broadcast=True))
        while True:
            packet = endpoint.recv(2048)
            if packet.interface is not None:
                reply_on(packet.interface, packet.data)

    Wraps rather than subclasses ``socket.socket``: the raw socket stays
    reachable as :attr:`socket` for anything this does not cover.

    :param sock: an already-bound UDP socket -- build it with
        :func:`netimps.bind`. Its ``family`` decides which pktinfo option is
        used; an ``AF_INET6`` socket gets the v6 one, including when it is
        dual-stack.
    :param pktinfo: request arrival-interface data. ``True`` (the default)
        enables it where supported and is a no-op elsewhere. This governs
        *receiving* only -- :meth:`send`'s ``src`` needs no socket option.

    Two flags report what this socket can actually do, so a caller never has
    to infer it from an empty result:

    :ivar has_pktinfo: ``recv`` will report the arrival interface. This
        is ``False`` -- not an optimistic ``True`` -- whenever the option for
        *this socket's family* is missing or refused.
    :ivar has_src_pinning: :meth:`send` can honour ``src``. ``False``
        where the platform exports no pktinfo cmsg for this family; ``src`` is
        then ignored, and the kernel picks the source as it always would.
    """

    __slots__ = (
        "socket",
        "has_pktinfo",
        "has_src_pinning",
        "_cmsg_size",
        "_iface_cache",
        "_iface_cache_at",
        "_notifier",
    )

    def __init__(self, sock: "_socket.socket", pktinfo: bool = True) -> None:
        self.socket = sock
        self.has_pktinfo = False
        self.has_src_pinning = False
        self._cmsg_size = 0
        self._iface_cache: "Dict[int, Optional[Interface]]" = {}
        self._iface_cache_at = 0.0
        #: Created on the first `arecv`, so a synchronous consumer never pays
        #: for it -- on Windows it owns a thread.
        self._notifier: "Any" = None

        family = getattr(sock, "family", _socket.AF_INET)
        level, receive_option, send_type, _layout = _pktinfo_options(family)

        # Sending needs no socket option, only ``sendmsg`` and a cmsg type for
        # the family -- so it is decided independently of ``pktinfo=``, which
        # is about what arrives.
        self.has_src_pinning = send_type is not None and _supports_recvmsg()

        if not pktinfo or receive_option is None or not _supports_recvmsg():
            return
        try:
            sock.setsockopt(level, receive_option, 1)
        except OSError:
            return  # option exists but this socket/family refuses it

        if family == _socket.AF_INET6 and _IP_PKTINFO is not None:
            # Dual-stack, and the three platforms disagree about who reports a
            # v4 arrival on an AF_INET6 socket. Measured on CI runners:
            #   Linux   -- accepts IP_PKTINFO here and sends BOTH cmsgs; the v6
            #              one already carries the v4-mapped address.
            #   macOS   -- REFUSES it (EINVAL), and the v6 cmsg carries the
            #              v4-mapped address anyway.
            #   Windows -- accepts it, and it is the ONLY way a v4 arrival is
            #              visible: the v6 option delivers no cmsg at all for
            #              one, so without this the arrival address is lost.
            # Hence try-and-ignore rather than a platform test: the two that do
            # not need it either tolerate it or refuse it harmlessly, and a
            # v6-only socket refuses it on both macOS and Windows.
            try:
                sock.setsockopt(_socket.IPPROTO_IP, _IP_PKTINFO, 1)
            except OSError:
                pass

        self.has_pktinfo = True
        self._cmsg_size = _cmsg_space(_CMSG_SLOT_BYTES) * _CMSG_SLOTS

    #: How long a cached index -> Interface mapping is trusted. Short, because
    #: an adapter can be renamed or re-addressed under a live server and the
    #: index alone would not reveal it; long enough that a packet burst costs one
    #: enumeration rather than one per datagram.
    #:
    #: Deliberately **the same constant** as the process-wide enumeration cache
    #: rather than a second number, so two caches of the same fact cannot
    #: disagree about how stale is too stale. One second bounds the cost at a
    #: single enumeration per second whatever the arrival rate; a longer window
    #: only widens the time a renamed adapter goes unnoticed.
    _IFACE_CACHE_TTL = INTERFACE_CACHE_TTL

    def _interface_for(self, index: int) -> "Optional[Interface]":
        """Resolve an arrival index to an :class:`Interface`, with a cache.

        ``recv`` used to call :func:`get_interfaces` and scan it on **every**
        datagram. Measured on Windows loopback with 300-octet packets:
        **1.07 ms per packet** against 0.015 ms with ``resolve_interface=False``,
        a 70x cost on the default path, and worse on a host with more adapters --
        a consuming project measured 35-42 ms per enumeration. The sender
        controls the packet rate in a server loop, so that cost is on the hot
        path by definition, and the class docstring's own example uses the
        default and reads ``.interface``: the documented usage was the slow one.

        Cached per endpoint, keyed by index, and refreshed on a **miss** as well
        as on a TTL. A miss is the interesting signal: an index this endpoint has
        not seen means the adapter set changed, so re-enumerating then is both
        cheap and exactly when it is needed. A negative result is cached too --
        an index with no matching adapter is a real answer, and re-enumerating
        for it on every packet is how a wrong one becomes expensive.
        """
        cached = self._iface_cache.get(index, _MISSING)
        fresh = (_time.monotonic() - self._iface_cache_at) < self._IFACE_CACHE_TTL
        if cached is not _MISSING and fresh:
            return cached  # type: ignore[return-value]

        from ._ifaddrs import get_interfaces

        self._iface_cache = {i.index: i for i in get_interfaces() if i.index}
        self._iface_cache_at = _time.monotonic()
        found = self._iface_cache.get(index)
        if found is None:
            # Pin the negative so a stale or vanished index does not re-enumerate
            # on every subsequent packet.
            self._iface_cache[index] = None
        return found

    @_builtin_timeout
    def recv(self, bufsize: int = 65535, resolve_interface: bool = True) -> Datagram:
        """Receive one datagram.

        :param resolve_interface: look the arrival index up in
            :func:`netimps.get_interfaces` to populate ``.interface``. Pass
            ``False`` in a hot loop and use ``.interface_index`` directly --
            enumeration is not free.

        When pktinfo is unavailable this still works; the interface fields are
        simply empty. When it *is* available -- :attr:`has_pktinfo` --
        the interface fields are filled for both address families, and
        ``.control_truncated`` says whether anything was dropped for want of
        buffer space.

        A timeout set on the socket raises the builtin :class:`TimeoutError`
        on every supported Python.
        """
        if not self.has_pktinfo:
            # No interface information here, but `recvmsg` still reports
            # `MSG_TRUNC`, and `recvfrom` cannot -- so the degraded path goes
            # through it anyway, with a zero-length control buffer. Losing
            # pktinfo is a documented degrade; losing the only signal that the
            # payload was cut short is silent data corruption, and the two do
            # not have to be given up together.
            if _supports_recvmsg():
                data, _anc, flags, raw = _recvmsg(self.socket, bufsize, 0)
                return Datagram(
                    data=data,
                    sender=cast("SocketAddress", raw),
                    truncated=bool(flags & _MSG_TRUNC),
                )
            data, sender = self.socket.recvfrom(bufsize)
            return Datagram(data=data, sender=sender)

        # Routed through `_msg`, not `self.socket.recvmsg`, so this works on
        # Windows whether or not the stdlib patch is installed -- a caller who
        # sets NETIMPS_SOCKET_PATCH must not thereby lose pktinfo here.
        data, ancdata, flags, raw_sender = _recvmsg(
            self.socket, bufsize, self._cmsg_size
        )
        # `_msg.recvmsg` types the address as optional because it decodes only
        # AF_INET/AF_INET6 sockaddrs and answers None for anything else. This
        # endpoint is one of those two by construction -- `_pktinfo_options`
        # already dispatched on the family -- so the narrowing is sound here and
        # would not be in the general case.
        sender = cast("SocketAddress", raw_sender)

        index = 0
        local: "Optional[IPAddress]" = None
        for level, ctype, cdata in ancdata:
            decoded = _unpack_pktinfo(level, ctype, cdata)
            if decoded is None:
                continue
            index, local = decoded
            break

        if self.socket.family == _socket.AF_INET6 and isinstance(local, IPv4Address):
            # A v4 arrival on a dual-stack socket. Windows reports it at level
            # IPPROTO_IP carrying the **plain** v4 address, while Linux and macOS
            # report the v4-mapped form in the v6 cmsg -- measured on CI, and the
            # two halves of the same Windows datagram even disagree, since its
            # `sender` is already ::ffff:127.0.0.1. `local_address` is documented
            # as v4-mapped on an AF_INET6 endpoint, so normalise rather than let
            # the platform show through.
            local = IPv6Address("::ffff:%s" % (local,))

        interface = None
        if resolve_interface and index:
            interface = self._interface_for(int(index))

        return Datagram(
            data=data,
            sender=sender,
            local_address=local,
            interface_index=int(index),
            interface=interface,
            control_truncated=bool(flags & _MSG_CTRUNC),
            truncated=bool(flags & _MSG_TRUNC),
        )

    def _pktinfo_control(
        self, src: "InterfaceLike"
    ) -> "Optional[Tuple[int, int, bytes]]":
        """Build the ``(level, type, data)`` cmsg that pins *src*, or ``None``.

        ``None`` means the platform cannot pin at all (no ``sendmsg``), which
        is the documented degrade. A *spec* that names nothing local raises
        :class:`ValueError` instead of being dropped: the caller asked for a
        specific adapter, and sending from another one is the silent wrong
        answer this exists to prevent.

        Both halves of the struct are filled where they resolve. Index alone
        is "this adapter, kernel picks the address"; address alone is "this
        address, kernel picks the adapter" -- and the outgoing struct is the
        only place the interface can be named, which the previous
        hardcoded-zero index never did.
        """
        if not self.has_src_pinning:
            return None

        from ._iface_spec import interface_address, interface_index

        family = self.socket.family
        level, _receive_option, send_type, _layout = _pktinfo_options(family)
        if send_type is None:  # pragma: no cover - guarded by the flag above
            return None
        want_ipv6 = family == _socket.AF_INET6

        # Both lookups are tolerant: a spec may name an adapter with no
        # address of the wanted family (index only), or an address no local
        # adapter claims (address only). Only resolving to *neither* is an
        # error. Passing an Interface answers both without enumerating.
        local = interface_address(src, want_ipv6=want_ipv6, strict=False)
        index = interface_index(src, strict=False) or 0
        if local is None and not index:
            raise ValueError(
                "cannot resolve src %r to a local address or interface index" % (src,)
            )

        if want_ipv6:
            if isinstance(local, IPv4Address):
                # A dual-stack socket sends IPv4 as v4-mapped, and so must the
                # source it is pinned to. Measured on Linux: pinning
                # ::ffff:127.0.0.1 delivers, and the receiver sees 127.0.0.1.
                local = IPv6Address("::ffff:%s" % (local,))
            packed = local.packed if local is not None else b"\x00" * 16
            return level, send_type, _struct.pack(_PKTINFO_V6, packed, index)

        if isinstance(local, IPv6Address):
            raise ValueError(
                "cannot pin an IPv6 source (%s) on an AF_INET socket -- "
                "build the endpoint on an AF_INET6 socket instead" % (local,)
            )
        if local is None and _IS_WINDOWS:
            # Windows sends a zero source address **literally**: measured, a pin
            # of 0.0.0.0 arrives from 0.0.0.0 rather than letting the kernel
            # choose, which is what Linux does with the same bytes. An
            # index-only pin therefore cannot be expressed this way here, and
            # silently sending from 0.0.0.0 would be far worse than refusing.
            raise ValueError(
                "cannot pin by interface index alone on Windows (index %d): the "
                "platform sends a zero source address literally rather than "
                "choosing one. Pass an address-bearing src instead." % (index,)
            )
        packed = local.packed if local is not None else b"\x00" * 4
        if _PKTINFO_V4_ADDR_FIRST:
            # Windows IN_PKTINFO has no spec_dst, and ipi_addr *is* the field
            # the send path reads -- the opposite of POSIX below.
            return level, send_type, _struct.pack(_PKTINFO_V4, packed, index)
        # ipi_addr is the *destination* on receipt and ignored on send; only
        # ipi_spec_dst selects the source address. Measured: zeroing it
        # changes nothing, and filling it with the source was misleading.
        return level, send_type, _struct.pack(_PKTINFO_V4, index, packed, b"\x00" * 4)

    @_builtin_timeout
    def send(
        self,
        data: bytes,
        address: "HostLike",
        port: int,
        src: "InterfaceLike" = None,
    ) -> int:
        """Send a datagram, optionally forcing the *src* interface.

        ``src`` accepts the usual union (an :class:`Interface`, a MAC, an
        adapter name or an address). Where the platform has ``sendmsg`` this
        pins the outgoing interface *and* source address via the family's
        pktinfo cmsg -- which matters when replying to a broadcast on a
        multi-homed host, since the routing table would otherwise pick for
        you.

        The cmsg follows the socket's family: ``in6_pktinfo`` for
        ``AF_INET6`` (a v4 source is converted to its v4-mapped form),
        ``in_pktinfo`` for ``AF_INET``. Sending an IPv6 cmsg on an ``AF_INET``
        socket is *accepted and ignored* by Linux, so an IPv6 ``src`` there
        raises :class:`ValueError` rather than reporting a success that did
        not happen.

        **Windows is supported**, via ``WSASendMsg``; this used to say the
        opposite, and did so for a while after it stopped being true. The one
        gap there is pinning by interface *index alone*, which raises
        :class:`ValueError` rather than degrading, because Windows sends a zero
        source address literally where POSIX reads it as "kernel chooses".

        Where a platform genuinely cannot pin -- no pktinfo cmsg for the family
        -- the datagram goes out unpinned and the spec is not resolved. That is
        the module's usual degrade, and :attr:`has_src_pinning` is ``False``
        there, so a caller who cares can check once rather than inferring it
        from a silent success.

        Raises :class:`ValueError` for a ``src`` that names no local address
        or interface, and lets an :class:`OSError` from the kernel through --
        a source address this host cannot send from is a real failure, not an
        unsupported platform.

        Resolving a MAC, adapter name or bare address enumerates interfaces;
        pass an :class:`Interface` in a send loop to avoid that.

        A timeout set on the socket raises the builtin :class:`TimeoutError`
        on every supported Python.
        """
        target = (_dst_argument(address), int(port))

        if src is None:
            return self.socket.sendto(data, target)

        control = self._pktinfo_control(src)
        if control is None:
            return self.socket.sendto(data, target)

        # Through `_msg`, same reasoning as `recv` above.
        return int(_sendmsg(self.socket, [data], [control], 0, target))

    def _reply_family(self, datagram: "Datagram") -> int:
        """The address family a reply to *datagram* must actually use.

        The **sender's** family, not the listener's. A dual-stack ``AF_INET6``
        listener sees a v4 client as ``::ffff:a.b.c.d``; a reply socket in the
        listener's family cannot reach it, because the socket comes up with
        ``IPV6_V6ONLY=1`` on Windows and ``sendto`` to a mapped address is then
        refused outright (``WinError 10049``). Deciding from the sender means
        the answer is the same with or without pktinfo, which is the point --
        the no-pktinfo path was the one that silently never replied.

        Falls back to the socket's own family when the sender cannot be parsed,
        which is the old behaviour and the only thing left to guess with.
        """
        from ._ip import unmap

        sender = datagram.sender
        host = sender[0] if isinstance(sender, tuple) and sender else None
        if isinstance(host, str):
            parsed = try_parse(host.split("%")[0], IPAddress)
            if parsed is not None:
                return (
                    _socket.AF_INET if unmap(parsed).version == 4 else _socket.AF_INET6
                )
        return self.socket.family

    @staticmethod
    def _is_repliable(local: "IPAddress", interface: "Optional[Interface]") -> bool:
        """Whether *local* is an address a reply socket may actually bind to.

        Classified rather than discovered by a failed bind, because **the
        platforms disagree about which addresses are bindable**. Measured: Linux
        binds ``255.255.255.255`` and ``239.1.2.3`` without complaint while
        Windows refuses both. So "try it and fall back on OSError" silently
        produces a socket bound to the broadcast address on Linux -- and a reply
        sent *from* ``255.255.255.255`` is one most clients discard, which is
        exactly the failure this method exists to prevent.

        Excluded: the unspecified address (nothing to answer from), multicast,
        and broadcast -- both the limited form and the **subnet** form, which
        needs the arrival interface's prefixes and is what
        :func:`netimps.is_broadcast` is for. Passing ``interface`` keeps that
        check off the enumerating path.
        """
        from ._ifaddrs import is_broadcast

        if local.is_unspecified or local.is_multicast:
            return False
        if is_multicast(local):
            return False
        return not is_broadcast(local, interface, cache=True)

    def reply_socket(
        self,
        datagram: "Datagram",
        port: "Union[int, Iterable[int]]" = 0,
        connreset: bool = False,
    ) -> "_socket.socket":
        """A new socket bound so replies leave from the address the client used.

        The point of pktinfo, in one call. A wildcard-bound server that answers
        from a fresh socket sends from whichever address the routing table
        prefers, which is not necessarily the one the client addressed -- and a
        client that checks (DHCP and TFTP both do) drops the reply::

            packet = endpoint.recv()
            with endpoint.reply_socket(packet) as reply:
                reply.sendto(answer, packet.reply_address)

        Falls back deliberately rather than failing: the returned socket is bound
        to the first of these that works -- the arrival address, then this
        endpoint's own bound address, then the wildcard. A socket that answers
        from the wrong address still answers.

        **A taken port is not an unusable address, and the two failures move in
        different directions.** An address that cannot be bound at all (a
        broadcast or multicast destination, a link-local one whose scope is
        wrong) advances to the next *address*; a port that is merely held
        advances to the next *port* on the same address. Conflating them is a
        silent correctness bug, and it was this method's: every ``OSError``
        advanced the address, so an explicit ``port=`` already taken on the
        arrival address fell through to the endpoint's own address and then the
        wildcard **with the same port** -- and where that later bind succeeded,
        the reply left from an address the client never addressed, which is the
        one failure this method exists to prevent. So when the ports run out on
        an address, this raises :class:`netimps.AddressInUseError` rather than
        answering from somewhere else.

        Three things make this worth a method, each found by measurement rather
        than reasoning:

        - **A v4 arrival on a dual-stack listener is ``::ffff:a.b.c.d``**, and
          binding that needs an ``AF_INET6`` socket with ``IPV6_V6ONLY`` off --
          which Windows does not default to. So a mapped address is unmapped and
          answered from a plain ``AF_INET`` socket instead.
        - **A broadcast, multicast or unspecified destination must not be
          answered from.** These are *classified* and skipped, not discovered by
          a failed bind, because the platforms disagree about which are bindable:
          measured, Linux binds ``255.255.255.255`` and ``239.1.2.3`` happily
          while Windows refuses both. Relying on the refusal would mean replying
          *from* the broadcast address on Linux, which most clients discard. The
          subnet-broadcast case needs the arrival interface's prefixes, which is
          what :func:`netimps.is_broadcast` supplies.
        - **An IPv6 link-local destination needs a scope id**, taken from
          ``datagram.interface_index``, or the bind fails with "invalid
          argument".

        ``connreset=False`` by default, unlike :func:`netimps.bind`: a reply
        socket is a server's, and a server loop should not die because an earlier
        answer drew an ICMP port-unreachable from a client that had gone away.
        The non-hijackable bind options apply as everywhere else.

        :param datagram: a :class:`Datagram` from :meth:`recv`. Its
            ``local_address`` is what this binds to; with ``None`` -- no pktinfo
            -- it goes straight to the fallbacks.
        :param port: local port for the reply socket; ``0`` lets the OS choose,
            which is what a per-transaction socket wants. Also accepts **any
            iterable of ports**, tried in the order given, for a server that
            pins transfer ports to a range a firewall can allow (``tftp-hpa
            -R``, ``dnsmasq --tftp-port-range``). The iterable is materialised
            once and reused for each address candidate, so a generator is safe
            -- but it must be finite. Empty raises :class:`ValueError`.
        :param connreset: passed to :func:`netimps.bind`; see above for why the
            default is inverted here.
        :raises AddressInUseError: every port was held on an otherwise bindable
            address. Deliberately *not* a fallback to a different address.
        """
        from ._ip import unmap

        # **The sender's real family decides the reply socket's**, not the
        # listener's. A dual-stack `AF_INET6` listener sees a v4 client as
        # `::ffff:a.b.c.d`, and a reply socket in the listener's family cannot
        # reach it: measured on Windows 11 ARM64, the `AF_INET6` socket comes up
        # with `IPV6_V6ONLY=1` (the platform default, which `bind()` does not
        # clear) and `sendto` to a mapped address fails with `WinError 10049`,
        # "address not valid in its context". The transfer then silently never
        # starts. That happened whenever there was no `local_address` to go on
        # -- `pktinfo=False`, or a platform that reported none -- because both
        # fallbacks used the listener's family.
        family = self._reply_family(datagram)
        candidates: "list" = []

        local = datagram.local_address
        if local is not None and self._is_repliable(local, datagram.interface):
            plain = unmap(local)
            if isinstance(plain, IPv4Address):
                # Answer v4 from a v4 socket. The mapped form would need an
                # AF_INET6 socket with V6ONLY cleared, which is not the default
                # on Windows and is a worse thing to require than a second
                # socket family.
                candidates.append((_socket.AF_INET, str(plain)))
            elif isinstance(plain, IPv6Address):
                text = str(plain)
                if plain.is_link_local and datagram.interface_index:
                    # The zone goes *in the address string*, which is what the
                    # kernel wants. Without a scope id a link-local bind is
                    # refused: the same address can exist on several interfaces
                    # and it will not guess which. `%zone` is how a
                    # sockaddr_in6 scope is spelled for `bind`.
                    text = "%s%%%d" % (text, int(datagram.interface_index))
                candidates.append((_socket.AF_INET6, text))

        # Fallback 1: whatever this endpoint itself is bound to -- right for a
        # listener pinned to one address, and a no-op for a wildcard one. It is
        # only usable when it is in the *reply's* family: a v6 wildcard listener
        # answering a v4 client would otherwise offer `::` to an `AF_INET`
        # socket, so such a mismatch is skipped and the v4 wildcard below is
        # used instead.
        try:
            own = self.socket.getsockname()
            if own and own[0]:
                plain_own = unmap(parse(str(own[0]).split("%")[0], IPAddress))
                wanted = 6 if family == _socket.AF_INET6 else 4
                if plain_own.version == wanted:
                    candidates.append((family, str(plain_own)))
        except (OSError, ValueError):  # pragma: no cover - a closed socket
            pass

        # Fallback 2: the wildcard, which always binds.
        candidates.append((family, ""))

        from ._sockets import bind as _bind
        from ._exceptions import AddressInUseError

        if isinstance(port, int):
            ports: "tuple" = (port,)
        else:
            # Materialised once: the same ports are retried for each address
            # candidate, and a generator would be empty by the second.
            ports = tuple(port)
            if not ports:
                raise ValueError("port must not be an empty iterable")

        last: "Optional[BaseException]" = None
        exhausted: "Optional[AddressInUseError]" = None
        for candidate_family, address in candidates:
            for one in ports:
                try:
                    return _bind(
                        address,
                        one,
                        family=candidate_family,
                        kind=_socket.SOCK_DGRAM,
                        connreset=connreset,
                    )
                except AddressInUseError as exc:
                    # The address is fine and the port is held: the next port on
                    # *this* address is the only move that preserves the reply's
                    # source address. Moving to the next address would answer
                    # from one the client never used.
                    last = exhausted = exc
                    continue
                except (OSError, ValueError) as exc:
                    # A broadcast, multicast or otherwise unbindable destination
                    # lands here, which is why the list is tried rather than
                    # vetted. The address is the problem, so no other port on it
                    # will do better.
                    last = exc
                    break
            else:
                # Every port held on an address that is otherwise bindable. Do
                # not fall back to an address the client did not address.
                raise exhausted  # type: ignore[misc]

        # Every candidate failed, including the wildcard, so something is wrong
        # with the socket rather than with the address.
        raise OSError(
            "could not bind a reply socket for %r" % (datagram.local_address,)
        ) from last

    async def arecv(
        self, bufsize: int = 65535, resolve_interface: bool = True
    ) -> "Datagram":
        """:meth:`recv`, awaited. Same arguments, same :class:`Datagram`.

        Works on **every** asyncio loop, including the Windows default
        ``ProactorEventLoop``, which has no ``add_reader`` and whose
        ``recvfrom`` would discard the ancillary data this class exists for::

            async def serve(endpoint):
                while True:
                    packet = await endpoint.arecv()
                    with endpoint.reply_socket(packet) as reply:
                        reply.sendto(answer(packet), packet.reply_address)

        The read itself happens **on the loop**, not in a helper thread, so
        ``bufsize`` stays a per-call argument and
        :attr:`Datagram.truncated` keeps meaning what it means. Only the
        *readability notification* is platform-specific -- ``add_reader`` where the
        loop has it, a thread where it does not. See
        :class:`netimps._aio.ReadNotifier`.

        One waiter at a time: this is a receive loop's method, and two coroutines
        awaiting the same endpoint would race for the same datagram regardless of
        how the waiting were arranged.

        :raises RuntimeError: if the endpoint has been closed.
        """
        notifier = self._ensure_notifier()
        while True:
            await notifier.wait()
            try:
                return self.recv(bufsize, resolve_interface)
            except BlockingIOError:
                # A spurious wakeup, or another reader took it. Wait again rather
                # than returning an empty datagram.
                continue

    async def datagrams(
        self, bufsize: int = 65535, resolve_interface: bool = True
    ) -> "Any":
        """Yield datagrams until the endpoint is closed -- ``async for`` sugar.

        ::

            async for packet in endpoint.datagrams():
                ...

        Stops cleanly on :meth:`close`; any other error propagates, because a
        receive loop that swallows them is how a dead server looks healthy.
        """
        while True:
            try:
                yield await self.arecv(bufsize, resolve_interface)
            except (RuntimeError, OSError, ValueError):
                if self._closed_for_async():
                    return
                raise

    def _ensure_notifier(self) -> "Any":
        """The endpoint's readability notifier, created on first await.

        Lazy on purpose: ``asyncio`` is not imported at package import time -- see
        the note in :mod:`netimps._aio` -- and a purely synchronous consumer
        should not pay for a thread it never uses.
        """
        if self._notifier is None:
            if self.socket.fileno() < 0:
                raise RuntimeError("endpoint is closed")
            from ._aio import ReadNotifier

            # Non-blocking, so a spurious readability signal cannot wedge the
            # loop inside `recv`.
            self.socket.setblocking(False)
            self._notifier = ReadNotifier(self.socket)
        return self._notifier

    def _closed_for_async(self) -> bool:
        try:
            return self.socket.fileno() < 0
        except Exception:  # pragma: no cover - a socket in an odd state
            return True

    def close(self) -> None:
        """Close the wrapped socket, and stop the async notifier if one was started.

        The notifier goes first: its thread selects on this socket, and closing
        the socket underneath it would turn an orderly shutdown into a caught
        ``OSError``.
        """
        notifier, self._notifier = self._notifier, None
        if notifier is not None:
            notifier.close()
        self.socket.close()

    def __enter__(self) -> "UDPEndpoint":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        try:
            bound = self.socket.getsockname()
        except OSError:  # unbound, or closed
            bound = None
        return "UDPEndpoint(bound=%r, pktinfo=%r, src_pinning=%r)" % (
            bound,
            self.has_pktinfo,
            self.has_src_pinning,
        )


_PKTINFO_SUPPORT: "Dict[int, bool]" = {}


def has_pktinfo(family: int = _socket.AF_INET) -> bool:
    """Whether a UDP socket of *family* can report each datagram's arrival
    interface on this host.

    The question a server asks **before** deciding how to bind: with packet
    info, one wildcard socket serves every address and still knows which one a
    datagram reached; without it the wildcard has to be expanded into a socket
    per address, which on Linux then receives no broadcasts at all.

    ::

        if has_pktinfo():
            socks = [bind("", 67)]
        else:
            socks = [bind(str(a), 67) for a in addresses]

    **Decided by asking a socket, not by testing a name**, which is the only
    reliable way: ``getattr(socket, "IP_PKTINFO", None)`` is ``None`` on CPython
    3.9-3.11 on *every* platform -- the constant arrived in 3.12 -- while the
    kernel supported it throughout. A name test therefore reports "no" on a
    platform that works, which silently pushes a server onto the per-address
    path it did not need. :class:`UDPEndpoint` already used the documented
    per-platform values rather than the constants for exactly this reason, and
    this asks it the same way the endpoint does, on a throwaway socket.

    The answer is **cached per family** for the life of the process, since it is
    a property of the platform and the interpreter rather than of any socket.

    Returns ``False`` rather than raising if a socket of that family cannot even
    be created -- a v6 answer on a host with IPv6 disabled is "no", not an
    error.
    """
    cached = _PKTINFO_SUPPORT.get(family)
    if cached is not None:
        return cached

    try:
        probe = _socket.socket(family, _socket.SOCK_DGRAM)
    except OSError:
        # No socket of this family at all, so nothing to report an arrival on.
        _PKTINFO_SUPPORT[family] = False
        return False
    try:
        answer = bool(UDPEndpoint(probe).has_pktinfo)
    finally:
        probe.close()
    _PKTINFO_SUPPORT[family] = answer
    return answer
