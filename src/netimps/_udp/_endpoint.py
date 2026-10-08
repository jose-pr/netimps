"""The UDP endpoint: receive with the arrival interface, and the async variants (internal)."""

from __future__ import annotations

import socket as _socket
import time as _time
from typing import Any, AsyncIterator, Callable, Dict, Iterable, Optional, cast

from .._ifaddrs import INTERFACE_CACHE_TTL, Interface, InterfaceLike
from .._ifaddrs import _interface_snapshot
from .._ip import HostLike, IPAddress, IPv4Address, IPv6Address
from .._msg import CMSG_SPACE as _cmsg_space
from .._msg import has_recvmsg as _supports_recvmsg
from .._msg import recvmsg as _recvmsg
from .._pktinfo import _IP_PKTINFO, _pktinfo_options, _unpack_pktinfo
from . import _freebsd
from ._admit import _AdmitMixin
from ._datagram import Datagram, SocketAddress
from ._reply import _ReplyMixin
from ._send import _SendMixin
from ._timeout import _builtin_timeout

#: Distinguishes "not cached" from "cached as None", since a negative result is a
#: real answer worth keeping.
_MISSING = object()


#: Windows reports 512, Linux 8, macOS 32 -- there is no portable literal, and
#: a missing constant means the flag can never be set, so 0 is the safe default.
_MSG_CTRUNC = getattr(_socket, "MSG_CTRUNC", 0)

#: ``MSG_TRUNC``: the *payload* did not fit. Values differ per platform -- 32 on
#: Linux, 16 on macOS, 256 on Windows -- so there is no portable literal to fall
#: back to, and a missing constant means the flag can never be set, which makes
#: 0 the only safe default. Separate from ``MSG_CTRUNC`` deliberately: the two
#: answer different questions and a caller acts differently on each.
_MSG_TRUNC = getattr(_socket, "MSG_TRUNC", 0)


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


class UDPEndpoint(_SendMixin, _ReplyMixin, _AdmitMixin):
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
    :param interfaces: the interfaces this endpoint serves, each an
        :class:`Interface` with an index; empty (the default) serves all.
        :meth:`admits` tests a datagram against them; receiving never filters.

    Two flags report what this socket can actually do, so a caller never has
    to infer it from an empty result:

    :ivar has_pktinfo: ``recv`` will report the arrival interface. This
        is ``False`` -- not an optimistic ``True`` -- whenever the option for
        *this socket's family* is missing or refused.
    :ivar has_src_pinning: :meth:`send` can honour ``src``. ``False``
        where the platform exports no pktinfo cmsg for this family, and for an
        IPv4 endpoint on FreeBSD that is bound to an address (the kernel pins
        only on a wildcard-bound socket); ``src`` is then ignored, and the
        kernel picks the source as it always would.
    """

    __slots__ = (
        "socket",
        "interfaces",
        "has_pktinfo",
        "has_src_pinning",
        "_cmsg_size",
        "_iface_cache",
        "_iface_cache_at",
        "_notifier",
        "_closed",
    )

    def __init__(
        self,
        sock: "_socket.socket",
        *,
        pktinfo: bool = True,
        interfaces: "Iterable[Interface]" = (),
    ) -> None:
        self.interfaces = self._served(interfaces)
        self.socket = sock
        self.has_pktinfo = False
        self.has_src_pinning = False
        self._cmsg_size = 0
        self._iface_cache: "Dict[int, Optional[Interface]]" = {}
        self._iface_cache_at = 0.0
        #: Created on the first `arecv`, so a synchronous caller never pays
        #: for it -- on Windows it owns a thread.
        self._notifier: "Any" = None
        self._closed = False

        family = getattr(sock, "family", _socket.AF_INET)
        level, receive_option, send_type, _layout = _pktinfo_options(family)

        if _freebsd.IS_FREEBSD and family == _socket.AF_INET:
            # FreeBSD carries IPv4 arrival data and the source pin in other
            # options; see `_freebsd`. The pin needs a wildcard-bound socket.
            self.has_src_pinning = _supports_recvmsg() and _freebsd.can_pin(sock)
            if pktinfo and _supports_recvmsg() and _freebsd.enable_receive(sock):
                self.has_pktinfo = True
                self._cmsg_size = _cmsg_space(_CMSG_SLOT_BYTES) * _CMSG_SLOTS
            return

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
    #: the mapping is built from, so the two cannot disagree about how stale is
    #: too stale.
    _IFACE_CACHE_TTL = INTERFACE_CACHE_TTL

    def _interface_for(self, index: int) -> "Optional[Interface]":
        """Resolve an arrival index to an :class:`Interface`, with a cache.

        Calling :func:`get_interfaces` and scanning it on **every** datagram
        costs, measured on Windows loopback with 300-octet packets, **1.07 ms
        per packet** against 0.015 ms with ``resolve_interface=False`` -- a 70x
        cost on the default path, and 35-42 ms per enumeration on a host with
        many adapters. The sender controls the packet rate in a server loop, so
        that cost is on the hot path by definition.

        The index map is per endpoint; the enumeration behind it is the
        process-wide one (:func:`netimps.get_interfaces` with ``cache=``), so
        any number of endpoints and the caller's own cached lookups cost one
        enumeration per TTL between them. The map is as old as the enumeration
        it was built from, so it is never trusted for longer than that TTL.

        Refreshed on a **miss** as well as on the TTL: an index a fresh map
        lacks means the adapter set changed since the shared enumeration, so
        that one case enumerates anew. A negative result is cached too -- an
        index with no adapter is a real answer, and must not cost every packet.
        """
        cached = self._iface_cache.get(index, _MISSING)
        fresh = (_time.monotonic() - self._iface_cache_at) < self._IFACE_CACHE_TTL
        if cached is not _MISSING and fresh:
            return cached  # type: ignore[return-value]

        ttl = 0.0 if fresh else self._IFACE_CACHE_TTL
        self._iface_cache_at, interfaces = _interface_snapshot(False, ttl)
        self._iface_cache = {i.index: i for i in interfaces if i.index}
        found = self._iface_cache.get(index)
        if found is None:
            # Pin the negative so a stale or vanished index does not re-enumerate
            # on every subsequent packet.
            self._iface_cache[index] = None
        return found

    @_builtin_timeout
    def recv(self, bufsize: int = 65535, *, resolve_interface: bool = True) -> Datagram:
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
        # sets NETIMPS_SOCKET_PATCH=0 must not thereby lose pktinfo here.
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
            if decoded is not None:
                index, local = decoded
                break
            if _freebsd.IS_FREEBSD:
                # Two messages, one per fact, so neither ends the scan.
                arrival = _freebsd.decode_arrival(level, ctype, cdata)
                if arrival is not None:
                    index = arrival[0] or index
                    local = arrival[1] or local

        if self.socket.family == _socket.AF_INET6 and isinstance(local, IPv4Address):
            # A v4 arrival on a dual-stack socket. Windows reports it at level
            # IPPROTO_IP carrying the **plain** v4 address, while Linux and macOS
            # report the v4-mapped form in the v6 cmsg -- measured on CI, and the
            # two halves of the same Windows datagram even disagree, since its
            # `sender` is already ::ffff:127.0.0.1. `destination` is documented
            # as v4-mapped on an AF_INET6 endpoint, so normalise rather than let
            # the platform show through.
            local = IPv6Address("::ffff:%s" % (local,))

        interface = None
        if resolve_interface and index:
            interface = self._interface_for(int(index))

        return Datagram(
            data=data,
            sender=sender,
            destination=local,
            interface_index=int(index),
            interface=interface,
            control_truncated=bool(flags & _MSG_CTRUNC),
            truncated=bool(flags & _MSG_TRUNC),
        )

    async def arecv(
        self, bufsize: int = 65535, *, resolve_interface: bool = True
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
        :class:`netimps._udp._notifier.ReadNotifier`.

        One waiter at a time: this is a receive loop's method, and two coroutines
        awaiting the same endpoint would race for the same datagram regardless of
        how the waiting were arranged.

        The socket's timeout is left as it is: the read is made non-blocking
        only for the duration of one call, so a synchronous :meth:`recv` on the
        same endpoint is unaffected.

        :raises RuntimeError: if the endpoint is closed, or is closed while this
            is waiting.
        """
        notifier = self._ensure_notifier()
        while True:
            await notifier.wait()
            try:
                return self._recv_nowait(bufsize, resolve_interface)
            except BlockingIOError:
                # A spurious wakeup, or another reader took it. Wait again rather
                # than returning an empty datagram.
                continue

    def _recv_nowait(self, bufsize: int, resolve_interface: bool) -> "Datagram":
        """:meth:`recv` that raises ``BlockingIOError`` instead of waiting.

        The mode is changed for this call only and restored on the way out, so
        the socket's timeout is the caller's again whatever the outcome.
        """
        sock = self.socket
        previous = sock.gettimeout()
        sock.settimeout(0.0)
        try:
            return self.recv(bufsize, resolve_interface=resolve_interface)
        finally:
            try:
                sock.settimeout(previous)
            except OSError:  # closed while receiving: nothing left to restore
                pass

    async def asend(
        self,
        data: bytes,
        dst: "HostLike",
        port: int,
        *,
        src: "InterfaceLike" = None,
    ) -> int:
        """:meth:`send`, awaited. Same arguments, same return value.

        The datagram is handed to the kernel without blocking; when the send
        buffer is full this waits (without blocking the loop) until the socket
        is writable and tries again. The socket's timeout is left as it was
        found, as for :meth:`arecv`.

        :raises RuntimeError: if the endpoint is closed.
        """
        sock = self.socket
        while True:
            if self._closed or sock.fileno() < 0:
                raise RuntimeError("endpoint is closed")
            previous = sock.gettimeout()
            sock.settimeout(0.0)
            try:
                return self.send(data, dst, port, src=src)
            except BlockingIOError:
                pass
            finally:
                try:
                    sock.settimeout(previous)
                except OSError:  # closed while sending
                    pass
            from ._notifier import wait_writable

            await wait_writable(sock)

    async def datagrams(
        self,
        bufsize: int = 65535,
        *,
        resolve_interface: bool = True,
        on_error: "Optional[Callable[[BaseException], bool]]" = None,
    ) -> "AsyncIterator[Datagram]":
        """Yield datagrams until the endpoint is closed -- ``async for`` sugar.

        ::

            async for packet in endpoint.datagrams():
                ...

        Stops cleanly on :meth:`close`. By default any other error propagates and
        ends the loop, because a receive loop that swallows them is how a dead
        server looks healthy.

        :param on_error: called with the exception when a receive fails. Return
            true to carry on with the next datagram, false (or raise) to stop
            with that error. The caller decides, so log or count there; nothing
            is dropped silently. Not called for the error a close causes.
        """
        while True:
            try:
                yield await self.arecv(bufsize, resolve_interface=resolve_interface)
            except (RuntimeError, OSError, ValueError) as exc:
                if self._closed_for_async():
                    return
                if on_error is not None and on_error(exc):
                    continue
                raise

    def _ensure_notifier(self) -> "Any":
        """The endpoint's readability notifier, created on first await.

        Lazy on purpose: ``asyncio`` is not imported at package import time -- see
        the note in :mod:`netimps._udp._notifier` -- and a purely synchronous caller
        should not pay for a thread it never uses.
        """
        if self._notifier is None:
            if self._closed or self.socket.fileno() < 0:
                raise RuntimeError("endpoint is closed")
            from ._notifier import ReadNotifier

            self._notifier = ReadNotifier(self.socket)
        return self._notifier

    def _closed_for_async(self) -> bool:
        if self._closed:
            return True
        try:
            return self.socket.fileno() < 0
        except Exception:  # pragma: no cover - a socket in an odd state
            return True

    def close(self) -> None:
        """Close the wrapped socket, and stop the async notifier if one was started.

        The notifier goes first: its thread selects on this socket, and closing
        the socket underneath it would turn an orderly shutdown into a caught
        ``OSError``. Complete on return, and harmless when called again. From a
        coroutine use :meth:`aclose`, which does not block the loop.

        A task awaiting :meth:`arecv` is woken with :class:`RuntimeError`, and
        :meth:`datagrams` finishes.
        """
        self._closed = True
        notifier, self._notifier = self._notifier, None
        if notifier is not None:
            notifier.close()
        self.socket.close()

    async def aclose(self) -> None:
        """:meth:`close`, awaited: the loop keeps running while the notifier's
        thread leaves.

        Complete on return -- the thread is gone and the socket is closed --
        and harmless when called again, or after :meth:`close`. Use it from a
        coroutine; :meth:`close` would block the loop for as long as the thread
        takes to stop.
        """
        self._closed = True
        notifier, self._notifier = self._notifier, None
        if notifier is not None:
            await notifier.aclose()
        self.socket.close()

    def __enter__(self) -> "UDPEndpoint":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    async def __aenter__(self) -> "UDPEndpoint":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
