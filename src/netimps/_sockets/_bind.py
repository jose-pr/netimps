"""``bind``: one call from a host and port to a listening socket, and the free-port probe."""

from __future__ import annotations

import ipaddress as _ipaddress
import socket as _socket
from typing import Any, Iterable, NamedTuple, Optional, Tuple, Union
from .._ifaddrs import (
    InterfaceLike,
    interface_address as _interface_address,
    interface_index as _interface_index,
)
from .._ip import HostLike, _dst_argument, _family_argument
from ._device import _DeviceOption, _apply_device, _device_name, _device_option
from ._hint import _with_hint
from ._options import disable_connreset


class SocketOption(NamedTuple):
    """One ``setsockopt`` triple, for :func:`bind`'s ``options=``.

    ``bind`` accepts bare ``(level, name, value)`` tuples as well -- this only
    gives the triple a name, so a caller building a list of them reads as
    something other than ``Iterable[Tuple[int, int, Any]]``::

        bind("", 67, options=[SocketOption(SOL_SOCKET, SO_RCVBUF, 1 << 20)])

    A :class:`typing.NamedTuple`, so it *is* a tuple: plain tuples are
    accepted and these unpack like any other.
    """

    level: int
    name: int
    value: Any


def bind(
    address: "HostLike" = "",
    port: int = 0,
    *,
    family: "Optional[int]" = None,
    kind: int = _socket.SOCK_DGRAM,
    reuse_address: bool = True,
    allow_address_takeover: bool = False,
    reuse_port: bool = False,
    broadcast: bool = False,
    connreset: "Optional[bool]" = None,
    interface: "InterfaceLike" = None,
    device: "InterfaceLike" = None,
    cache: "Union[bool, float]" = False,
    options: "Iterable[Tuple[int, int, Any]]" = (),
    listen: "Optional[int]" = None,
) -> "_socket.socket":
    """Create, configure and bind a socket in one call.

    The setup every server repeats, with the options that are easy to get
    wrong handled once::

        sock = bind("", 67, broadcast=True)               # DHCP-style listener
        sock = bind("127.0.0.1", 0, kind=SOCK_STREAM, listen=5)
        sock = bind(port=5353, interface="eth0")          # pin to one adapter

    :param address: local address to bind. ``""`` (the default) is the
        wildcard, which is what a server almost always wants.

        Accepts the same loose union as the rest of the package, not just a
        ``str``: an :class:`IPv4Address`/:class:`IPv6Address`, an
        :class:`IPv4Interface`/:class:`IPv6Interface` (its ``.ip`` is used, since
        the ``/prefix`` means nothing to ``bind``), a :class:`netimps.Host` or a
        :class:`netimps.FQDN`: the value every other entry point in the package
        takes, and not the raw ``TypeError`` the socket layer raises for it
        ("str, bytes or bytearray expected, not IPv4Address"). A *network*
        raises :class:`TypeError`, because it has no single
        address and guessing one (the network address? the first host?) would be
        worse than refusing.
    :param port: local port; ``0`` lets the OS choose.
    :param family: ``4`` or ``AF_INET``, ``6`` or ``AF_INET6``; anything else
        raises :class:`ValueError`. ``None`` (the default) takes the
        family from what was given: an IPv6 literal, or an *interface* whose
        address is IPv6, gives ``AF_INET6``; an IPv4 literal gives ``AF_INET``;
        a name gives ``AF_INET`` when it has an IPv4 address and ``AF_INET6``
        when it has only IPv6. The wildcard ``""`` is IPv4: a wildcard says
        nothing about the family, and an IPv6 wildcard (``"::"``) must be asked
        for. A family that contradicts the address fails in the socket layer,
        as it always has.
    :param interface: bind to this adapter's address instead of ``address``.
        Accepts an :class:`Interface`, a MAC, an adapter name or an address --
        the same union as ``ping(src=)``. Raises :class:`ValueError` if it
        cannot be resolved, rather than silently binding the wildcard.
    :param device: restrict the socket to this one device, so it receives only
        what arrives on it. Takes the same union as ``interface``. **The address
        stays what ``address`` says**: with no address the wildcard is bound
        (IPv4 unless ``family`` says otherwise), which is what a broadcast
        listener on one adapter of a multi-homed host wants, and a socket bound
        to an adapter's *address* hears no broadcast on Linux. With an address
        too, the kernel applies both: the socket receives what is addressed to
        that address *and* arrived on the device. ``device`` and ``interface``
        together raise :class:`ValueError`, since ``interface`` already stands
        for an address on an adapter. A device naming no local interface raises
        :class:`ValueError` and a platform with no device binding raises
        :class:`DeviceBindingUnsupportedError`, both before a socket is
        opened; :func:`has_device_binding` says which platforms can. Measured
        on Linux only: see the platform notes in the header.
    :param reuse_address: ask for the conventional "restart without waiting
        out ``TIME_WAIT``" behaviour. **What that takes differs by platform**,
        so the flag is not a single socket option: POSIX gets
        ``SO_REUSEADDR``, Windows gets ``SO_EXCLUSIVEADDRUSE``. See below.
    :param allow_address_takeover: set ``SO_REUSEADDR`` on Windows too, where
        it means something else entirely. Default ``False``; on POSIX it adds
        nothing, since ``reuse_address`` already sets exactly that option.
    :param reuse_port: share the port with other sockets that ask the same.
        POSIX sets ``SO_REUSEPORT``. **Windows has no such option**: for a
        datagram socket the flag takes the address-sharing path
        (``SO_REUSEADDR``, as ``allow_address_takeover=True`` does), so two
        sockets that both pass it bind one port; there, sharing also lets
        another process take the port over. A stream socket on Windows is
        unchanged and stays exclusive.
    :param connreset: Windows only, and only for UDP. ``False`` turns
        ``SIO_UDP_CONNRESET`` off, so that an ICMP port-unreachable provoked by
        an earlier send stops being reported as
        :class:`ConnectionResetError` on a *later*, unrelated receive; ``True``
        leaves the platform default (reporting on). ``None`` (the default) is
        ``False`` for a datagram socket and leaves any other socket alone. A
        no-op everywhere but Windows. See :func:`disable_connreset`.
    :param cache: reuse a recent enumeration of the adapters when
        ``interface`` or ``device`` has to be resolved, as
        :func:`get_interfaces` does: ``True`` for
        :data:`INTERFACE_CACHE_TTL` seconds or a number for that TTL. ``False``
        (the default) enumerates on each call. Ignored when neither is given.
    :param options: extra ``(level, name, value)`` triples -- or
        :class:`SocketOption` values -- for anything not covered by the named
        arguments.
    :param listen: call ``listen(backlog)`` after binding. Ignored for
        datagram sockets, where it is meaningless.

    .. warning::
       **``SO_REUSEADDR`` is not the same option on Windows.** On POSIX it
       only permits binding an address still in ``TIME_WAIT`` -- and
       **only for a stream socket**. ``TIME_WAIT`` is a TCP concept, so on a
       UDP socket the option's one remaining effect on Linux is to permit
       duplicate bindings of *live* sockets, which is traffic theft rather
       than a restart convenience. So this does not set it for
       ``SOCK_DGRAM``; use ``reuse_port=True`` or
       ``allow_address_takeover=True`` to share a UDP port deliberately. On
       Windows it lets **any process** bind an ``addr:port`` another socket is
       already listening on, and the later binder can win subsequent
       connections -- reproduced on
       Windows 11, where a plain second bind was refused with ``EACCES`` while
       one through this function succeeded. So ``reuse_address=True`` sets
       ``SO_EXCLUSIVEADDRUSE`` there instead, which is the safe request with
       the same intent, and the literal option is available only by asking for
       it by its consequence: ``allow_address_takeover=True``.

    Raises :class:`OSError` if the bind fails, with the text of
    :func:`bind_error_hint` in its message when that function recognises the
    failure: ``str(exc)`` is already something a user can act on. An address
    that is taken is always :class:`AddressInUseError`; any other failure keeps
    its own :class:`OSError` subclass and ``errno``. The socket is closed before
    the exception propagates, so a failed call leaks nothing.
    """
    family = _family_argument(family)
    device_name: "Optional[str]" = None
    device_option: "Optional[_DeviceOption]" = None
    if device is not None:
        if interface is not None:
            raise ValueError(
                "device= and interface= both name an adapter: pass one (an "
                "address on the device goes in address=)"
            )
        # Both checks run before a socket exists, so a refused call leaks nothing.
        device_name = _device_name(device, cache)
        device_option = _device_option()
    # Coerced through the same helper `ping`, `resolve` and `UDPEndpoint.send`
    # use, so one union is accepted everywhere rather than this one entry point
    # being stricter than its neighbours.
    address = _dst_argument(address) if address != "" else ""
    # Read once: a generator is exhausted by the first pass.
    options = tuple(options)

    if interface is not None:
        resolved = _interface_address(
            interface,
            want_ipv6=None if family is None else family == _socket.AF_INET6,
            cache=cache,
        )
        if resolved is None:
            raise ValueError("cannot resolve interface %r to an address" % (interface,))
        address = str(resolved)
        if family is None:
            family = (
                _socket.AF_INET6
                if getattr(resolved, "version", 4) == 6
                else _socket.AF_INET
            )
        if getattr(resolved, "version", None) == 6 and resolved.is_link_local:
            # A link-local bind needs its zone: the same address can exist on
            # several adapters, so the kernel cannot tell which is meant.
            # Measured, POSIX refuses the bare form outright -- EINVAL on Linux,
            # "Can't assign requested address" on macOS -- while Windows accepts
            # it. The zone is attached here as `%index` and turned into the
            # sockaddr's numeric scope id by `_sockaddr_for_bind`, which is the
            # only spelling POSIX accepts.
            zone = _interface_index(interface, strict=False, cache=cache)
            if zone and "%" not in address:
                address = "%s%%%d" % (address, int(zone))

    if family is None:
        family = _infer_family(address, kind)

    sock = _socket.socket(family, kind)
    try:
        exclusive = getattr(_socket, "SO_EXCLUSIVEADDRUSE", None)
        # An explicit `(SOL_SOCKET, SO_REUSEADDR, nonzero)` in `options` is the
        # caller asking for takeover in so many words, so it counts as
        # `allow_address_takeover=True` rather than fighting it.
        #
        # Windows **refuses** `SO_REUSEADDR` on a socket that already carries
        # `SO_EXCLUSIVEADDRUSE`, with a bare `WSAEINVAL` and no indication which
        # of the two it objected to. Since this function started setting
        # `SO_EXCLUSIVEADDRUSE` for both values of `reuse_address`, the
        # stdlib-shaped spelling of "share this address" therefore stopped
        # working here, failing with "[WinError 10022] An invalid argument was
        # supplied".
        takeover_requested = (
            allow_address_takeover
            or _shares_by_address(reuse_port, kind, exclusive)
            or any(
                level == _socket.SOL_SOCKET and name == _socket.SO_REUSEADDR and value
                for level, name, value in options
            )
        )
        if takeover_requested:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        elif exclusive is not None:
            # Windows, and set for **both** values of `reuse_address`. With
            # neither option set, a *more specific* SO_REUSEADDR bind takes
            # traffic from a wildcard holder: measured, a thief on 127.0.0.1
            # received the datagram while the holder on 0.0.0.0 got nothing and
            # no error. Tying the option to `reuse_address=True` alone would
            # make `reuse_address=False`, the setting that reads as strictest,
            # the least strict one available.
            #
            # Setting it regardless costs nothing: on Windows this option's only
            # effect is denying that takeover. There is no TIME_WAIT restart for
            # UDP it could forbid, and for TCP it is already what
            # `reuse_address=True` asked for. `reuse_address` therefore governs
            # POSIX `SO_REUSEADDR` only, which is what the name means everywhere
            # else.
            sock.setsockopt(_socket.SOL_SOCKET, exclusive, 1)
        elif reuse_address and kind != _socket.SOCK_DGRAM:
            # POSIX, **stream sockets only**. `SO_REUSEADDR` on a datagram socket
            # buys nothing a caller wants and costs the port: `TIME_WAIT` is a
            # TCP concept, so for UDP the option's only effect on Linux is to
            # permit *duplicate bindings of live sockets*. Measured on WSL: with
            # this set by default, a second `bind()` of the same live UDP
            # `addr:port` succeeded and the datagram went to the **second**
            # socket, with the holder getting no error -- silent traffic theft
            # under the default call.
            #
            # `socket(7)` is explicit that the exception is an active *listening*
            # socket, and a UDP socket never listens. So "two live sockets
            # cannot hold one addr:port" is true for TCP and false for UDP.
            #
            # Sharing a UDP port is still reachable, by the names that say so:
            # `reuse_port=True` (`SO_REUSEPORT`, the option actually designed for
            # it) or `allow_address_takeover=True`. `multicast_socket` sets what
            # it needs itself and does not rely on this.
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        if reuse_port:
            # Absent on Windows; setting it unconditionally would raise there.
            option = getattr(_socket, "SO_REUSEPORT", None)
            if option is not None:
                try:
                    sock.setsockopt(_socket.SOL_SOCKET, option, 1)
                except OSError:
                    pass  # present but refused by this kernel -- not fatal
        if broadcast:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        if kind == _socket.SOCK_DGRAM and (connreset is None or not connreset):
            disable_connreset(sock)
        for level, name, value in options:
            sock.setsockopt(level, name, value)
        if device_name is not None and device_option is not None:
            _apply_device(sock, device_option, device_name)

        try:
            sock.bind(_sockaddr_for_bind(family, address, port))
        except OSError as exc:
            raise _with_hint(exc, port) from exc
        if listen is not None and kind == _socket.SOCK_STREAM:
            sock.listen(listen)
    except BaseException:
        sock.close()
        raise
    return sock


def _shares_by_address(reuse_port: bool, kind: int, exclusive: "Optional[int]") -> bool:
    """Whether ``reuse_port`` has to be spelled as address sharing here.

    Windows has no ``SO_REUSEPORT``: the way two datagram sockets share a port
    there is ``SO_REUSEADDR``. A stream socket keeps the exclusive default.
    """
    return (
        reuse_port
        and kind == _socket.SOCK_DGRAM
        and exclusive is not None
        and getattr(_socket, "SO_REUSEPORT", None) is None
    )


def _infer_family(address: str, kind: int) -> int:
    """The address family *address* implies; ``AF_INET`` when it implies none.

    An empty address is the IPv4 wildcard. A literal decides by its version. A
    name is looked up and takes ``AF_INET`` when it has an IPv4 address, so a
    dual-stack name binds as IPv4; a name with only IPv6 addresses gets
    ``AF_INET6``, and one that does not resolve is left to the socket layer to
    refuse.
    """
    if not address:
        return _socket.AF_INET
    try:
        return (
            _socket.AF_INET6
            if _ipaddress.ip_address(address.split("%", 1)[0]).version == 6
            else _socket.AF_INET
        )
    except ValueError:
        pass
    try:
        families = {
            info[0]
            for info in _socket.getaddrinfo(address, None, type=kind)
            if info[0] in (_socket.AF_INET, _socket.AF_INET6)
        }
    except OSError:
        return _socket.AF_INET
    if _socket.AF_INET in families or not families:
        return _socket.AF_INET
    return _socket.AF_INET6


def _sockaddr_for_bind(family: int, address: str, port: int) -> "Any":
    """The ``bind`` argument for *address*, carrying an IPv6 zone correctly.

    **A ``%zone`` suffix has to become the sockaddr's numeric scope id; it
    cannot stay in the string.** Measured on Linux (kernel 6.x, CPython 3.13)
    against a real NIC's ``fe80::`` address, binding each spelling:

    ======================================  =========================
    ``bind(("fe80::1%2", 0))``              ``OSError`` EINVAL
    ``bind(("fe80::1%eth0", 0))``           ``OSError`` EINVAL
    ``bind(("fe80::1", 0))``                ``OSError`` EINVAL
    ``bind(("fe80::1", 0, 0, 2))``          **ok**
    ======================================  =========================

    So the 4-tuple is the only form that works, and the bare form fails too --
    a link-local bind needs its zone on POSIX whatever the adapter. Windows
    accepts every one of these, which is exactly why a Windows-only measurement
    says nothing here.

    The zone may be a name or an index, since both spellings reach this from
    ``getsockname`` and from a caller writing the natural form.
    """
    if family != _socket.AF_INET6 or "%" not in address:
        return (address, port)

    host, _, zone = address.partition("%")
    scope = 0
    if zone.isdigit():
        scope = int(zone)
    else:
        try:
            scope = _socket.if_nametoindex(zone)
        except (OSError, AttributeError, ValueError):
            scope = 0
    if not scope:
        # An unresolvable zone is better bound bare than silently bound to
        # "the kernel's choice", which scope id 0 means.
        return (host, port)
    return (host, port, 0, scope)


def get_free_port(
    src: "HostLike" = "127.0.0.1", *, family: "Optional[int]" = None
) -> int:
    """Return a port number that was free a moment ago.

    Binds port 0, reads back whatever the OS assigned, and closes::

        port = get_free_port()
        server = start_my_server(port=port)

    A *getter*, despite "free" in the name -- it acquires a number, it does not
    release anything. The port is **not** held open for you.

    .. warning::
       **Inherently racy.** The port is released the instant this returns, so
       another process can take it before you bind. There is no way around that
       with a returned port number -- if you can, bind port 0 in the server
       itself and read back ``getsockname()`` instead of calling this.

    ``SO_REUSEADDR`` is deliberately **not** set: it would let the OS hand back
    a port still in ``TIME_WAIT``, which then fails or steals traffic when the
    caller binds it for real.

    ``src`` is any host, as for :func:`bind`, and ``family`` follows it the way
    it does there: an IPv6 address gives ``AF_INET6``, an IPv4 one or the
    default ``AF_INET``.
    """
    address = _dst_argument(src)
    family = _family_argument(family)
    if family is None:
        family = _infer_family(address, _socket.SOCK_STREAM)
    sock = _socket.socket(family, _socket.SOCK_STREAM)
    try:
        sock.bind(_sockaddr_for_bind(family, address, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()
