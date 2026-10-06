"""Binding a socket to one network device: the platform table, ``has_device_binding`` and the option."""

from __future__ import annotations

import errno as _errno
import socket as _socket
import sys as _sys
from typing import NamedTuple
from .._exceptions import DeviceBindingUnsupportedError
from .._ifaddrs import InterfaceLike, interface_index as _interface_index


class _DeviceOption(NamedTuple):
    """The socket option that restricts a socket to one device, and how it names it."""

    level: int
    number: int


#: The platform's device-binding option, by ``sys.platform`` prefix. A platform
#: has a row only when a measurement showed the option restricts what a
#: wildcard socket *receives*, as an ordinary user. Adding a platform is adding
#: a row here, and its measurement to the comment beside it.
#:
#: ``SO_BINDTODEVICE`` is 25 and takes the device name as bytes. Measured
#: 2026-10-07 on kernel 6.18 under WSL2, as uid 1000 and as root, IPv4 and
#: IPv6: a wildcard socket bound to ``lo`` received a loopback datagram and one
#: bound to ``eth0`` did not. CPython exports ``socket.SO_BINDTODEVICE`` only
#: on Linux and only from 3.3, so the literal is used and the ``OSError`` from
#: ``setsockopt`` is the "refused" signal.
#:
#: Platforms with no row, measured 2026-10-07: Windows and macOS 15.7 accept
#: options that steer what is *sent* (``IP_UNICAST_IF``; ``IP_BOUND_IF`` and
#: ``IPV6_BOUND_IF``) and a wildcard socket naming another interface still
#: received a loopback datagram, so none restricts receive; macOS refuses
#: ``SO_BINDTODEVICE`` and the ``UNICAST_IF`` pair with errno 42. FreeBSD 16.0
#: refuses every candidate with errno 42.
_OPTIONS = {
    "linux": _DeviceOption(_socket.SOL_SOCKET, 25),
}

#: Why a platform has no row, for the error message.
_NO_OPTION = {
    "win32": (
        "no option restricts what a socket receives (measured 2026-10-07: "
        "IP_UNICAST_IF and IPV6_UNICAST_IF steer what is sent, and a socket "
        "naming another interface still received a loopback datagram)"
    ),
    "darwin": (
        "SO_BINDTODEVICE, IP_UNICAST_IF and IPV6_UNICAST_IF are refused, and "
        "IP_BOUND_IF and IPV6_BOUND_IF are accepted but scope what is sent, "
        "not what is received (measured 2026-10-07, macOS 15.7)"
    ),
    "freebsd": (
        "every candidate option is refused with ENOPROTOOPT (measured "
        "2026-10-07, FreeBSD 16.0)"
    ),
}


def _platform_key() -> str:
    for prefix in ("linux", "win32", "darwin", "freebsd"):
        if _sys.platform.startswith(prefix):
            return prefix
    return _sys.platform


def _device_option() -> "_DeviceOption":
    """The option for this platform, or :class:`DeviceBindingUnsupportedError`."""
    key = _platform_key()
    option = _OPTIONS.get(key)
    if option is None:
        raise DeviceBindingUnsupportedError(
            _errno.ENOPROTOOPT,
            "cannot bind a socket to a device on %s: %s; has_device_binding() "
            "says whether a platform can"
            % (_sys.platform, _NO_OPTION.get(key, "unmeasured")),
        )
    return option


def _device_name(device: "InterfaceLike") -> str:
    """The kernel's name for the interface *device* names.

    :raises ValueError: when *device* names no local interface.
    """
    index = _interface_index(device, strict=True)
    try:
        return _socket.if_indextoname(int(index or 0))
    except (OSError, OverflowError) as exc:
        raise ValueError(
            "cannot resolve device %r to an interface name" % (device,)
        ) from exc


def has_device_binding() -> bool:
    """Whether ``bind(device=...)`` can restrict a socket to one device here.

    Decided by asking the kernel on a throwaway socket, naming the loopback
    device, so it also reflects what this process may do (``SO_BINDTODEVICE``
    needs ``CAP_NET_RAW`` before Linux 5.7). Where the platform has no
    measured option it is ``False`` without a socket being opened.
    """
    option = _OPTIONS.get(_platform_key())
    if option is None:
        return False
    try:
        name = _socket.if_indextoname(1)
    except (OSError, AttributeError):
        name = "lo"
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as probe:
            probe.setsockopt(option.level, option.number, name.encode())
    except OSError:
        return False
    return True


def _apply_device(sock: "_socket.socket", option: "_DeviceOption", name: str) -> None:
    """Restrict *sock* to the device *name*, before it is bound."""
    try:
        sock.setsockopt(option.level, option.number, name.encode())
    except OSError as exc:
        # The same errno, so a PermissionError stays one; the name is what the
        # kernel's own text lacks.
        raise OSError(
            exc.errno, "cannot bind to device %r: %s" % (name, exc.strerror)
        ) from exc
