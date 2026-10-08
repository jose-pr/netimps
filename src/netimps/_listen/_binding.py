"""The sockets a listen specification names, bound (internal).

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import logging as _logging
import socket as _socket
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple, Union

from .._exceptions import DeviceBindingUnsupportedError, NetimpsValueError
from .._ifaddrs import (
    Interface,
    clear_interface_cache,
    iter_addresses,
    iter_interfaces,
)
from .._ip import IPAddress, IPv6Address
from .._sockets import bind, has_device_binding
from .._udp import UDPEndpoint, has_pktinfo
from ._grammar import ListenAddress, ListenLike, _Selector, parse_listen

LOGGER = _logging.getLogger(__package__)

#: One socket to open: the host text to bind, its port, the interfaces that limit
#: it, the one device to bind it to, and whether it asks for packet info.
_Socket = Tuple[str, int, Tuple[Interface, ...], Optional[Interface], bool]


def bind_listen(
    listen: "ListenLike" = None,
    default_ports: "Union[int, Sequence[int]]" = 0,
    *,
    family: "Optional[int]" = None,
    per_address: "Optional[bool]" = None,
    device_binding: bool = True,
    allow_address_takeover: bool = False,
    broadcast: bool = False,
) -> "Tuple[UDPEndpoint, ...]":
    """Bind the sockets `listen` names and return an endpoint for each, in order.

    ``listen``, ``default_ports`` and ``family`` are ``parse_listen``'s. An address
    is one socket; a wildcard is one socket that reports the arrival interface,
    or one for each address of the host when ``per_address`` is true (or ``None``
    and the host reports no packet info); a wildcard limited to interfaces is one
    wildcard socket whose endpoint ``.interfaces`` are the adapters, bound to the
    device when ``device_binding`` allows and the platform can. Every socket is
    exclusive, and an IPv6 socket is IPv6 only.

    A selector that matches no adapter, and a limited binding with
    ``per_address=True`` or on a host without packet info, raise
    ``NetimpsValueError`` before a socket is opened. A failure closes every
    socket this call opened and raises the error unchanged. What each kind of
    entry opens is set out in ``netimps/_listen/AGENTS.md``.
    """
    specs = parse_listen(listen, default_ports, family=family)
    clear_interface_cache()
    # Every refusal that needs no socket comes before the first one is opened.
    plans = [_plan(spec, per_address, device_binding) for spec in specs]
    opened: "List[UDPEndpoint]" = []
    held: "Set[Tuple[str, int]]" = set()
    warned: "List[bool]" = []
    try:
        for plan in plans:
            for host, port, adapters, device, pktinfo in plan:
                if (host, port) in held:
                    continue
                held.add((host, port))
                sock = _open(
                    host,
                    port,
                    device,
                    allow_address_takeover,
                    broadcast,
                    warned,
                )
                try:
                    endpoint = UDPEndpoint(sock, pktinfo=pktinfo, interfaces=adapters)
                except BaseException:
                    sock.close()
                    raise
                opened.append(endpoint)
    except BaseException:
        for endpoint in opened:
            try:
                endpoint.close()
            except Exception:  # closing is cleanup and must not mask the error
                LOGGER.debug("closing a listening socket failed", exc_info=True)
        raise
    return tuple(opened)


def _family_of(address: "IPAddress") -> int:
    return _socket.AF_INET6 if isinstance(address, IPv6Address) else _socket.AF_INET


def _adapters(selectors: "Sequence[_Selector]") -> "Tuple[Interface, ...]":
    """The adapters the selectors name, once each by index; each must name one.

    A MAC names every adapter carrying it (a bridge and its ports can share
    one); an adapter name names one; an `Interface` names itself.
    """
    found: "Dict[int, Interface]" = {}
    for selector in selectors:
        matched = [a for a in iter_interfaces(selector) if a.index]
        if not matched:
            hint = (
                "; a listen name is an adapter name or a MAC, and a host name is "
                "never resolved"
                if isinstance(selector, str)
                else ""
            )
            raise NetimpsValueError("no interface matches %r%s" % (selector, hint))
        for adapter in matched:
            found.setdefault(adapter.index, adapter)
    return tuple(found.values())


def _plan(
    spec: "ListenAddress", per_address: "Optional[bool]", device_binding: bool
) -> "List[_Socket]":
    """The sockets one entry opens. Looks interfaces up; opens nothing."""
    family = _family_of(spec.address)
    if not spec.address.is_unspecified:
        return [(str(spec.address), spec.port, (), None, False)]
    if spec.interfaces:
        if per_address:
            raise NetimpsValueError(
                "per_address cannot be combined with listening on an interface: "
                "one socket per address hears no broadcast on most platforms"
            )
        if not has_pktinfo(family):
            raise NetimpsValueError(
                "listening on an interface needs packet info, which sockets on "
                "this host do not report"
            )
        adapters = _adapters(spec.interfaces)
        device = (
            adapters[0]
            if device_binding and has_device_binding() and len(adapters) == 1
            else None
        )
        return [(str(spec.address), spec.port, adapters, device, True)]
    if per_address or (per_address is None and not has_pktinfo(family)):
        return [(host, spec.port, (), None, False) for host in _host_addresses(family)]
    return [(str(spec.address), spec.port, (), None, True)]


def _host_addresses(family: int) -> "Iterator[str]":
    """Every address of `family` the host holds, once each, loopback and link-local included.

    An IPv6 link-local address is bound with its zone, the adapter it is on: the
    same address can exist on several adapters, and the bind fails without one.
    """
    seen: "Set[str]" = set()
    for adapter, entry in iter_addresses(family=family):
        text = str(entry.ip)
        if isinstance(entry.ip, IPv6Address) and entry.ip.is_link_local:
            text = "%s%%%d" % (text.partition("%")[0], adapter.index)
        if text not in seen:
            seen.add(text)
            yield text


def _open(
    host: str,
    port: int,
    device: "Optional[Interface]",
    allow_address_takeover: bool,
    broadcast: bool,
    warned: "List[bool]",
) -> "_socket.socket":
    """One exclusive UDP socket. IPv6 is IPv6 only on every platform.

    A device bind the kernel refuses is repeated without the device, and said
    once per call; an error the repeat raises is the real one.
    """
    family = _socket.AF_INET6 if ":" in host else _socket.AF_INET
    options: "Dict[str, object]" = dict(
        family=family,
        kind=_socket.SOCK_DGRAM,
        reuse_address=False,
        allow_address_takeover=allow_address_takeover,
        connreset=False,
        broadcast=broadcast and family == _socket.AF_INET,
    )
    if family == _socket.AF_INET6:
        options["options"] = ((_socket.IPPROTO_IPV6, _socket.IPV6_V6ONLY, 1),)
    if device is not None:
        options["device"] = device
    try:
        return bind(host, port, **options)  # type: ignore[arg-type]
    except (DeviceBindingUnsupportedError, PermissionError) as refused:
        if device is None:
            raise
        if not warned:
            warned.append(True)
            LOGGER.warning(
                "Could not bind %s:%d to the device %s (%s: %s): datagrams from "
                "other interfaces are received and left to endpoint.admits.",
                host,
                port,
                device.name,
                type(refused).__name__,
                refused,
            )
        del options["device"]
        return bind(host, port, **options)  # type: ignore[arg-type]
