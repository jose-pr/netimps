"""The listen grammar: what a user writes to say where a service listens (internal).

`parse_listen` reads it with no I/O: no name is resolved and no interface is
looked up, so whether an adapter exists is for the code that binds. Re-exported
from :mod:`netimps`.
"""

from __future__ import annotations

import socket as _socket
from typing import (
    Any,
    Dict,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from .._exceptions import NetimpsValueError
from .._ifaddrs import Interface
from .._ip import IPAddress, IPv4Address, IPv6Address, split_host
from .._mac import MACAddress

#: What names an interface in a binding.
_Selector = Union[Interface, MACAddress, str]

#: The host of a binding: `None` and blank text mean every address; an
#: `Interface`, a `MACAddress` or text that is no address names an interface.
_Host = Optional[Union[str, IPv4Address, IPv6Address, Interface, MACAddress]]

#: What follows a host in a pair: a port, several, or `None` for the defaults.
_Ports = Optional[Union[int, str, Sequence[Union[int, str]]]]


class ListenAddress(NamedTuple):
    """One socket a specification names: an address, a port and the interfaces limiting it.

    `interfaces` is empty for a socket that is not limited; otherwise `address`
    is the wildcard of the socket's family.
    """

    address: IPAddress
    port: int
    interfaces: Tuple[_Selector, ...] = ()


_Binding = Union[
    _Host,
    ListenAddress,
    Tuple[_Host, _Ports],
    List[Any],  # a pair as a config file has it
]

#: What `parse_listen` and `bind_listen` accept: nothing (every interface), one
#: binding, or a sequence of bindings. A binding is text (several joined by
#: commas), an address, an `Interface` or a `MACAddress`, a `ListenAddress`, or a
#: `(host, ports)` pair.
ListenLike = Optional[Union[_Binding, Sequence[_Binding]]]


class _Parsed(NamedTuple):
    address: IPAddress
    ports: Optional[List[int]]
    selectors: Tuple[_Selector, ...]
    label: object


_DIGITS_AND_SIGNS = frozenset("0123456789+- _")


def parse_listen(
    listen: "ListenLike" = None,
    default_ports: "Union[int, Sequence[int]]" = 0,
    *,
    family: "Optional[int]" = None,
) -> "Tuple[ListenAddress, ...]":
    """The sockets `listen` names, each address and port once, in the order first written.

    ``listen`` is ``None`` (the wildcard), text (``"host"``, ``"host:port"``,
    ``"[::1]:69"``, ``"*"``, ``":67"``, ``"eth1:67"``, a MAC, several joined by
    commas), an address, an ``Interface``, a ``MACAddress``, a ``ListenAddress``,
    a ``(host, ports)`` pair, or a sequence of those. Text that is no address
    names an interface; a host name is never resolved. ``default_ports`` is an
    int or a sequence, given to each binding that names no port. ``family``
    (``AF_INET`` or ``AF_INET6``) makes the wildcard forms and an interface
    binding that family's; ``None`` takes the wildcard forms as IPv4's.

    Raises ``TypeError`` for a value of a type the grammar does not take and
    ``NetimpsValueError`` for anything else it refuses. The grammar in full is in
    ``netimps/_listen/AGENTS.md``.
    """
    wanted = _family(family)
    ports = _default_ports(default_ports)
    limits: "Dict[Tuple[IPAddress, int], List[_Selector]]" = {}
    plain: "Set[Tuple[IPAddress, int]]" = set()
    for parsed in _iter_bindings(listen, wanted):
        if parsed.ports is None and not ports:
            raise NetimpsValueError(
                "%r names no port and there is no default port" % (parsed.label,)
            )
        for port in ports if parsed.ports is None else parsed.ports:
            key = (parsed.address, port)
            found = limits.setdefault(key, [])
            if not parsed.selectors:
                plain.add(key)
            for selector in parsed.selectors:
                if selector not in found:
                    found.append(selector)
    if not limits:
        raise NetimpsValueError("listen names no address: %r" % (listen,))
    return tuple(
        ListenAddress(address, port, () if (address, port) in plain else tuple(found))
        for (address, port), found in limits.items()
    )


def _family(family: object) -> "Optional[int]":
    if family is None:
        return None
    # Neither constant is 0 or 1 on any platform, so a bool is refused with the rest.
    if isinstance(family, int) and family in (_socket.AF_INET, _socket.AF_INET6):
        return int(family)
    raise NetimpsValueError(
        "family must be None, socket.AF_INET or socket.AF_INET6, not %r" % (family,)
    )


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("a port is an int, not %s %r" % (type(value).__name__, value))
    if not 0 <= value <= 65535:
        raise NetimpsValueError("port out of range: %d (must be 0-65535)" % value)
    return int(value)


def _default_ports(value: object) -> "List[int]":
    if isinstance(value, (str, bytes)) or not isinstance(value, (int, Sequence)):
        raise TypeError(
            "default_ports is an int or a sequence of ints, not %s %r"
            % (type(value).__name__, value)
        )
    return [_port(value)] if isinstance(value, int) else [_port(p) for p in value]


def _wildcard(family: "Optional[int]") -> IPAddress:
    return IPv6Address("::") if family == _socket.AF_INET6 else IPv4Address("0.0.0.0")


def _check_family(address: IPAddress, family: "Optional[int]", written: object) -> None:
    if family is None:
        return
    if family == _socket.AF_INET and isinstance(address, IPv6Address):
        raise NetimpsValueError(
            "%r is an IPv6 address, which family=AF_INET does not take" % (written,)
        )
    if family == _socket.AF_INET6 and isinstance(address, IPv4Address):
        raise NetimpsValueError(
            "%r is an IPv4 address, which family=AF_INET6 does not take" % (written,)
        )


def _wildcard_form(text: str) -> str:
    """The wildcard spellings as `split_host` reads them: `*`, `*:port`; `::` is an address."""
    if not text:
        return "*"
    if text.startswith(":") and not text.startswith("::"):
        return "*" + text
    return text


def _address(text: str) -> "Optional[IPAddress]":
    for kind in (IPv4Address, IPv6Address):
        try:
            return kind(text)  # type: ignore[no-any-return]
        except ValueError:
            pass
    return None


def _selector(text: str) -> "_Selector":
    mac = MACAddress.try_parse(text)
    if mac is not None:
        return mac
    if not text.strip() or "/" in text:
        raise NetimpsValueError("%r is not an interface name" % (text,))
    return text


def _host(
    text: str, family: "Optional[int]"
) -> "Tuple[IPAddress, Tuple[_Selector, ...]]":
    """What the host text of a binding names: an address, or an interface.

    The wildcard first, then an address of either family, then a MAC, then an
    adapter name: no name is looked up as a host name.
    """
    if text == "*":
        return _wildcard(family), ()
    address = _address(text)
    if address is not None:
        _check_family(address, family, text)
        return address, ()
    return _wildcard(family), (_selector(text),)


def _is_port_like(value: object) -> bool:
    """Whether `value` can be a pair's second item rather than a second binding."""
    if value is None or isinstance(value, int):
        return True  # a bool among them: `split_host` refuses it as a port
    if isinstance(value, str):
        return all(c in _DIGITS_AND_SIGNS for c in value)
    if isinstance(value, (tuple, list)):
        return all(
            item is not None
            and not isinstance(item, (tuple, list))
            and _is_port_like(item)
            for item in value
        )
    return False


def _is_host_like(value: object) -> bool:
    return value is None or isinstance(
        value, (str, IPv4Address, IPv6Address, Interface, MACAddress)
    )


def _is_pair(value: "Sequence[object]") -> bool:
    return (
        len(value) == 2
        and _is_host_like(value[0])
        and not (isinstance(value[0], str) and "," in value[0])
        and _is_port_like(value[1])
    )


def _ports_of(
    host_text: str, ports: object, label: object
) -> "Tuple[str, Optional[List[int]]]":
    """The host and the ports of a pair, checked by `split_host`."""
    wanted: "Sequence[object]"
    if ports is None or isinstance(ports, (int, str)):
        wanted = [ports]
    else:
        wanted = list(ports)  # type: ignore[call-overload]
        if not wanted:
            raise NetimpsValueError("%r names no port" % (label,))
    resolved: "Optional[List[int]]" = None
    host = host_text
    for one in wanted:
        # `split_host` checks the type and range of the port and that it agrees
        # with one written in the host.
        host, port = split_host((host_text, one))  # type: ignore[arg-type]
        if port is not None:
            resolved = (resolved or []) + [port]
    return host, resolved


def _pair(host: object, ports: object, family: "Optional[int]") -> _Parsed:
    label = (host, ports)
    if isinstance(host, (Interface, MACAddress)):
        _text, resolved = _ports_of("*", ports, label)
        return _Parsed(_wildcard(family), resolved, (host,), label)
    text = "*" if host is None else _wildcard_form(str(host).strip())
    mac = MACAddress.try_parse(text)
    if mac is not None:
        # The colon spelling cannot carry a port in the text: it comes second.
        _text, resolved = _ports_of("*", ports, label)
        return _Parsed(_wildcard(family), resolved, (mac,), label)
    text, resolved = _ports_of(text, ports, label)
    address, selectors = _host(text, family)
    return _Parsed(address, resolved, selectors, label)


def _one_text(text: str, family: "Optional[int]") -> _Parsed:
    stripped = text.strip()
    mac = MACAddress.try_parse(stripped)
    if mac is not None:
        return _Parsed(_wildcard(family), None, (mac,), text)
    host, port = split_host(_wildcard_form(stripped))
    address, selectors = _host(host, family)
    return _Parsed(address, None if port is None else [port], selectors, text)


def _listen_address(entry: ListenAddress, family: "Optional[int]") -> _Parsed:
    if not isinstance(entry.address, (IPv4Address, IPv6Address)):
        raise TypeError("a ListenAddress holds an address, not %r" % (entry.address,))
    _check_family(entry.address, family, entry.address)
    if not isinstance(entry.interfaces, tuple) or not all(
        isinstance(item, (Interface, MACAddress, str)) for item in entry.interfaces
    ):
        raise TypeError(
            "a ListenAddress holds its interfaces as a tuple of Interface, "
            "MACAddress or adapter name, not %r" % (entry.interfaces,)
        )
    selectors = tuple(
        _selector(item) if isinstance(item, str) else item for item in entry.interfaces
    )
    if selectors and not entry.address.is_unspecified:
        # Bound as written it would hear every interface, with nothing to say so.
        raise NetimpsValueError(
            "%r limits an address to interfaces: only a wildcard is limited" % (entry,)
        )
    return _Parsed(entry.address, [_port(entry.port)], selectors, entry)


def _bindings_of(item: object, family: "Optional[int]") -> "Iterator[_Parsed]":
    if item is None:
        yield _pair(None, None, family)
    elif isinstance(item, ListenAddress):
        yield _listen_address(item, family)
    elif isinstance(item, str):
        parts = [part.strip() for part in item.split(",") if part.strip()]
        if not parts:
            raise NetimpsValueError("listen names no address: %r" % (item,))
        for part in parts:
            yield _one_text(part, family)
    elif isinstance(item, (IPv4Address, IPv6Address, Interface, MACAddress)):
        yield _pair(item, None, family)
    elif isinstance(item, (tuple, list)) and _is_pair(item):
        yield _pair(item[0], item[1], family)
    else:
        raise TypeError(
            "a listen binding is text, an address, an interface, None, a "
            "ListenAddress or a (host, ports) pair, not %s %r"
            % (type(item).__name__, item)
        )


def _iter_bindings(listen: object, family: "Optional[int]") -> "Iterator[_Parsed]":
    if (
        isinstance(listen, (tuple, list))
        and not isinstance(listen, ListenAddress)
        and not _is_pair(listen)
    ):
        for item in listen:
            yield from _bindings_of(item, family)
    else:
        yield from _bindings_of(listen, family)
