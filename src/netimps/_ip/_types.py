"""The v4/v6 union aliases, the accepted-input unions and the tables ``parse`` builds from."""

from __future__ import annotations

import ipaddress as _ipaddress
from typing import Any, Callable, Dict, Optional, Tuple, Union
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)

#: Either concrete address type: ``IPv4Address | IPv6Address``.
IPAddress = Union[IPv4Address, IPv6Address]


#: Either concrete interface type (address + prefix).
IPInterface = Union[IPv4Interface, IPv6Interface]


#: Either concrete network type.
IPNetwork = Union[IPv4Network, IPv6Network]


#: Anything ``parse(..., IPAddress)`` accepts.
IPAddressLike = Union[str, int, bytes, IPv4Address, IPv6Address]


#: Anything ``parse(..., IPInterface)`` accepts.
IPInterfaceLike = Union[
    str,
    int,
    bytes,
    IPv4Address,
    IPv6Address,
    IPv4Interface,
    IPv6Interface,
    IPv4Network,
    IPv6Network,
    Tuple[
        Union[str, int, bytes, IPv4Address, IPv6Address],
        Union[str, int],
    ],
]


#: Anything ``parse(..., IPNetwork)`` accepts.
IPNetworkLike = Union[
    str,
    int,
    bytes,
    IPv4Network,
    IPv6Network,
    IPv4Address,
    IPv6Address,
    IPv4Interface,
    IPv6Interface,
    Tuple[
        Union[str, int, bytes, IPv4Address, IPv6Address],
        Union[str, int],
    ],
]


# How each supported result type is built from a raw value. The stdlib
# ``ip_*`` functions rather than the concrete constructors, so every entry
# accepts the full range of inputs (str / int / packed bytes / an existing
# object) and picks the right family automatically.
#: What every entry in the tables below is: a callable taking the raw value plus
#: keyword options and returning the built object. Named so the dict literals
#: are not inferred as the join of three different ``ipaddress.ip_*`` functions,
#: which collapses to a type a checker refuses to call.
_Builder = Callable[..., Any]

_BUILDERS: "Dict[Any, _Builder]" = {
    IPAddress: _ipaddress.ip_address,
    IPInterface: _ipaddress.ip_interface,
    IPNetwork: _ipaddress.ip_network,
}


# Concrete types build via the same version-agnostic function, then assert the
# family: asking for IPv4Address and getting an IPv6Address back would defeat
# the request. Keyed to the union whose builder they share.
_CONCRETE = {
    IPv4Address: IPAddress,
    IPv6Address: IPAddress,
    IPv4Interface: IPInterface,
    IPv6Interface: IPInterface,
    IPv4Network: IPNetwork,
    IPv6Network: IPNetwork,
}


# ``ip_network`` is the one builder whose stdlib default we override: it is
# strict by default, which rejects "10.0.0.5/24" (host bits set). Non-strict is
# the useful behaviour and what callers nearly always mean; pass strict=True to
# get the stdlib's.
_BUILDER_DEFAULTS: "Dict[_Builder, Dict[str, Any]]" = {
    _ipaddress.ip_network: {"strict": False},
}


def ip_literal(text: str) -> "Optional[IPAddress]":
    """The address ``text`` spells, or ``None`` when it is not an address literal.

    What ``try_parse(text, IPAddress)`` answers for text, without the parser
    that sits above this module. A scope id (``fe80::1%eth0``) is part of the
    literal.
    """
    try:
        return _ipaddress.ip_address(text)
    except ValueError:
        return None
