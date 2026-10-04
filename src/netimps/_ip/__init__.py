"""IP address, interface and network types (internal).

The v4/v6 union aliases callers annotate with, the builder tables :func:`parse`
dispatches on, and the address/network helpers that are specific to IP (as
opposed to the generic parsing combinators, which live in ``_parse``).

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

from ._types import (
    IPAddress,
    IPAddressLike,
    IPInterface,
    IPInterfaceLike,
    IPNetwork,
    IPNetworkLike,
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from ._host import Host, HostLike, _dst_argument, _host_text, get_hostname
from ._hosttext import join_host, split_host, split_zone
from ._cidr import collapse, subtract
from ._classify import (
    LINK_LOCAL_V4,
    LINK_LOCAL_V6,
    LOOPBACK_V4,
    LOOPBACK_V6,
    _as_address,
    _family_argument,
    _required_family,
    is_link_scoped,
    is_wildcard,
    unmap,
)

__all__ = [
    "Host",
    "LINK_LOCAL_V4",
    "LOOPBACK_V4",
    "LOOPBACK_V6",
    "LINK_LOCAL_V6",
    "IPAddress",
    "IPInterface",
    "IPNetwork",
    "IPAddressLike",
    "IPInterfaceLike",
    "IPNetworkLike",
    "HostLike",
    "IPv4Address",
    "IPv4Interface",
    "IPv4Network",
    "IPv6Address",
    "IPv6Interface",
    "IPv6Network",
    "get_hostname",
    "collapse",
    "subtract",
    "split_host",
    "split_zone",
    "join_host",
    "unmap",
    "is_wildcard",
    "is_link_scoped",
]
