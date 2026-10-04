"""netimps -- small, self-contained network utilities.

A thin, typed convenience layer over the standard library's :mod:`ipaddress`
plus a handful of host helpers (DNS lookup, ping, interface discovery). One
flat import surface; no hard runtime dependencies. :func:`resolve` chains
``dnspython``/OS-resolver/``nslookup`` backends, using whichever is available
-- ``dnspython`` (install with the ``dns`` extra) is optional but gives the
fullest one.

::

    import netimps

    netimps.parse("10.0.0.5")                           # -> IPv4Address
    netimps.MACAddress("AA:BB:CC:DD:EE:FF").format("-")
    netimps.resolve("example.com", "aaaa")
    for iface in netimps.get_interfaces():
        print(iface.name, iface.mac, iface.ips)

Types and parsing
-----------------
``IPAddress``/``IPInterface``/``IPNetwork`` are the v4/v6 unions you annotate
with, reading the way :class:`ipaddress.IPv4Address` does::

    def get_route(dst: netimps.IPAddress, via: netimps.IPNetwork) -> None: ...

The same names are what you *parse into*, via one entry point::

    parse(value, IPNetwork)              # raises on bad input
    try_parse(value, IPNetwork)          # None instead
    is_valid(value, IPNetwork)           # bool convertibility check

All IP/network values are the concrete :mod:`ipaddress` classes, so
``.exploded``, ``.network_address``, ``.netmask`` and ``addr in network``
membership all behave exactly as the stdlib does.
"""

from __future__ import annotations

# Re-export the concrete stdlib types so consumers can annotate with them.
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)

from ._exceptions import (
    AddressInUseError,
    DNSDecodeError,
    NetimpsError,
    NetimpsValueError,
    ResolutionError,
    ResolutionTimeoutError,
)
from ._ip import (
    LINK_LOCAL_V4,
    LINK_LOCAL_V6,
    LOOPBACK_V4,
    LOOPBACK_V6,
    Host,
    HostLike,
    IPAddress,
    IPAddressLike,
    IPInterface,
    IPInterfaceLike,
    IPNetwork,
    IPNetworkLike,
    collapse,
    get_hostname,
    is_link_scoped,
    split_host,
    split_zone,
    join_host,
    unmap,
    is_wildcard,
    subtract,
)
from ._parse import is_valid, parse, try_parse

# The public spellings of everything below; the _-prefixed modules are
# implementation detail and must not be imported from outside the package.
from ._mac import MACAddress, MACAddressLike
from ._scheme import (
    get_default_port,
    get_default_scheme,
    register_port,
)
from ._ifaddrs import (
    INTERFACE_CACHE_TTL,
    Interface,
    clear_interface_cache,
    interface_enumerations,
    get_interfaces,
    is_broadcast,
    is_unicast,
    iter_addresses,
)
from ._dns import (
    RESOLUTION_CACHE_TTL,
    clear_resolution_cache,
    resolve,
    resolve_dnspython,
    resolve_system,
    resolve_nslookup,
    resolve_wire,
    resolve_doh,
)
from ._ping import PingResult, ping
from ._scan import PORT_RANGES, scan_hosts, scan_ports
from ._multicast import (
    is_multicast,
    join_group,
    leave_group,
    multicast_socket,
)
from ._fqdn import FQDN, FQDNLike
from ._retry import Backoff, backoff_delays, retry
from ._msg import (
    CMSG_LEN,
    CMSG_SPACE,
    patch_socket_module,
    recvmsg,
    sendmsg,
    is_socket_patched,
    has_recvmsg,
)
from ._msg import _patch_requested as _msg_patch_requested

from ._udp import Datagram, UDPEndpoint, has_pktinfo, SocketAddress
from ._sockets import (
    bind,
    max_udp_payload,
    SocketOption,
    disable_connreset,
    set_buffer_size,
    discover_mtu,
    get_pmtu,
    get_tcp_mss,
    bind_error_hint,
    get_interface,
    iter_interfaces,
    is_local_address,
    is_local_host,
    Route,
    get_free_port,
    get_source_ip,
    count_hops,
    get_route,
    tcp_check,
    wait_for_port,
)
from ._sockets import InterfaceQuery
from ._scan import PortsLike
from ._iface_spec import InterfaceLike

__all__ = [
    # Types: the v4/v6 unions you annotate with, plus the stdlib concretes.
    "IPAddress",
    "IPInterface",
    "IPNetwork",
    "IPv4Address",
    "IPv4Interface",
    "IPv4Network",
    "IPv6Address",
    "IPv6Interface",
    "IPv6Network",
    "MACAddress",
    "IPAddressLike",
    "IPInterfaceLike",
    "IPNetworkLike",
    "HostLike",
    "MACAddressLike",
    # Parsing.
    "parse",
    "try_parse",
    "is_valid",
    "Host",
    "is_link_scoped",
    "LINK_LOCAL_V4",
    "LOOPBACK_V4",
    "LOOPBACK_V6",
    "LINK_LOCAL_V6",
    "collapse",
    "subtract",
    "split_host",
    "split_zone",
    "join_host",
    "unmap",
    "is_wildcard",
    "get_default_port",
    "get_default_scheme",
    "register_port",
    "resolve",
    "resolve_dnspython",
    "resolve_system",
    "resolve_nslookup",
    "resolve_wire",
    "resolve_doh",
    "ResolutionError",
    "ResolutionTimeoutError",
    "DNSDecodeError",
    "NetimpsError",
    "NetimpsValueError",
    "ping",
    "PingResult",
    "Interface",
    "get_interfaces",
    "clear_interface_cache",
    "interface_enumerations",
    "INTERFACE_CACHE_TTL",
    "RESOLUTION_CACHE_TTL",
    "clear_resolution_cache",
    "is_broadcast",
    "is_unicast",
    "iter_addresses",
    # Socket / route helpers.
    "get_source_ip",
    "get_free_port",
    "tcp_check",
    "wait_for_port",
    "get_route",
    "bind",
    "AddressInUseError",
    "SocketOption",
    "disable_connreset",
    "set_buffer_size",
    "bind_error_hint",
    "get_interface",
    "iter_interfaces",
    "is_local_address",
    "is_local_host",
    "UDPEndpoint",
    "has_pktinfo",
    "Datagram",
    # Domain names as a value type. Note the pathlib inversion -- see FQDN.
    "FQDN",
    "FQDNLike",
    # Ancillary-data messaging, available on every platform (Windows included).
    "recvmsg",
    "sendmsg",
    "CMSG_LEN",
    "CMSG_SPACE",
    "has_recvmsg",
    "patch_socket_module",
    "is_socket_patched",
    "retry",
    "Backoff",
    "backoff_delays",
    # Scanning.
    "scan_ports",
    "scan_hosts",
    "PORT_RANGES",
    # Multicast.
    "multicast_socket",
    "join_group",
    "leave_group",
    "is_multicast",
    "Route",
    "count_hops",
    "get_pmtu",
    "discover_mtu",
    "max_udp_payload",
    "get_tcp_mss",
    "get_hostname",
    "InterfaceLike",
    "InterfaceQuery",
    "PortsLike",
    "SocketAddress",
]


def _installed_version() -> str:
    """The version the installed distribution actually declares.

    Read rather than restated. A literal here is a second source of truth for
    one fact, and it drifts the moment `pyproject.toml` is bumped and this line
    is not -- which is exactly what happened cutting 0.3.0, leaving
    `__version__` saying 0.2.2 while the metadata said 0.3.0 and the shipped
    header promised the two were the same value.

    Falls back to "0.0.0+unknown" when the package is not installed at all
    (running straight from a source tree with no metadata), which is honest
    about not knowing rather than inventing a number.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("netimps")
    except PackageNotFoundError:  # pragma: no cover - only in a bare checkout
        return "0.0.0+unknown"


__version__ = _installed_version()

# The patch is for *other people's* code: `_udp` calls `_msg` directly, so
# netimps' own behaviour is identical whether or not this runs. That is
# deliberate -- opting out below must not quietly cost `UDPEndpoint` its
# pktinfo support.
#
# Third-party code is the reason it runs at import time: a module that reads
# `socket.CMSG_SPACE` into a constant at *its* import time (which is the normal
# way to probe it) sees None if it is imported before `import netimps` has run.
#
# Opt out with NETIMPS_SOCKET_PATCH=0 before the first import, or call
# `patch_socket_module(False)` afterwards. See `_msg` for why this is default-on
# and why it installs four names rather than one.
if _msg_patch_requested():
    patch_socket_module()
