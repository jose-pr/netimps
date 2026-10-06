"""Socket-level helpers and route/MTU queries (internal).

The small functions every network tool ends up rewriting: which local address
would reach a host, an unused port for a test server, an honest TCP
reachability check, and waiting for a service to come up. Plus the routing and
MTU queries that need per-platform work.

Re-exported from :mod:`netimps`; do not import this module path directly.

Privilege boundary
------------------
Everything here works unprivileged **except** :func:`count_hops`'s in-process
path, which reads ICMP TTL-exceeded replies and therefore needs a raw socket
(root/Administrator). Without one it drives the system ``traceroute``, or
raises :class:`PermissionError` rather than silently returning nonsense when
``allow_traceroute=False``.
:func:`get_route` deliberately stops at the first hop, which *is* available
unprivileged on every supported platform.
"""

from __future__ import annotations

from ._bind import SocketOption, bind, get_free_port
from ._connect import get_source_ip, tcp_check, wait_for_port
from ._device import has_device_binding
from ._hint import bind_error_hint
from ._hops import count_hops
from ._mtu import discover_mtu, max_udp_payload
from ._options import disable_connreset, set_buffer_size
from ._pmtu import get_pmtu, get_tcp_mss
from ._route import Route, get_route

__all__ = [
    "bind",
    "has_device_binding",
    "max_udp_payload",
    "SocketOption",
    "disable_connreset",
    "set_buffer_size",
    "bind_error_hint",
    "get_source_ip",
    "get_free_port",
    "tcp_check",
    "wait_for_port",
    "get_route",
    "Route",
    "count_hops",
    "get_pmtu",
    "discover_mtu",
    "get_tcp_mss",
]
