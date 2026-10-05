"""Native network-interface enumeration (internal).

Enumerates the host's interfaces -- adapter name, MAC, and every address with
its *real* prefix length -- using nothing but the standard library. POSIX goes
through ``getifaddrs(3)``; Windows through ``GetAdaptersAddresses``. Both are
bound with :mod:`ctypes`, so the package has no third-party dependency (the
widely used ``ifaddr`` package solves the same problem, and is deliberately
*not* used here).

The public entry point is :func:`get_interfaces`, re-exported from
:mod:`netimps`. Do not depend on this module path from outside the package.

Normalisation is the whole point
--------------------------------
The platforms disagree about far more than struct layout, so all of it is
resolved here rather than in every caller:

===================  ==================  ==================  =================
Concern              Linux               macOS/BSD           Windows
===================  ==================  ==================  =================
Interface name       ``eth0``            ``en0``             GUID + friendly
Prefix source        netmask sockaddr    netmask sockaddr    ``OnLinkPrefixLength``
Link-layer family    ``AF_PACKET`` (17)  ``AF_LINK`` (18)    ``PhysicalAddress``
IPv6 scope           ``%1``              ``%en0``            ``%12``
Loopback name        ``lo``              ``lo0``             ``Loopback Pseudo-Interface 1``
===================  ==================  ==================  =================

Two consequences worth stating outright, because getting them wrong is subtle:

* ``Interface.is_loopback`` comes from the kernel's own flag -- ``IFF_LOOPBACK``
  on POSIX, ``IF_TYPE_SOFTWARE_LOOPBACK`` on Windows -- and never from the
  name: a ``name == "lo"`` test silently fails on macOS (``lo0``) and is
  meaningless on Windows. The address heuristic remains only as the fallback
  for the degraded enumeration path, which reports no flags; it is wrong
  wherever a loopback interface *also* carries a routable address, which WSL2
  does by default (``10.255.255.254/32`` on ``lo``) and every keepalived /
  anycast / VIP host does on purpose.
* Prefixes are always real prefix lengths. The POSIX netmask sockaddr is
  converted by counting bits; Windows already reports an integer. Either way
  ``iface.ips[0].network`` behaves identically.

Platform-native leftovers (adapter GUID, ``IFF_*`` flags, ...) are available
only via ``get_interfaces(raw=True)`` -- see :class:`Interface.raw`.
"""

from __future__ import annotations

from ._addresses import is_broadcast, is_unicast, iter_addresses
from ._cache import (
    INTERFACE_CACHE_TTL,
    _interface_snapshot,
    clear_interface_cache,
    get_interfaces,
    interface_enumerations,
)
from ._lookup import (
    InterfaceQuery,
    get_interface,
    is_local_address,
    is_local_host,
    iter_interfaces,
    _without_zone,
)
from ._model import Interface
from ._spec import InterfaceLike, interface_address, interface_index

__all__ = [
    "Interface",
    "InterfaceLike",
    "InterfaceQuery",
    "get_interfaces",
    "get_interface",
    "iter_interfaces",
    "iter_addresses",
    "is_broadcast",
    "is_unicast",
    "is_local_address",
    "is_local_host",
    "interface_address",
    "interface_index",
    "clear_interface_cache",
    "interface_enumerations",
    "INTERFACE_CACHE_TTL",
]
