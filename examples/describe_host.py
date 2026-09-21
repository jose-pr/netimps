#!/usr/bin/env python3
"""Print what this machine looks like on the network.

    python examples/describe_host.py

Read-only and entirely local: it enumerates adapters, asks the kernel which
source address it would use for a given destination, and reports the first hop.
No packets are sent -- ``get_source_ip`` connects an unconnected UDP socket,
which only fixes the local end.

This is the "what am I even on?" script every network tool ends up growing, and
it exercises most of the discovery surface in one page.
"""

from __future__ import annotations

import sys

import netimps

#: Somewhere off-link, purely as a routing question. Nothing is sent to it.
PROBE = "1.1.1.1"


def main() -> int:
    print("host: %s\n" % netimps.HOST_DN)

    print("interfaces")
    for iface in netimps.get_interfaces():
        flags = []
        if iface.is_loopback:
            flags.append("loopback")
        print(
            "  %-34s %-18s mtu=%-6s %s"
            % (
                iface.name,
                iface.mac or "-",
                iface.mtu if iface.mtu is not None else "-",
                ",".join(flags) or "",
            )
        )
        for address in iface.ips:
            # is_link_scoped is "link scope or narrower", so it covers loopback
            # (host scope) as well as link-local -- the shared property being
            # that neither can usefully be routed off this host or link. It is
            # NOT "is private": 10/8 is globally scoped and returns False.
            scope = (
                "not routable off-link" if netimps.is_link_scoped(address.ip) else ""
            )
            print("      %-42s %s" % (address, scope))

    print("\nrouting")
    source = netimps.get_source_ip(PROBE)
    print("  source address for %-12s %s" % (PROBE, source or "(none)"))

    route = netimps.get_route(PROBE)
    # on_link is deliberately three-state: None means "this platform could not
    # tell us", which is not the same as "no router involved".
    if route.on_link is None:
        reachability = "unknown (no next-hop lookup available here)"
    elif route.on_link:
        reachability = "on-link, no router"
    else:
        reachability = "via %s" % route.gateway
    print("  first hop                       %s" % reachability)

    mtu = netimps.get_pmtu(PROBE)
    print("  cached path MTU                 %s" % (mtu if mtu else "(none cached)"))

    print("\nloopback sanity")
    result = netimps.ping("127.0.0.1")
    print("  ping 127.0.0.1                  %s" % ("ok" if result else "no reply"))
    if result:
        print("      rtt=%s ms  ttl=%s" % (result.rtt_ms, result.ttl))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
