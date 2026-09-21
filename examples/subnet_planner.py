#!/usr/bin/env python3
"""Carve a network up and report what is left, using the CIDR set maths.

    python examples/subnet_planner.py
    python examples/subnet_planner.py 10.0.0.0/8 10.0.1.0/24 10.0.9.0/24

Takes a supernet followed by the blocks already allocated out of it, and prints
the minimal set of ranges still free. `subtract` is the piece `ipaddress` does
not ship -- it has `collapse_addresses`, but nothing to punch holes.

Pure computation: no sockets, no name resolution, nothing to configure.
"""

from __future__ import annotations

import sys

import netimps

DEFAULT_SUPERNET = "10.0.0.0/16"
DEFAULT_ALLOCATED = ["10.0.1.0/24", "10.0.2.0/23", "10.0.9.0/24"]


def main(argv: "list[str]") -> int:
    if len(argv) > 1:
        supernet, allocated = argv[1], argv[2:]
    else:
        supernet, allocated = DEFAULT_SUPERNET, DEFAULT_ALLOCATED

    try:
        parsed = netimps.parse(supernet, netimps.IPNetwork)
    except ValueError as exc:
        print("not a network: %s" % exc, file=sys.stderr)
        return 2

    print("supernet   %s  (%d addresses)" % (parsed, parsed.num_addresses))

    if allocated:
        print("allocated")
        # collapse() first so overlapping or adjacent allocations are reported
        # the way they actually consume space, not as the caller typed them.
        for block in netimps.collapse(allocated):
            print("  %-22s %d addresses" % (block, block.num_addresses))
    else:
        print("allocated  (nothing)")

    free = netimps.subtract([parsed], allocated)
    print("free")
    if not free:
        print("  (nothing -- fully allocated)")
    total = 0
    for block in free:
        total += block.num_addresses
        print("  %-22s %d addresses" % (block, block.num_addresses))

    if parsed.num_addresses:
        print(
            "\n%d of %d addresses free (%.1f%%)"
            % (total, parsed.num_addresses, 100.0 * total / parsed.num_addresses)
        )

    # Mixed families are handled independently, so a v6 exclusion never affects
    # v4 output -- worth showing, since it is the surprising part of the API.
    mixed = netimps.subtract([parsed], ["2001:db8::/32"])
    assert mixed == [parsed], "a v6 exclusion must not touch a v4 supernet"
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
