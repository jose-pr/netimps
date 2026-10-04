"""CIDR set maths: ``collapse`` and ``subtract``."""

from __future__ import annotations

import ipaddress as _ipaddress
from typing import Iterable, List
from ipaddress import IPv4Network, IPv6Network
from .._parse import parse as _parse
from ._types import IPNetwork, IPNetworkLike


def collapse(networks: "Iterable[IPNetworkLike]") -> "List[IPNetwork]":
    """Merge an iterable of networks into the smallest equivalent list.

    Adjacent and overlapping networks are combined; the result is sorted and
    covers exactly the same addresses::

        collapse(["10.0.0.0/25", "10.0.0.128/25"])   # [IPv4Network('10.0.0.0/24')]
        collapse(["10.0.0.0/24", "10.0.0.8/29"])     # [IPv4Network('10.0.0.0/24')]

    Accepts anything :func:`parse` does, mixed v4 and v6 -- the families are
    collapsed independently and returned v4 first. Raises :class:`ValueError`
    on malformed input.
    """
    v4: "List[IPv4Network]" = []
    v6: "List[IPv6Network]" = []
    for item in networks:
        net = _parse(item, IPNetwork)
        if isinstance(net, IPv4Network):
            v4.append(net)
        else:
            v6.append(net)
    out: "List[IPNetwork]" = []
    if v4:
        out.extend(_ipaddress.collapse_addresses(v4))
    if v6:
        out.extend(_ipaddress.collapse_addresses(v6))
    return out


def subtract(
    networks: "Iterable[IPNetworkLike]", remove: "Iterable[IPNetworkLike]"
) -> "List[IPNetwork]":
    """Return ``networks`` minus every address in ``remove``.

    The set difference :mod:`ipaddress` leaves out -- it ships
    ``collapse_addresses`` but nothing to punch holes::

        subtract(["10.0.0.0/24"], ["10.0.0.64/26"])
        # [IPv4Network('10.0.0.0/26'), IPv4Network('10.0.0.128/25')]

        subtract(["0.0.0.0/0"], ["10.0.0.0/8", "192.168.0.0/16"])  # public v4

    The result is collapsed, so it is the minimal set of networks covering
    what is left. Removing something absent is a no-op, and removing a
    superset yields ``[]``. Mixed families are handled independently: an IPv6
    exclusion never affects IPv4 output.
    """
    remaining = collapse(networks)
    for item in remove:
        excluded = _parse(item, IPNetwork)
        next_round: "List[IPNetwork]" = []
        for net in remaining:
            if net.version != excluded.version:
                next_round.append(net)  # different family: untouched
                continue
            # mypy cannot see that the `.version` check above guarantees `net`
            # and `excluded` share a concrete type -- ipaddress's own stubs
            # type subnet_of/address_exclude as same-family-only, stricter
            # than the runtime, which accepts the IPv4Network|IPv6Network
            # union fine once the families actually match.
            if not (
                net.subnet_of(excluded)  # type: ignore[arg-type]
                or excluded.subnet_of(net)  # type: ignore[arg-type]
                or net.overlaps(excluded)
            ):
                next_round.append(net)
                continue
            if net.subnet_of(excluded):  # type: ignore[arg-type]
                continue  # fully removed
            next_round.extend(net.address_exclude(excluded))  # type: ignore[arg-type]
        remaining = next_round
    return collapse(remaining)
