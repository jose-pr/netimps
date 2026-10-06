"""``netimps route``: how traffic reaches a destination."""

from __future__ import annotations

import typing as _ty

from netimps import Route as _Route
from netimps import count_hops, get_route

from ._common import FOUND, Command, address_text, guarded


class Route(Command):
    """Show how traffic reaches a destination."""

    _parsername_ = "route"

    dst: str = "8.8.8.8"
    "Destination to route toward"
    ("dst",)

    hops: bool = False
    "Also count the hops (slower; may need privileges)"
    ("--hops",)

    @guarded
    def __call__(self) -> int:
        found = get_route(self.dst)
        payload = self.payload(found)
        self.emit(payload, self.text(found, payload))
        return FOUND

    def payload(self, found: _Route) -> "_ty.Dict[str, _ty.Any]":
        payload: "_ty.Dict[str, _ty.Any]" = {
            "dst": address_text(found.dst),
            "src": None if found.src is None else address_text(found.src),
            "gateway": None if found.gateway is None else address_text(found.gateway),
            "interface_index": found.interface_index,
            "on_link": found.on_link,
        }
        if self.hops:
            payload["hops"] = count_hops(self.dst)
        return payload

    def text(self, found: _Route, payload: "_ty.Dict[str, _ty.Any]") -> str:
        # ``on_link`` is a tri-state: True (no router needed), False (via the
        # gateway), or None when this platform could not be asked. Rendering
        # None as "on-link" would state as fact the one thing the lookup
        # failed to establish, so the two stay distinguishable in text
        # ("unknown") exactly as they are in JSON (``null``).
        if found.gateway is not None:
            gateway = address_text(found.gateway)
        elif found.on_link:
            gateway = "(on-link, no router)"
        else:
            gateway = "(unknown)"
        lines = [
            "dst      %s" % payload["dst"],
            "src      %s" % payload["src"],
            "gateway  %s" % gateway,
            "on-link  %s" % ("unknown" if found.on_link is None else found.on_link),
        ]
        if self.hops:
            lines.append("hops     %s" % payload["hops"])
        return "\n".join(lines)
