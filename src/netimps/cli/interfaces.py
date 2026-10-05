"""``netimps interfaces``: the adapters with their addresses, MACs and MTU."""

from __future__ import annotations

import typing as _ty

from netimps import Interface, get_interfaces

from ._common import FOUND, NONE, Command, guarded


class Interfaces(Command):
    """List network interfaces with their addresses, MACs and MTU."""

    _parsername_ = "interfaces"
    _parseraliases_ = ["ifaces", "if"]

    name: _ty.Optional[str] = None
    "Only show this interface"
    ("name",)

    raw: bool = False
    "Include the platform-specific raw data (not portable)"
    ("--raw",)

    @guarded
    def __call__(self) -> int:
        found = self.find()
        if not found:
            self.note("no interface named %r" % self.name)
            return NONE
        self.emit(self.records(found), "\n".join(self.lines(i) for i in found))
        return FOUND

    def find(self) -> "_ty.List[Interface]":
        found = get_interfaces(raw=self.raw)
        if self.name:
            found = [i for i in found if i.name == self.name]
        return found

    def records(self, found: "_ty.List[Interface]") -> "_ty.List[_ty.Any]":
        return [
            {
                "name": i.name,
                "index": i.index,
                "mac": None if i.mac is None else str(i.mac),
                "mtu": i.mtu,
                "is_loopback": i.is_loopback,
                "addresses": [str(a) for a in i.ips],
                "is_up": i.is_up,
                "raw": None if i.raw is None else dict(i.raw),
            }
            for i in found
        ]

    def lines(self, iface: Interface) -> str:
        flags = " [loopback]" if iface.is_loopback else ""
        if iface.is_up is False:
            flags += " [down]"
        head = "%s%s\n  index %s   mac %s   mtu %s" % (
            iface.name,
            flags,
            iface.index,
            iface.mac,
            iface.mtu,
        )
        return "\n".join([head] + ["  %s" % address for address in iface.ips])
