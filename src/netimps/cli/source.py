"""``netimps source``: the local address that reaches a destination."""

from __future__ import annotations

from netimps import get_source_ip

from ._common import FOUND, NONE, Command, guarded


class Source(Command):
    """Show which local address is used to reach a destination."""

    _parsername_ = "source"
    _parseraliases_ = ["src"]

    dst: str = "8.8.8.8"
    "Destination to route toward"
    ("dst",)

    @guarded
    def __call__(self) -> int:
        address = get_source_ip(self.dst)
        if address is None:
            self.note("no route to %s" % self.dst)
            return NONE
        self.emit({"dst": self.dst, "src": str(address)}, str(address))
        return FOUND
