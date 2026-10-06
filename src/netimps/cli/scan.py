"""``netimps scan``: a host's open ports, or a network's responsive hosts."""

from __future__ import annotations

import typing as _ty

from netimps import (
    IPNetwork,
    get_default_scheme,
    scan_hosts,
    scan_ports,
    try_parse,
)

from ._common import FOUND, NONE, Command, address_text, guarded


class Scan(Command):
    """Scan a host's ports, or a network for responsive hosts."""

    _parsername_ = "scan"

    target: str
    "Host to scan, or a network in CIDR form"
    ("target",)

    ports: str = "common"
    "Ports: a range name (common/well-known/all), scheme, or comma list"
    ("--ports", "-p")

    timeout: float = 1.0
    "Per-connection timeout"
    ("--timeout", "-t")

    workers: int = 100
    "Concurrent connections"
    ("--workers", "-w")

    @guarded
    def __call__(self) -> int:
        # The two answer different questions and so have different shapes: a
        # list of hosts for a sweep, one host for a port scan.
        if self.is_sweep():
            payload: _ty.Any = self.sweep()
            plain = "\n".join(
                "%-16s %s" % (h["host"], " ".join(map(str, h["ports"])))
                for h in payload
            )
            found = bool(payload)
            nothing = "no hosts responded"
        else:
            payload = self.scan()
            plain = "\n".join(
                "%d/tcp open  %s" % (p, get_default_scheme(p) or "")
                for p in payload["ports"]
            )
            found = bool(payload["ports"])
            nothing = "no open ports found"
        self.emit(payload, plain or nothing)
        return FOUND if found else NONE

    def is_sweep(self) -> bool:
        # A bare address parses as a /32, which is a host scan, not a sweep.
        return "/" in self.target and try_parse(self.target, IPNetwork) is not None

    def sweep(self) -> "_ty.List[_ty.Dict[str, _ty.Any]]":
        found = scan_hosts(
            self.target,
            ports=self.ports,
            timeout=self.timeout,
            workers=self.workers,
        )
        return [{"host": address_text(addr), "ports": ports} for addr, ports in found]

    def scan(self) -> "_ty.Dict[str, _ty.Any]":
        open_ports = scan_ports(
            self.target,
            ports=self.ports,
            timeout=self.timeout,
            workers=self.workers,
        )
        return {"host": self.target, "ports": open_ports}
