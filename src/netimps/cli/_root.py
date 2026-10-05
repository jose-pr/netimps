"""The root parser: the eleven subcommands under one program name."""

from __future__ import annotations

from duho import AUTO, Args

from .addr import Addr
from .check import Check
from .interfaces import Interfaces
from .mtu import Mtu
from .ping import Ping
from .port import Port
from .resolve import Resolve
from .route import Route
from .scan import Scan
from .source import Source
from .split import Split


class Netimps(Args):
    """Network utilities: interfaces, reachability, routing, MTU, DNS, scanning."""

    _parsername_ = "netimps"
    _version_ = AUTO
    _distribution_ = "netimps"
    _subcommands_ = [
        Interfaces,
        Ping,
        Resolve,
        Check,
        Route,
        Mtu,
        Scan,
        Addr,
        Source,
        Port,
        Split,
    ]
