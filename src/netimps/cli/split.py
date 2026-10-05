"""``netimps split``: ``host:port`` text into its two parts."""

from __future__ import annotations

import typing as _ty

from netimps import split_host

from ._common import FOUND, Command, guarded


class Split(Command):
    """Split a host:port string, handling IPv6 brackets correctly."""

    _parsername_ = "split"

    value: str
    "The host:port string, e.g. '[::1]:8080'"
    ("value",)

    default_port: _ty.Optional[int] = None
    "Port to assume when the string has none"
    ("--default-port", "-d")

    @guarded
    def __call__(self) -> int:
        host, port = split_host(self.value, default_port=self.default_port)
        self.emit(
            {"host": host, "port": port},
            "%s\t%s" % (host, "" if port is None else port),
        )
        return FOUND
