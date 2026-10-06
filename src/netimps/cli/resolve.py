"""``netimps resolve``: a DNS lookup returning native records."""

from __future__ import annotations

import typing as _ty

from netimps import resolve

from ._common import FOUND, NONE, Command, guarded, address_text


class Resolve(Command):
    """Resolve a name via DNS."""

    _parsername_ = "resolve"
    _parseraliases_ = ["dns"]

    query: str
    "Name to look up"
    ("query",)

    rdtype: _ty.Optional[str] = None
    "Record type (a, aaaa, mx, txt, ns, ptr, ...); auto-detects ptr for an address query"
    ("rdtype",)

    nameserver: _ty.Optional[str] = None
    "Query this nameserver instead of the system resolver"
    ("--nameserver", "-n")

    timeout: float = 5.0
    "Seconds for the whole resolution, retries included"
    ("--timeout", "-t")

    tcp: bool = False
    "Query over TCP rather than UDP"
    ("--tcp",)

    @guarded
    def __call__(self) -> int:
        # A backend that could not even ask (a missing binary, an unreachable
        # server) raises, and `guarded` makes it an error: only an answer of
        # "no records" is an empty list.
        records = [
            address_text(r)
            for r in resolve(
                self.query,
                self.rdtype,
                ns=self.nameserver,
                timeout=self.timeout,
                tcp=self.tcp,
            )
        ]
        self.emit(records, "\n".join(records))
        return FOUND if records else NONE
