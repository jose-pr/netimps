"""ICMP echo via the platform ``ping`` binary (internal).

Shelling out rather than using raw sockets, so this works unprivileged. The
cost is per-platform flag translation and output parsing, both of which are
kept strictly numeric/address-based so nothing here depends on the locale.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

from ._command import supports_dont_fragment
from ._probe import _probe_targets
from ._result import PingResult
from ._run import ping

__all__ = ["ping", "PingResult"]
