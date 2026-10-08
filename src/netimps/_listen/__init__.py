"""Where a service listens: the grammar that names it and the sockets that serve it (internal).

Re-exported from :mod:`netimps`. See ``AGENTS.md`` beside this file.
"""

from __future__ import annotations

from ._grammar import ListenAddress, ListenLike, parse_listen

__all__ = ["ListenAddress", "ListenLike", "parse_listen"]
