"""The answer cache behind ``cache=``."""

from __future__ import annotations

import threading as _threading
import time as _time
from typing import Any, Dict, List, Optional, Tuple, Union

#: Seconds an answer is kept when a lookup passes ``cache=True``. Resolver
#: answers carry TTLs of their own that the backends do not expose, so this is a
#: fixed middle: long enough that a loop resolving one upstream per packet asks
#: once, short enough that a changed record is seen within the half minute.
#: Pass a number to choose your own.
RESOLUTION_CACHE_TTL = 30.0


#: The cache never grows past this many entries; the oldest go first.
_RESOLUTION_CACHE_LIMIT = 1024


_CACHE_LOCK = _threading.Lock()


#: key -> (monotonic stamp, answer). An empty tuple is a cached miss.
_RESOLUTION_CACHE: "Dict[Tuple[Any, ...], Tuple[float, Tuple[Any, ...]]]" = {}


def clear_resolution_cache() -> None:
    """Drop every cached answer, so the next ``cache=`` lookup asks again.

    For a caller that *knows* a record changed and should not wait out the TTL.
    Harmless when nothing is cached.
    """
    with _CACHE_LOCK:
        _RESOLUTION_CACHE.clear()


def _freeze(value: "Any") -> "Any":
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, str):
        return value.lower()
    return value


def _cache_key(
    query: str,
    rdtype: "Optional[Union[str, Tuple[str, ...]]]",
    ns: "Any",
    timeout: "Optional[float]",
    port: int,
    tcp: bool,
    search: "Any",
    backends: "Any",
    strict: bool,
    source: "Any",
) -> "Tuple[Any, ...]":
    """Every argument that can change the answer, in a hashable form.

    Names and addresses compare without case, since DNS does; the trailing root
    dot is not folded away, because it also decides whether a search list applies.
    """
    return (
        query.lower(),
        _freeze(rdtype) if rdtype else None,
        _freeze(ns),
        timeout,
        port,
        tcp,
        _freeze(search),
        _freeze(backends),
        strict,
        _freeze(source),
    )


def _cache_get(key: "Tuple[Any, ...]", ttl: float) -> "Optional[Tuple[Any, ...]]":
    with _CACHE_LOCK:
        entry = _RESOLUTION_CACHE.get(key)
        if entry is not None and (_time.monotonic() - entry[0]) < ttl:
            return entry[1]
    return None


def _cache_put(key: "Tuple[Any, ...]", answer: "List[Any]") -> None:
    with _CACHE_LOCK:
        _RESOLUTION_CACHE[key] = (_time.monotonic(), tuple(answer))
        while len(_RESOLUTION_CACHE) > _RESOLUTION_CACHE_LIMIT:
            del _RESOLUTION_CACHE[next(iter(_RESOLUTION_CACHE))]
