"""Re-raise ``socket.timeout`` as the builtin ``TimeoutError`` (internal)."""

from __future__ import annotations

import functools as _functools
import socket as _socket
from typing import Any, Callable, TypeVar, cast

_F = TypeVar("_F", bound=Callable[..., Any])


def _builtin_timeout(method: _F) -> _F:
    """Re-raise ``socket.timeout`` as the builtin ``TimeoutError``.

    From 3.10 they are one class and this changes nothing; on the 3.9 floor
    ``socket.timeout`` is only an ``OSError``, so a caller catching
    ``TimeoutError`` would otherwise miss it.
    """

    @_functools.wraps(method)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return method(*args, **kwargs)
        except _socket.timeout as exc:
            if isinstance(exc, TimeoutError):
                raise
            raise TimeoutError(*exc.args) from exc

    return cast(_F, wrapper)
