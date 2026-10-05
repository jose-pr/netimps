"""``netimps port``: a scheme's port, a port's scheme, or a free local port."""

from __future__ import annotations

import typing as _ty

from netimps import get_default_port, get_default_scheme, get_free_port

from ._common import FOUND, NONE, Command, guarded


def _is_number(text: str) -> bool:
    """Whether ``int()`` reads ``text``: the conversion is the test, since
    ``str.isdigit()`` is true for characters ``int()`` rejects."""
    try:
        int(text)
    except ValueError:
        return False
    return True


class Port(Command):
    """Look up a scheme's port, a port's scheme, or a free local port."""

    _parsername_ = "port"

    value: _ty.Optional[str] = None
    "Scheme name or port number; omit to get a free local port"
    ("value",)

    @guarded
    def __call__(self) -> int:
        if self.value is None:
            free = get_free_port()
            self.emit({"free_port": free}, str(free))
            return FOUND
        # An out-of-range number raises here, which is bad input.
        port = get_default_port(self.value)
        if _is_number(self.value):
            scheme = get_default_scheme(_ty.cast(int, port))
            self.emit({"port": port, "scheme": scheme}, scheme or "unknown")
            return FOUND if scheme else NONE
        self.emit(
            {"scheme": self.value, "port": port}, str(port) if port else "unknown"
        )
        return FOUND if port else NONE
