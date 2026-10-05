"""What every command shares: the base class, the output and the statuses."""

from __future__ import annotations

import functools as _functools
import json as _json
import sys as _sys
import typing as _ty

from duho import Cmd, LoggingArgs

from netimps import ResolutionError

#: Exit statuses, one meaning each (as ``grep``): found or yes, nothing found or
#: no, and an error.
FOUND = 0
NONE = 1
ERROR = 2

_F = _ty.TypeVar("_F", bound=_ty.Callable[..., int])


def error(text: str) -> None:
    """Print a diagnostic on stderr, keeping stdout for the answer alone."""
    print(text, file=_sys.stderr)


def guarded(call: "_F") -> "_F":
    """Turn the errors a bad argument raises into ``error: ...`` and status 2.

    A command's ``__call__`` wears it, so a caller of the command gets the
    status and never a traceback for text the library rejected.
    """

    @_functools.wraps(call)
    def wrapper(*args: "_ty.Any", **kwargs: "_ty.Any") -> int:
        try:
            return call(*args, **kwargs)
        except (ValueError, ResolutionError) as exc:
            error("error: %s" % exc)
            return ERROR

    return _ty.cast("_F", wrapper)


class Command(LoggingArgs, Cmd):
    """Shared options: ``--json`` on every command, and ``-q`` for scripts."""

    _logger_name_ = "netimps"

    json_out: bool = False
    "Emit JSON instead of human-readable text"
    ("--json",)

    @property
    def silent(self) -> bool:
        """``-q`` given: print no result line, answer by the status alone."""
        return self.quiet > 0

    def emit(self, payload: "_ty.Any", plain: str) -> None:
        """The result: JSON under ``--json`` (``-q`` does not touch it), else
        ``plain`` unless ``-q``. An empty ``plain`` prints nothing."""
        if self.json_out:
            print(_json.dumps(payload, indent=2, default=str))
        elif plain and not self.silent:
            print(plain)

    def note(self, text: str) -> None:
        """A diagnostic that goes with a "no" answer; ``-q`` drops it."""
        if not self.silent:
            error(text)
