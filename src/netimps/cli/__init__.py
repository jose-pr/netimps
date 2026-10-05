"""The ``netimps`` command line, built on ``duho``.

``main`` is the entry point of the ``netimps`` console script and of
``python -m netimps``. It needs the ``cli`` extra (``pip install
netimps[cli]``); importing this package does not, so a bare install gets one
line naming the extra instead of an ``ImportError``.

The root parser is :data:`Netimps`, built on first use because its base class
comes from ``duho``.
"""

from __future__ import annotations

import typing as _ty

if _ty.TYPE_CHECKING:
    from ._root import Netimps

__all__ = ["main"]

#: What a user who ran the console script without the extra needs to be told.
_NEEDS_EXTRA = "netimps: the CLI needs the 'cli' extra -- pip install 'netimps[cli]'"


def main(argv: "_ty.Optional[_ty.Sequence[str]]" = None) -> int:
    """Run the command line and return its exit status.

    ``0`` the answer was yes or something was found, ``1`` nothing was found
    or the answer was no, ``2`` an error: bad input, a missing program, an
    outage the command could not answer through. A usage error from the
    parser raises :class:`SystemExit` with ``2``.

    Without ``duho`` installed this raises :class:`SystemExit` naming the
    ``cli`` extra.
    """
    try:
        import duho
    except ImportError as exc:
        raise SystemExit(_NEEDS_EXTRA) from exc

    from ._root import Netimps

    status = duho.main(Netimps, argv)
    return 0 if status is None else int(status)


def __getattr__(name: str) -> "_ty.Any":
    """``Netimps``, imported on first use: its base class needs ``duho``."""
    if name == "Netimps":
        from ._root import Netimps

        return Netimps
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
