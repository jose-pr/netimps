"""``python -m netimps`` entry point.

Equivalent to the ``netimps`` console script. Requires the ``cli`` extra::

    pip install netimps[cli]

Without it, this exits with a one-line message naming the extra -- importing
:mod:`netimps.cli` never needs duho, only running a command does.
"""

from .cli import run

if __name__ == "__main__":
    raise SystemExit(run())
