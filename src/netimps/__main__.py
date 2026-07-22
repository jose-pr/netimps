"""``python -m netimps`` entry point.

Equivalent to the ``netimps`` console script. Requires the ``cli`` extra::

    pip install netimps[cli]
"""

from .cli import run

if __name__ == "__main__":
    raise SystemExit(run())
