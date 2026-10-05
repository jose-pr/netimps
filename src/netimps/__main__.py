"""``python -m netimps``: the same program as the ``netimps`` console script.

Needs the ``cli`` extra (``pip install netimps[cli]``); without it this exits
with one line naming the extra.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
