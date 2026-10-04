"""How the package modules import each other.

Internal code imports a name from the module that owns it. A back-import from
the root only works because the root happens to be partly initialised at that
moment, and it breaks the first time a module is imported on its own.
"""

import re
from pathlib import Path

import netimps

_SRC = Path(netimps.__file__).parent


def test_no_module_imports_a_name_from_the_root():
    """`from . import try_parse` resolves through the root's partly built
    namespace; it fails when a submodule is imported first."""
    pattern = re.compile(r"^\s+from \. import [a-zA-Z]", re.MULTILINE)
    offenders = [
        p.name
        for p in _SRC.glob("*.py")
        if pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert offenders == []
