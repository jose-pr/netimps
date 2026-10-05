"""How the package modules import each other.

Internal code imports a name from the module that owns it. A back-import from
the root only works because the root happens to be partly initialised at that
moment, and it breaks the first time a module is imported on its own.
"""

import ast
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


#: The most lines a module may have. A module is a unit someone reviews in one
#: sitting; past this it is split along a seam, or named below with the reason.
MAX_MODULE_LINES = 500

#: Modules over the limit, each with why.
_LONG_MODULES = {
    "_fqdn/_name.py": (
        "one class: the label algebra, the constructors and the dunder methods "
        "share its slots, and docstrings are most of the lines"
    ),
}

#: A function-local import of a sibling module, by ``(file, imported module)``,
#: with the cycle or the platform that forces it. Every other import of a
#: sibling is at the top of its module.
_LOCAL_IMPORTS = {
    ("cli/__init__.py", "netimps.cli._root"): (
        "the root parser's base class comes from duho, the optional `cli` "
        "extra: `import netimps.cli` must work without it so `main` can name "
        "the extra"
    ),
    ("_fqdn/_name.py", "netimps._dns"): (
        "_dns imports _ip, which imports this module: a top-level import here "
        "runs while _ip is half built"
    ),
    ("_fqdn/_name.py", "netimps._ping"): (
        "_ping imports _dns and _ip, which import this module"
    ),
    ("_ip/_host.py", "netimps._dns"): (
        "_dns imports _ip, so a top-level import here runs while _ip is half built"
    ),
    ("_msg/_dispatch.py", "netimps._winsock"): (
        "Windows-only: the module fails to import anywhere else, and a missing "
        "ws2_32 degrades the platform instead of breaking `import netimps`"
    ),
    ("_sockets/_options.py", "netimps._winsock"): (
        "Windows-only: the module fails to import anywhere else"
    ),
    ("_udp/_endpoint.py", "netimps._udp._notifier"): (
        "the notifier is a thread and an asyncio dependency created on the "
        "first awaited receive, so a synchronous caller never loads it"
    ),
}


def _modules():
    return sorted(_SRC.rglob("*.py"))


def _name(path):
    return path.relative_to(_SRC).as_posix()


def _package_of(path):
    """The dotted package a module's relative imports start from."""
    parts = list(path.relative_to(_SRC.parent).with_suffix("").parts)
    parts.pop()  # the module itself, or `__init__`
    return parts


def _local_sibling_imports(path):
    """``{imported module}`` for every relative import inside a function."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    package = _package_of(path)
    found = set()

    def visit(node, inside):
        for child in ast.iter_child_nodes(node):
            now = inside or isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            )
            if now and isinstance(child, ast.ImportFrom) and child.level:
                base = package[: len(package) - (child.level - 1)]
                if child.module:
                    found.add(".".join(base + child.module.split(".")))
                else:
                    found.update(".".join(base + [alias.name]) for alias in child.names)
            visit(child, now)

    visit(tree, False)
    return found


def test_no_module_is_over_the_size_limit_without_a_reason():
    long = {
        _name(p): len(p.read_text(encoding="utf-8").splitlines())
        for p in _modules()
        if len(p.read_text(encoding="utf-8").splitlines()) > MAX_MODULE_LINES
    }
    unexplained = {name: n for name, n in long.items() if name not in _LONG_MODULES}
    assert unexplained == {}, "split it, or name it in _LONG_MODULES with a reason"
    stale = [name for name in _LONG_MODULES if name not in long]
    assert stale == [], "no longer over the limit: remove from _LONG_MODULES"
    assert all(reason.strip() for reason in _LONG_MODULES.values())


def test_a_sibling_is_imported_at_the_top_of_a_module_or_the_reason_is_recorded():
    used = {
        (_name(p), target) for p in _modules() for target in _local_sibling_imports(p)
    }
    unexplained = sorted(used - set(_LOCAL_IMPORTS))
    assert unexplained == [], "lift the import to the top, or record the cycle"
    stale = sorted(set(_LOCAL_IMPORTS) - used)
    assert stale == [], "no such function-local import: remove it from the list"
    assert all(reason.strip() for reason in _LOCAL_IMPORTS.values())
