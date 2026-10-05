"""The shipped ``AGENTS.md`` headers stay complete, listed and true.

``src/netimps/AGENTS.md`` is the top header; a large topic keeps its names and
one sentence there and its detail in an ``AGENTS.md`` beside the code that
implements it. These tests pin what makes that split trustworthy: every export
is in the top header, every header is listed where a reader looks for it, none
outgrows its limit, and every signature a header prints is the live one.
"""

import ast
import inspect
import re
import socket
import subprocess
from pathlib import Path

import pytest

import netimps

_ROOT = Path(__file__).resolve().parent.parent
_PACKAGE = _ROOT / "src" / "netimps"
_TOP = _PACKAGE / "AGENTS.md"
_SUBHEADERS = sorted(p for p in _PACKAGE.rglob("AGENTS.md") if p != _TOP)

#: The most lines a header may have. A reader takes the top header in one go
#: and a sub-header for one topic; past these, detail moves down or out.
TOP_MAX_LINES = 900
SUB_MAX_LINES = 500
#: The repo-root file orients a contributor and points elsewhere for detail.
ROOT_MAX_LINES = 220


def _lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def _inside_package(path):
    """The path a reader of the installed package uses: ``netimps/_dns/AGENTS.md``."""
    return "netimps/" + path.relative_to(_PACKAGE).as_posix()


def test_the_top_header_is_not_over_its_limit():
    assert len(_lines(_TOP)) <= TOP_MAX_LINES


@pytest.mark.parametrize("path", _SUBHEADERS, ids=_inside_package)
def test_a_sub_header_is_not_over_its_limit(path):
    assert len(_lines(path)) <= SUB_MAX_LINES


def test_there_are_sub_headers():
    # A split that left nothing below would make the limits above vacuous.
    assert _SUBHEADERS


@pytest.mark.parametrize("name", netimps.__all__)
def test_every_export_is_in_the_top_header(name):
    text = _TOP.read_text(encoding="utf-8")
    pattern = r"`[^`\n]*(?<![\w.])%s(?!\w)[^`\n]*`" % re.escape(name)
    assert re.search(pattern, text), "%s is in __all__ but not in a code span of %s" % (
        name,
        _TOP.name,
    )


@pytest.mark.parametrize("path", _SUBHEADERS, ids=_inside_package)
def test_every_sub_header_is_in_the_top_headers_table(path):
    rows = [l for l in _lines(_TOP) if l.startswith("|")]
    assert any(
        "`%s`" % _inside_package(path) in row for row in rows
    ), "%s is not named in a table row of the top header" % _inside_package(path)


@pytest.mark.parametrize("path", _SUBHEADERS, ids=_inside_package)
def test_a_sub_header_says_its_directory_is_private(path):
    head = "\n".join(_lines(path)[:20])
    assert head.startswith("# `netimps`"), path
    assert "public API header" in head
    if path.parent.name != "cli":
        assert "private" in head and "not an import path" in head


def _committed_headers():
    try:
        out = subprocess.run(
            ["git", "ls-files", "--", "*AGENTS.md"],
            cwd=str(_ROOT),
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [p for p in out.split() if p != "AGENTS.md"]


def test_the_root_file_names_every_committed_header():
    root = _ROOT / "AGENTS.md"
    if not root.exists():
        pytest.skip("the root AGENTS.md is not part of this tree")
    text = root.read_text(encoding="utf-8")
    missing = [p for p in _committed_headers() if p not in text]
    assert not missing, "the root AGENTS.md does not name: %s" % ", ".join(missing)


def test_the_root_file_is_not_over_its_limit():
    root = _ROOT / "AGENTS.md"
    if not root.exists():
        pytest.skip("the root AGENTS.md is not part of this tree")
    assert len(_lines(root)) <= ROOT_MAX_LINES


def test_the_tests_header_names_every_test_file_and_directory():
    tests = _ROOT / "tests"
    header = tests / "AGENTS.md"
    if not header.exists():
        pytest.skip("tests/AGENTS.md is not part of this tree")
    text = header.read_text(encoding="utf-8")
    names = [
        p.relative_to(tests).as_posix()
        for p in tests.rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.suffix in (".py", ".ini")
        and p.name not in ("__init__.py", "conftest.py", "consumer.ini")
    ]
    missing = [n for n in names if n not in text]
    assert not missing, "tests/AGENTS.md does not name: %s" % ", ".join(missing)


# --------------------------------------------------------------------------
# The signature probe.

#: ``**`name(args) -> result`**``: how a header prints a signature.
_SIGNATURE = re.compile(
    r"\*\*`(?:async )?([A-Za-z_][\w.]*)\(([^`]*?)\)(?: ->[^`]*)?`\*\*"
)

#: Names a printed default may use.
_NAMESPACE = dict(vars(socket))
_NAMESPACE.update(vars(netimps))


def _resolve(dotted):
    obj = netimps
    for part in dotted.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def _shape(parameters):
    """``[(name, kind, default)]`` with ``self`` and ``cls`` dropped."""
    shaped = []
    for name, kind, default in parameters:
        if name in ("self", "cls"):
            continue
        shaped.append((name, kind, default))
    return shaped


def _printed(args):
    """The parameters of a signature as a header prints them."""
    tree = ast.parse("def f(%s): pass" % " ".join(args.split()))
    spec = tree.body[0].args
    out = []
    positional = spec.posonlyargs + spec.args
    defaults = [None] * (len(positional) - len(spec.defaults)) + list(spec.defaults)
    for arg, default in zip(positional, defaults):
        out.append((arg.arg, "positional", default))
    if spec.vararg:
        out.append((spec.vararg.arg, "var_positional", None))
    for arg, default in zip(spec.kwonlyargs, spec.kw_defaults):
        out.append((arg.arg, "keyword", default))
    if spec.kwarg:
        out.append((spec.kwarg.arg, "var_keyword", None))
    return [(n, k, None if d is None else ast.unparse(d)) for n, k, d in out]


_KINDS = {
    inspect.Parameter.POSITIONAL_ONLY: "positional",
    inspect.Parameter.POSITIONAL_OR_KEYWORD: "positional",
    inspect.Parameter.VAR_POSITIONAL: "var_positional",
    inspect.Parameter.KEYWORD_ONLY: "keyword",
    inspect.Parameter.VAR_KEYWORD: "var_keyword",
}


def _live(obj):
    out = []
    for p in inspect.signature(obj).parameters.values():
        default = None if p.default is inspect.Parameter.empty else ("=", p.default)
        out.append((p.name, _KINDS[p.kind], default))
    return out


def _same_default(printed, live):
    if printed is None or live is None:
        return printed is None and live is None
    if type(live[1]) is object:
        # A private "not given" sentinel; the header documents it as None.
        return True
    try:
        return eval(printed, dict(_NAMESPACE)) == live[1]
    except Exception:
        return printed == repr(live[1])


def _probe(path):
    """``(checked, mismatches)`` for every signature a header prints."""
    checked, bad = 0, []
    text = path.read_text(encoding="utf-8")
    for match in _SIGNATURE.finditer(text):
        name, args = match.group(1), match.group(2)
        obj = _resolve(name)
        if obj is None or "<" in args or not callable(obj):
            continue
        if isinstance(obj, type) and issubclass(obj, BaseException):
            continue
        try:
            printed = _shape(_printed(args))
            live = _shape(_live(obj))
        except (SyntaxError, ValueError, TypeError):
            continue
        if not printed and live:
            continue  # prose naming a call, such as `Host.fqdn()`, is no signature
        checked += 1
        same = len(printed) == len(live) and all(
            p[0] == l[0] and p[1] == l[1] and _same_default(p[2], l[2])
            for p, l in zip(printed, live)
        )
        if not same:
            bad.append("%s(%s)" % (name, " ".join(args.split())))
    return checked, bad


def test_every_printed_signature_is_the_live_one():
    checked, bad = 0, []
    for path in [_TOP] + _SUBHEADERS:
        n, mismatches = _probe(path)
        checked += n
        bad.extend("%s: %s" % (_inside_package(path), m) for m in mismatches)
    assert not bad, "signature drift:\n" + "\n".join(bad)
    # A probe that matched nothing would pass whatever the headers say.
    assert checked >= 40, checked


def test_the_probe_sees_a_changed_signature(tmp_path):
    header = tmp_path / "AGENTS.md"
    header.write_text(
        "**`tcp_check(dst, port, *, timeout=2.0) -> bool`** — wrong default.\n"
        "**`tcp_check(dst, port, timeout=3.0) -> bool`** — not keyword-only.\n"
        "**`tcp_check(dst, port, *, timeout=3.0) -> bool`** — right.\n",
        encoding="utf-8",
    )
    checked, bad = _probe(header)
    assert checked == 3
    assert len(bad) == 2
