"""The shipped source and header describe the code as it is.

A comment or docstring that narrates what the code "used to" do is true only
at one version and wrong for every reader after it; the changelog is where a
change is recorded. This scans ``src/netimps/*.py`` and ``src/netimps/AGENTS.md``
for that wording and fails naming the file and line.

A phrase that is a fact and not history goes in ``_ALLOWED`` with a reason.
"""

import re
from pathlib import Path

import pytest

_PACKAGE = Path(__file__).resolve().parent.parent / "src" / "netimps"

#: History wording, and "consumer" where the library's word is "caller".
_HISTORY = re.compile(
    r"\bused to\b|\bno longer\b|\bpreviously\b|\bthe old\b|\bhas always\b"
    r"|\bas before\b|\bwas a (?:real )?bug\b|\bturned out\b|\bshipped broken\b"
    r"|\bbefore the fix\b|\bthis one is new\b|\bearlier version\b"
    r"|\bas of the\b|\bnow\b|\bconsumers?\b",
    re.IGNORECASE,
)

#: ``(substring of the line, why the phrase is a fact and not history)``.
_ALLOWED = (
    ("is used to reach", "'used to' meaning 'employed for', not 'formerly did'"),
    ("is no longer supported", "the text of a runtime error for a removed variable"),
    ("enumerates now and reseeds", "'now' is the moment of the call"),
    ("added anything to :mod:`socket` right now", "'now' is the moment of the call"),
    ("deadline = now() + timer.delay", "'now' is a clock argument in an example"),
    ("empty now: another reader", "'now' is the state at the moment of the read"),
    ("installed right now", "'now' is the moment of the call"),
)


def _sources():
    return sorted(_PACKAGE.glob("*.py")) + [_PACKAGE / "AGENTS.md"]


def _allowed(line):
    return any(fragment in line for fragment, _reason in _ALLOWED)


def _offences():
    found = []
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if _HISTORY.search(line) and not _allowed(line):
                found.append("%s:%d: %s" % (path.name, number, line.strip()))
    return found


def test_the_package_comments_narrate_no_history():
    found = _offences()
    assert not found, (
        "comments describe the code as it is, not what it used to do; state "
        "the property, or add a fact-not-history phrase to _ALLOWED:\n"
        + "\n".join(found)
    )


def test_the_pattern_catches_the_wording_it_is_for():
    for line in (
        "# this used to call gethostbyname",
        "It was a bug here: every error advanced.",
        "The old code swallowed these.",
        "a consumer of this",
        "as of the Winsock backend",
    ):
        assert _HISTORY.search(line), line


@pytest.mark.parametrize("fragment", [fragment for fragment, _ in _ALLOWED])
def test_every_allowed_phrase_is_still_in_the_source(fragment):
    # An entry whose phrase has gone is an exemption nothing needs.
    assert any(
        fragment in path.read_text(encoding="utf-8") for path in _sources()
    ), fragment
