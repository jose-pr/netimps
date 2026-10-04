"""The names each backend asks about for a given ``search=``.

The system and ``nslookup`` backends try the name as given first, then each
domain; the wire backend tries each domain first and only a single-label name
at all. The three orders are observable, so they are pinned here.
"""

import pytest

from netimps import ResolutionError, _dns, _dnswire

SYSTEM_DOMAINS = ["sys.test", "other.test."]

NAMES = ["host", "host.sub", "host.", "a.b.c"]
SEARCHES = [
    True,
    False,
    [],
    ["a.test", "b.test"],
    ["a.test.", ".b.test", ""],
]


def _system(monkeypatch, name, search):
    seen = []

    def once(candidate, family, timeout):
        seen.append(candidate)
        return []

    monkeypatch.setattr(_dns._system, "_resolve_system_once", once)
    _dns.resolve_system(name, "a", search=search)
    return seen


def _nslookup(monkeypatch, name, search):
    seen = []

    def once(candidate, rdtype, ns, timeout):
        seen.append(candidate)
        return []

    monkeypatch.setattr(_dns._nslookup, "_resolve_nslookup_once", once)
    monkeypatch.setattr(
        _dns._common, "_system_search_domains", lambda: list(SYSTEM_DOMAINS)
    )
    _dns.resolve_nslookup(name, "a", search=search)
    return seen


def _wire(monkeypatch, name, search):
    seen = []

    def build(candidate, rdtype, ident):
        seen.append(candidate)
        raise ValueError("stop here")

    monkeypatch.setattr(_dnswire, "build_query", build)
    with pytest.raises(ResolutionError):
        _dns.resolve_wire(name, "a", ns="127.0.0.1", search=search)
    return seen


BACKENDS = {"system": _system, "nslookup": _nslookup, "wire": _wire}


#: ``(backend, name, index into SEARCHES) -> the names asked, in order``.
EXPECTED = {
    ("system", "host", 0): ["host"],
    ("system", "host", 1): ["host."],
    ("system", "host", 2): ["host"],
    ("system", "host", 3): ["host", "host.a.test", "host.b.test"],
    ("system", "host", 4): ["host", "host.a.test", "host..b.test"],
    ("system", "host.sub", 0): ["host.sub"],
    ("system", "host.sub", 1): ["host.sub."],
    ("system", "host.sub", 2): ["host.sub"],
    ("system", "host.sub", 3): ["host.sub", "host.sub.a.test", "host.sub.b.test"],
    ("system", "host.sub", 4): ["host.sub", "host.sub.a.test", "host.sub..b.test"],
    ("system", "host.", 0): ["host."],
    ("system", "host.", 1): ["host."],
    ("system", "host.", 2): ["host."],
    ("system", "host.", 3): ["host."],
    ("system", "host.", 4): ["host."],
    ("system", "a.b.c", 0): ["a.b.c"],
    ("system", "a.b.c", 1): ["a.b.c."],
    ("system", "a.b.c", 2): ["a.b.c"],
    ("system", "a.b.c", 3): ["a.b.c", "a.b.c.a.test", "a.b.c.b.test"],
    ("system", "a.b.c", 4): ["a.b.c", "a.b.c.a.test", "a.b.c..b.test"],
    ("nslookup", "host", 0): ["host", "host.sys.test", "host.other.test"],
    ("nslookup", "host", 1): ["host."],
    ("nslookup", "host", 2): ["host"],
    ("nslookup", "host", 3): ["host", "host.a.test", "host.b.test"],
    ("nslookup", "host", 4): ["host", "host.a.test", "host..b.test"],
    ("nslookup", "host.sub", 0): [
        "host.sub",
        "host.sub.sys.test",
        "host.sub.other.test",
    ],
    ("nslookup", "host.sub", 1): ["host.sub."],
    ("nslookup", "host.sub", 2): ["host.sub"],
    ("nslookup", "host.sub", 3): ["host.sub", "host.sub.a.test", "host.sub.b.test"],
    ("nslookup", "host.sub", 4): ["host.sub", "host.sub.a.test", "host.sub..b.test"],
    ("nslookup", "host.", 0): ["host."],
    ("nslookup", "host.", 1): ["host."],
    ("nslookup", "host.", 2): ["host."],
    ("nslookup", "host.", 3): ["host."],
    ("nslookup", "host.", 4): ["host."],
    ("nslookup", "a.b.c", 0): ["a.b.c", "a.b.c.sys.test", "a.b.c.other.test"],
    ("nslookup", "a.b.c", 1): ["a.b.c."],
    ("nslookup", "a.b.c", 2): ["a.b.c"],
    ("nslookup", "a.b.c", 3): ["a.b.c", "a.b.c.a.test", "a.b.c.b.test"],
    ("nslookup", "a.b.c", 4): ["a.b.c", "a.b.c.a.test", "a.b.c..b.test"],
    ("wire", "host", 0): ["host"],
    ("wire", "host", 1): ["host"],
    ("wire", "host", 2): ["host"],
    ("wire", "host", 3): ["host.a.test", "host.b.test", "host"],
    ("wire", "host", 4): ["host.a.test", "host.b.test", "host.", "host"],
    ("wire", "host.sub", 0): ["host.sub"],
    ("wire", "host.sub", 1): ["host.sub"],
    ("wire", "host.sub", 2): ["host.sub"],
    ("wire", "host.sub", 3): ["host.sub"],
    ("wire", "host.sub", 4): ["host.sub"],
    ("wire", "host.", 0): ["host."],
    ("wire", "host.", 1): ["host."],
    ("wire", "host.", 2): ["host."],
    ("wire", "host.", 3): ["host."],
    ("wire", "host.", 4): ["host."],
    ("wire", "a.b.c", 0): ["a.b.c"],
    ("wire", "a.b.c", 1): ["a.b.c"],
    ("wire", "a.b.c", 2): ["a.b.c"],
    ("wire", "a.b.c", 3): ["a.b.c"],
    ("wire", "a.b.c", 4): ["a.b.c"],
}


@pytest.mark.parametrize("key", sorted(EXPECTED))
def test_each_backend_asks_the_names_it_always_has(monkeypatch, key):
    backend, name, index = key
    assert BACKENDS[backend](monkeypatch, name, SEARCHES[index]) == EXPECTED[key]


@pytest.mark.parametrize("search", SEARCHES)
def test_a_reverse_lookup_through_nslookup_is_never_expanded(monkeypatch, search):
    seen = []

    def once(candidate, rdtype, ns, timeout):
        seen.append(candidate)
        return []

    monkeypatch.setattr(_dns._nslookup, "_resolve_nslookup_once", once)
    monkeypatch.setattr(
        _dns._common, "_system_search_domains", lambda: list(SYSTEM_DOMAINS)
    )
    _dns.resolve_nslookup("10.0.0.1", "ptr", search=search)
    assert seen == ["10.0.0.1"]
