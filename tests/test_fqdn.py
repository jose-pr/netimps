"""The ``Fqdn`` domain-name value type.

Pure value-type tests, so they are cheap and pinned hard. The network helpers
are asserted to be *pass-throughs* against a faked backend -- nothing here
resolves anything, and `conftest.py`'s guard enforces that.
"""

import pickle

import pytest

import netimps
from netimps import Fqdn, Host

# --------------------------------------------------------------------------- #
# Construction                                                                 #
# --------------------------------------------------------------------------- #


def test_construction_from_a_dotted_string_and_from_labels_agree():
    assert Fqdn("www.example.com") == Fqdn("www", "example", "com")
    assert Fqdn("www.example.com") == Fqdn(["www", "example", "com"])
    assert Fqdn("www", "example.com") == Fqdn("www.example.com")


def test_composition_from_another_fqdn():
    assert Fqdn("www", Fqdn("example.com")) == Fqdn("www.example.com")
    # Absoluteness comes from the last part, which is the one holding the root.
    composed = Fqdn("www", Fqdn("example.com."))
    assert composed.is_fully_qualified()
    assert str(composed) == "www.example.com."


def test_str_round_trips_including_the_trailing_dot():
    for text in ("example.com", "example.com.", "localhost", "a.b.c.d"):
        assert str(Fqdn(text)) == text


def test_repr_is_reconstructible():
    f = Fqdn("www.example.com.")
    assert repr(f) == "Fqdn('www.example.com.')"
    assert eval(repr(f), {"Fqdn": Fqdn}) == f  # noqa: S307


# --------------------------------------------------------------------------- #
# The inversion from pathlib -- the single most important property             #
# --------------------------------------------------------------------------- #


def test_the_algebra_is_inverted_from_pathlib_on_purpose():
    """DNS puts the significant label last, so every borrowed name flips.

    Asserted explicitly and loudly so that a future refactor "for consistency
    with pathlib" fails here rather than silently inverting the public API. If
    this test ever needs changing, that is an API break and not a cleanup.
    """
    f = Fqdn("www.example.com")

    # pathlib's `.name` is the RIGHTmost component; ours is the LEFTmost.
    assert f.hostname == "www"
    assert f.name == "www"
    assert f.hostname != f.tld

    # pathlib's `.parent` drops the rightmost; ours drops the leftmost.
    assert f.domain == Fqdn("example.com")

    # pathlib's `/` appends; ours prepends.
    assert Fqdn("example.com") / "www" == Fqdn("www.example.com")
    assert str(Fqdn("example.com") / "www") == "www.example.com"

    # And `.labels` is in text order, which is the reverse of significance.
    assert f.labels == ("www", "example", "com")


@pytest.mark.parametrize(
    "primary, alias",
    [
        ("labels", "parts"),
        ("hostname", "name"),
        ("domain", "parent"),
        ("domains", "parents"),
    ],
)
def test_pathlib_aliases_are_the_same_value(primary, alias):
    """The aliases exist for familiarity and must never drift from the primary.

    Kept as a parametrised law rather than four asserts so adding an alias
    without adding it here is the thing that fails.
    """
    f = Fqdn("a.b.example.com")
    assert getattr(f, primary) == getattr(f, alias)


def test_method_aliases_are_the_same_value():
    f = Fqdn("example.com.")
    assert f.is_fully_qualified() == f.is_absolute() is True
    assert Fqdn("example.com").is_absolute() is False
    assert f.with_hostname("mail") == f.with_name("mail")


def test_tld_has_no_suffix_alias():
    """`.suffix` was rejected, not forgotten.

    A filesystem suffix is part of a name (`.txt`); a TLD is a whole label. The
    analogy misleads, so the alias is deliberately absent -- pinned so nobody
    adds it as an obvious omission.
    """
    assert Fqdn("www.example.com").tld == "com"
    assert not hasattr(Fqdn("www.example.com"), "suffix")


# --------------------------------------------------------------------------- #
# Labels, domain, TLD                                                          #
# --------------------------------------------------------------------------- #


def test_domain_chain_terminates_rather_than_self_referencing():
    """`.domain` is None at the top, unlike `Path("/").parent` which is itself.

    A self-reference would make `while f.domain:` loop forever, which is the
    natural way to walk up a name.
    """
    f = Fqdn("a.b.example.com")
    assert f.domains == (
        Fqdn("b.example.com"),
        Fqdn("example.com"),
        Fqdn("com"),
    )
    assert Fqdn("com").domain is None

    seen = []
    current = f
    while current is not None:
        seen.append(str(current))
        current = current.domain
    assert seen == ["a.b.example.com", "b.example.com", "example.com", "com"]


def test_domain_is_not_the_registrable_domain():
    """Documented gap, pinned so it is not mistaken for a bug.

    Telling `example.co.uk` from `co.uk` needs the Public Suffix List, which is
    a dependency this package does not take.
    """
    assert Fqdn("example.com").domain == Fqdn("com")
    assert Fqdn("example.co.uk").domain == Fqdn("co.uk")


def test_single_label_names_work():
    f = Fqdn("localhost")
    assert f.hostname == "localhost"
    assert f.tld == "localhost"
    assert f.domain is None
    assert f.domains == ()
    assert len(f) == 1


def test_len_counts_labels_not_characters():
    assert len(Fqdn("www.example.com")) == 3
    assert len(str(Fqdn("www.example.com"))) == 15


def test_iteration_indexing_and_membership():
    f = Fqdn("a.b.c.d")
    assert list(f) == ["a", "b", "c", "d"]
    assert f[0] == "a"
    assert f[-1] == "d"
    # A slice is labels, not a name: an arbitrary slice usually is not one.
    assert f[1:] == ("b", "c", "d")
    assert isinstance(f[1:], tuple)
    assert "b" in f and "B" in f and "z" not in f
    assert 42 not in f


# --------------------------------------------------------------------------- #
# Algebra                                                                      #
# --------------------------------------------------------------------------- #


def test_truediv_prepends_and_accepts_both_types():
    base = Fqdn("example.com")
    assert base / "www" == Fqdn("www.example.com")
    assert base / Fqdn("www") == Fqdn("www.example.com")
    assert base / "a.b" == Fqdn("a.b.example.com")
    assert base / "www" / "deep" == Fqdn("deep.www.example.com")


def test_there_is_no_reflected_truediv():
    """Deliberate: the right operand is the label, so a reflected form would
    swap the operands' roles while producing the same string."""
    with pytest.raises(TypeError):
        "www" / Fqdn("example.com")


def test_truediv_rejects_nonsense_rather_than_guessing():
    with pytest.raises(TypeError):
        Fqdn("example.com") / 42
    with pytest.raises(TypeError):
        Fqdn("example.com") / "a..b"


def test_child_is_the_spelled_out_truediv():
    assert Fqdn("com").child("example", "www") == Fqdn("www.example.com")
    assert Fqdn("com").child("example") == Fqdn("com") / "example"


def test_with_hostname_replaces_only_the_leftmost_label():
    assert Fqdn("www.example.com").with_hostname("mail") == Fqdn("mail.example.com")
    assert Fqdn("localhost").with_hostname("other") == Fqdn("other")
    with pytest.raises(ValueError, match="one label"):
        Fqdn("www.example.com").with_hostname("a.b")


def test_is_subdomain_of_excludes_self():
    f = Fqdn("www.example.com")
    assert f.is_subdomain_of("example.com")
    assert f.is_subdomain_of("com")
    assert not f.is_subdomain_of(f)
    assert not f.is_subdomain_of("www.example.com")
    assert not Fqdn("example.com").is_subdomain_of("www.example.com")
    # Not fooled by a shared text suffix that is not a label boundary.
    assert not Fqdn("notexample.com").is_subdomain_of("example.com")


def test_is_subdomain_of_ignores_qualification():
    """`example.com` and `example.com.` are the same place in the tree."""
    assert Fqdn("www.example.com.").is_subdomain_of("example.com")
    assert Fqdn("www.example.com").is_subdomain_of("example.com.")


def test_relative_to_strips_the_suffix_and_is_never_qualified():
    assert Fqdn("www.example.com").relative_to("example.com") == Fqdn("www")
    assert Fqdn("a.b.example.com").relative_to("example.com") == Fqdn("a.b")
    # A fragment of a name has no root, whatever the original had.
    assert not Fqdn("www.example.com.").relative_to("example.com").is_fully_qualified()
    with pytest.raises(ValueError, match="not under"):
        Fqdn("www.example.com").relative_to("example.org")
    with pytest.raises(ValueError, match="not under"):
        Fqdn("example.com").relative_to("example.com")


def test_reverse_flips_label_order():
    assert Fqdn("www.example.com").reverse().labels == ("com", "example", "www")
    assert Fqdn("www.example.com").reverse().reverse() == Fqdn("www.example.com")


def test_reverse_is_not_a_reverse_dns_pointer():
    """Different operation, similar name. `.reverse_pointer` is absent because
    it is built from an address and this type has none."""
    assert not hasattr(Fqdn("example.com"), "reverse_pointer")


def test_qualification_conversions():
    rel, absolute = Fqdn("example.com"), Fqdn("example.com.")
    assert rel.as_fully_qualified() == absolute
    assert absolute.relative() == rel
    assert absolute.as_fully_qualified() is absolute
    assert rel.relative() is rel


def test_absoluteness_survives_the_algebra():
    a = Fqdn("example.com.")
    assert (a / "www").is_fully_qualified()
    assert a.domain.is_fully_qualified()
    assert a.with_hostname("other").is_fully_qualified()


# --------------------------------------------------------------------------- #
# Identity: the one rule whose absence is silent                               #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "spelling",
    ["example.com", "EXAMPLE.COM", "Example.Com", "eXaMpLe.cOm"],
)
def test_equal_and_hash_alike_across_case(spelling):
    """RFC 4343: DNS comparison is case-insensitive, and `hash` must agree.

    Same shape as `test_mac.py`'s hash/eq law. An `__eq__` that folds case
    while `__hash__` does not makes a dict silently keep duplicates, which is
    the failure mode that never raises.
    """
    reference = Fqdn("example.com")
    parsed = Fqdn(spelling)
    assert parsed == reference
    assert hash(parsed) == hash(reference)
    assert len({parsed, reference}) == 1


def test_qualification_is_part_of_identity():
    """`example.com` and `example.com.` are different queries, like Path("a")
    and Path("/a"). Surprising, documented, and deliberate."""
    assert Fqdn("example.com") != Fqdn("example.com.")
    assert hash(Fqdn("example.com")) != hash(Fqdn("example.com."))
    assert len({Fqdn("example.com"), Fqdn("example.com.")}) == 2
    # Compare labels when qualification is not what you mean.
    assert Fqdn("example.com").labels == Fqdn("example.com.").labels


def test_eq_does_not_coerce_a_string():
    """Same policy as MACAddress: coercing would make == disagree with hash."""
    assert Fqdn("example.com") != "example.com"
    assert Fqdn.try_parse("example.com") == Fqdn("example.com")


def test_ordering_groups_by_tld_not_by_text():
    """Sorted on reversed labels, which is what a list of names wants."""
    names = [Fqdn("b.com"), Fqdn("a.org"), Fqdn("a.com")]
    assert [str(f) for f in sorted(names)] == ["a.com", "b.com", "a.org"]
    # Explicitly NOT the same as sorting the text.
    assert sorted(str(f) for f in names) == ["a.com", "a.org", "b.com"]


def test_full_ordering_operators():
    a, b = Fqdn("a.com"), Fqdn("b.com")
    assert a < b and a <= b and b > a and b >= a
    assert a <= Fqdn("a.com") and a >= Fqdn("a.com")
    assert not a > b and not b < a
    with pytest.raises(TypeError):
        a < "a.com"


def test_immutable():
    f = Fqdn("example.com")
    with pytest.raises(AttributeError):
        f.labels = ()
    with pytest.raises(AttributeError):
        f._labels = ()
    with pytest.raises(AttributeError):
        del f._labels


def test_hashable_in_a_set_and_dict_key():
    mapping = {Fqdn("a.com"): 1, Fqdn("A.COM"): 2}
    assert len(mapping) == 1 and mapping[Fqdn("a.com")] == 2


def test_pickle_round_trip():
    for text in ("www.example.com", "example.com."):
        f = Fqdn(text)
        assert pickle.loads(pickle.dumps(f)) == f


# --------------------------------------------------------------------------- #
# Validation                                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "literal", ["10.0.0.1", "127.0.0.1", "::1", "fe80::1", "0.0.0.0"]
)
def test_an_address_literal_is_refused(literal):
    """Load-bearing for the whole design: this type is a *name* algebra.

    An IP has no labels, no parent domain and no TLD, so accepting one would
    make every method on it meaningless. netimps.Host is the union type.
    """
    with pytest.raises(ValueError, match="is an IP address"):
        Fqdn(literal)
    assert Fqdn.is_valid(literal) is False
    assert Fqdn.try_parse(literal) is None


def test_digit_labels_in_a_real_name_are_fine():
    """The address check must not catch legitimate names that look numeric.

    `4.3.2.1.in-addr.arpa` is the canonical case, and `0.pool.ntp.org` is one
    people actually type.
    """
    assert Fqdn("4.3.2.1.in-addr.arpa").tld == "arpa"
    assert Fqdn("0.pool.ntp.org").hostname == "0"
    assert Fqdn("1.2.3.4.example.com").domain == Fqdn("2.3.4.example.com")


def test_deriving_a_name_never_re_runs_the_address_check():
    """Walking down a numeric name must not trip over its own validation.

    `.domain` on `1.2.3.4.example.com` passes through forms that would be
    rejected as constructor input once enough labels are stripped; the derived
    path bypasses validation precisely so this works.
    """
    f = Fqdn("1.2.3.4.sub")
    assert f.reverse() == Fqdn("sub.4.3.2.1")
    walked = []
    current = f
    while current is not None:
        walked.append(str(current))
        current = current.domain
    assert walked == ["1.2.3.4.sub", "2.3.4.sub", "3.4.sub", "4.sub", "sub"]


@pytest.mark.parametrize(
    "bad, match",
    [
        ("", "cannot be empty"),
        ("   ", "cannot be empty"),
        ("a..b", "empty label"),
        (".", "at least one label"),
        ("x" * 64 + ".com", "over the 63-octet limit"),
    ],
)
def test_malformed_names_are_refused(bad, match):
    with pytest.raises(ValueError, match=match):
        Fqdn(bad)


def test_the_length_limits_are_exact():
    """253 printable octets, not the commonly quoted 255.

    The wire form spends an octet on each label's length prefix and one on the
    root, so the printable cap is lower. Checked at the boundary in both
    directions, since an off-by-one here rejects valid names.
    """

    def name_of(total):
        parts, remaining = [], total
        while remaining > 64:
            parts.append("x" * 63)
            remaining -= 64
        parts.append("x" * remaining)
        return ".".join(parts)

    assert len(name_of(253)) == 253
    assert Fqdn.is_valid(name_of(253)) is True
    assert Fqdn.is_valid(name_of(254)) is False
    # And the label boundary, likewise both ways.
    assert Fqdn.is_valid("x" * 63 + ".com") is True
    assert Fqdn.is_valid("x" * 64 + ".com") is False


def test_only_the_last_part_may_carry_the_root_dot():
    """Otherwise `Fqdn("a.", "b")` silently produces a name with a hole."""
    with pytest.raises(ValueError, match="only the last part"):
        Fqdn("a.", "b")
    assert Fqdn("a", "b.") == Fqdn("a.b.")


def test_non_string_parts_are_a_type_error():
    with pytest.raises(TypeError):
        Fqdn(42)
    with pytest.raises(TypeError):
        Fqdn(None)
    with pytest.raises(ValueError):
        Fqdn()


def test_idna_encodes_a_non_ascii_name():
    """Via the stdlib, which is IDNA 2003 -- documented, not hidden."""
    assert str(Fqdn("münchen.de")) == "xn--mnchen-3ya.de"
    assert Fqdn("münchen.de") == Fqdn("xn--mnchen-3ya.de")
    assert Fqdn("MÜNCHEN.de") == Fqdn("xn--mnchen-3ya.de")


def test_is_valid_and_try_parse_never_raise():
    for value in ("example.com", "10.0.0.1", "", None, 42, "a..b", object()):
        assert isinstance(Fqdn.is_valid(value), bool)
        result = Fqdn.try_parse(value)
        assert result is None or isinstance(result, Fqdn)


def test_exported_from_the_package():
    assert netimps.Fqdn is Fqdn
    assert "Fqdn" in netimps.__all__
    assert "FqdnLike" in netimps.__all__


# --------------------------------------------------------------------------- #
# The Host bridge                                                              #
# --------------------------------------------------------------------------- #


def test_host_fqdn_narrows_a_name_and_refuses_an_address(no_such_host):
    assert Host("www.example.com").fqdn == Fqdn("www.example.com")
    assert Host("10.0.0.5").fqdn is None
    assert Host("::1").fqdn is None
    # A syntactically impossible name answers None rather than raising from a
    # property.
    assert Host("a..b").fqdn is None


def test_host_keeps_its_own_contract(no_such_host):
    """The bridge is additive: Host still reports the original text."""
    host = Host("WWW.Example.COM")
    assert str(host) == "WWW.Example.COM"
    assert host.fqdn == Fqdn("www.example.com")


# --------------------------------------------------------------------------- #
# Network helpers: pass-throughs, asserted as such                             #
# --------------------------------------------------------------------------- #


def test_resolve_is_a_pass_through(monkeypatch):
    """No logic of its own -- that would belong in `_dns`, not here."""
    seen = {}

    def fake_resolve(query, **kwargs):
        seen["query"] = query
        seen["kwargs"] = kwargs
        return ["sentinel"]

    monkeypatch.setattr(netimps, "resolve", fake_resolve)
    result = Fqdn("www.example.com").resolve(rdtype="aaaa", strict=True)
    assert result == ["sentinel"]
    assert seen["query"] == "www.example.com"
    assert seen["kwargs"] == {"rdtype": "aaaa", "strict": True}


def test_resolve_passes_the_fully_qualified_form_through(monkeypatch):
    """A trailing dot is how a caller bypasses the search list, so it must
    survive the delegation rather than being normalised away."""
    seen = {}
    monkeypatch.setattr(
        netimps, "resolve", lambda query, **kw: seen.setdefault("query", query) and []
    )
    Fqdn("example.com.").resolve()
    assert seen["query"] == "example.com."


def test_ping_is_a_pass_through(monkeypatch):
    seen = {}

    def fake_ping(dst, **kwargs):
        seen["dst"] = dst
        seen["kwargs"] = kwargs
        return "pong"

    monkeypatch.setattr(netimps, "ping", fake_ping)
    assert Fqdn("example.com").ping(count=2) == "pong"
    assert seen == {"dst": "example.com", "kwargs": {"count": 2}}


def test_ip_returns_the_first_answer_or_none(monkeypatch):
    monkeypatch.setattr(netimps, "resolve", lambda query, **kw: ["first", "second"])
    assert Fqdn("example.com").ip() == "first"
    monkeypatch.setattr(netimps, "resolve", lambda query, **kw: [])
    assert Fqdn("example.com").ip() is None


def test_ip_does_not_cache_unlike_host(monkeypatch):
    """Host caches because it is mutable; this type is immutable, and a cache
    on it would be a lie about freshness."""
    calls = []
    monkeypatch.setattr(
        netimps, "resolve", lambda query, **kw: calls.append(query) or ["a"]
    )
    f = Fqdn("example.com")
    f.ip()
    f.ip()
    assert len(calls) == 2
