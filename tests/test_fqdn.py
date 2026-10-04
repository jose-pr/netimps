"""The ``FQDN`` domain-name value type.

Pure value-type tests, so they are cheap and pinned hard. The network helpers
are asserted to be *pass-throughs* against a faked backend -- nothing here
resolves anything, and `conftest.py`'s guard enforces that.
"""

import pickle

import pytest

import netimps
from netimps import FQDN, Host

# --------------------------------------------------------------------------- #
# Construction                                                                 #
# --------------------------------------------------------------------------- #


def test_construction_from_a_dotted_string_and_from_labels_agree():
    assert FQDN("www.example.com") == FQDN("www", "example", "com")
    assert FQDN("www.example.com") == FQDN(["www", "example", "com"])
    assert FQDN("www", "example.com") == FQDN("www.example.com")


def test_composition_from_another_fqdn():
    assert FQDN("www", FQDN("example.com")) == FQDN("www.example.com")
    # Absoluteness comes from the last part, which is the one holding the root.
    composed = FQDN("www", FQDN("example.com."))
    assert composed.is_fully_qualified()
    assert str(composed) == "www.example.com."


def test_str_round_trips_including_the_trailing_dot():
    for text in ("example.com", "example.com.", "localhost", "a.b.c.d"):
        assert str(FQDN(text)) == text


def test_repr_is_reconstructible():
    f = FQDN("www.example.com.")
    assert repr(f) == "FQDN('www.example.com.')"
    assert eval(repr(f), {"FQDN": FQDN}) == f  # noqa: S307


# --------------------------------------------------------------------------- #
# The inversion from pathlib -- the single most important property             #
# --------------------------------------------------------------------------- #


def test_the_algebra_is_inverted_from_pathlib_on_purpose():
    """DNS puts the significant label last, so every borrowed name flips.

    Asserted explicitly and loudly so that a future refactor "for consistency
    with pathlib" fails here rather than silently inverting the public API. If
    this test ever needs changing, that is an API break and not a cleanup.
    """
    f = FQDN("www.example.com")

    # pathlib's `.name` is the RIGHTmost component; ours is the LEFTmost.
    assert f.hostname == "www"
    assert f.name == "www"
    assert f.hostname != f.tld

    # pathlib's `.parent` drops the rightmost; ours drops the leftmost.
    assert f.domain == FQDN("example.com")

    # pathlib's `/` appends; ours prepends.
    assert FQDN("example.com") / "www" == FQDN("www.example.com")
    assert str(FQDN("example.com") / "www") == "www.example.com"

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
    f = FQDN("a.b.example.com")
    assert getattr(f, primary) == getattr(f, alias)


def test_method_aliases_are_the_same_value():
    f = FQDN("example.com.")
    assert f.is_fully_qualified() == f.is_absolute() is True
    assert FQDN("example.com").is_absolute() is False
    assert f.with_hostname("mail") == f.with_name("mail")


def test_tld_has_no_suffix_alias():
    """`.suffix` was rejected, not forgotten.

    A filesystem suffix is part of a name (`.txt`); a TLD is a whole label. The
    analogy misleads, so the alias is deliberately absent -- pinned so nobody
    adds it as an obvious omission.
    """
    assert FQDN("www.example.com").tld == "com"
    assert not hasattr(FQDN("www.example.com"), "suffix")


# --------------------------------------------------------------------------- #
# Labels, domain, TLD                                                          #
# --------------------------------------------------------------------------- #


def test_domain_chain_terminates_rather_than_self_referencing():
    """`.domain` is None at the top, unlike `Path("/").parent` which is itself.

    A self-reference would make `while f.domain:` loop forever, which is the
    natural way to walk up a name.
    """
    f = FQDN("a.b.example.com")
    assert f.domains == (
        FQDN("b.example.com"),
        FQDN("example.com"),
        FQDN("com"),
    )
    assert FQDN("com").domain is None

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
    assert FQDN("example.com").domain == FQDN("com")
    assert FQDN("example.co.uk").domain == FQDN("co.uk")


def test_single_label_names_work():
    f = FQDN("localhost")
    assert f.hostname == "localhost"
    assert f.tld == "localhost"
    assert f.domain is None
    assert f.domains == ()
    assert len(f) == 1


def test_len_counts_labels_not_characters():
    assert len(FQDN("www.example.com")) == 3
    assert len(str(FQDN("www.example.com"))) == 15


def test_iteration_indexing_and_membership():
    f = FQDN("a.b.c.d")
    assert list(f) == ["a", "b", "c", "d"]
    assert f[0] == "a"
    assert f[-1] == "d"
    # A slice is labels, not a name: an arbitrary slice usually is not one.
    assert f[1:] == ("b", "c", "d")
    assert isinstance(f[1:], tuple)
    # Label membership lives on `.labels`. `in` on the name itself means
    # containment -- see test_in_means_containment_like_ip_in_subnet.
    assert "b" in f.labels and "z" not in f.labels


# --------------------------------------------------------------------------- #
# Algebra                                                                      #
# --------------------------------------------------------------------------- #


def test_truediv_prepends_and_accepts_both_types():
    base = FQDN("example.com")
    assert base / "www" == FQDN("www.example.com")
    assert base / FQDN("www") == FQDN("www.example.com")
    assert base / "a.b" == FQDN("a.b.example.com")
    assert base / "www" / "deep" == FQDN("deep.www.example.com")


def test_there_is_no_reflected_truediv():
    """Deliberate: the right operand is the label, so a reflected form would
    swap the operands' roles while producing the same string."""
    with pytest.raises(TypeError):
        "www" / FQDN("example.com")


def test_truediv_rejects_nonsense_rather_than_guessing():
    with pytest.raises(TypeError):
        FQDN("example.com") / 42
    with pytest.raises(TypeError):
        FQDN("example.com") / "a..b"


def test_child_is_the_spelled_out_truediv():
    assert FQDN("com").child("example", "www") == FQDN("www.example.com")
    assert FQDN("com").child("example") == FQDN("com") / "example"


def test_with_hostname_replaces_only_the_leftmost_label():
    assert FQDN("www.example.com").with_hostname("mail") == FQDN("mail.example.com")
    assert FQDN("localhost").with_hostname("other") == FQDN("other")
    with pytest.raises(ValueError, match="one label"):
        FQDN("www.example.com").with_hostname("a.b")


def test_is_subdomain_of_excludes_self():
    f = FQDN("www.example.com")
    assert f.is_subdomain_of("example.com")
    assert f.is_subdomain_of("com")
    assert not f.is_subdomain_of(f)
    assert not f.is_subdomain_of("www.example.com")
    assert not FQDN("example.com").is_subdomain_of("www.example.com")
    # Not fooled by a shared text suffix that is not a label boundary.
    assert not FQDN("notexample.com").is_subdomain_of("example.com")


def test_is_subdomain_of_ignores_qualification():
    """`example.com` and `example.com.` are the same place in the tree."""
    assert FQDN("www.example.com.").is_subdomain_of("example.com")
    assert FQDN("www.example.com").is_subdomain_of("example.com.")


def test_relative_to_strips_the_suffix_and_is_never_qualified():
    assert FQDN("www.example.com").relative_to("example.com") == FQDN("www")
    assert FQDN("a.b.example.com").relative_to("example.com") == FQDN("a.b")
    # A fragment of a name has no root, whatever the original had.
    assert not FQDN("www.example.com.").relative_to("example.com").is_fully_qualified()
    with pytest.raises(ValueError, match="not under"):
        FQDN("www.example.com").relative_to("example.org")
    with pytest.raises(ValueError, match="not under"):
        FQDN("example.com").relative_to("example.com")


def test_reverse_flips_label_order():
    assert FQDN("www.example.com").reverse().labels == ("com", "example", "www")
    assert FQDN("www.example.com").reverse().reverse() == FQDN("www.example.com")


def test_reverse_is_not_a_reverse_dns_pointer():
    """Different operation, similar name. `.reverse_pointer` is absent because
    it is built from an address and this type has none."""
    assert not hasattr(FQDN("example.com"), "reverse_pointer")


def test_qualification_conversions():
    rel, absolute = FQDN("example.com"), FQDN("example.com.")
    assert rel.fully_qualified() == absolute
    assert absolute.relative() == rel
    assert absolute.fully_qualified() is absolute
    assert rel.relative() is rel


def test_absoluteness_survives_the_algebra():
    a = FQDN("example.com.")
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
    reference = FQDN("example.com")
    parsed = FQDN(spelling)
    assert parsed == reference
    assert hash(parsed) == hash(reference)
    assert len({parsed, reference}) == 1


def test_qualification_is_part_of_identity():
    """`example.com` and `example.com.` are different queries, like Path("a")
    and Path("/a"). Surprising, documented, and deliberate."""
    assert FQDN("example.com") != FQDN("example.com.")
    assert hash(FQDN("example.com")) != hash(FQDN("example.com."))
    assert len({FQDN("example.com"), FQDN("example.com.")}) == 2
    # Compare labels when qualification is not what you mean.
    assert FQDN("example.com").labels == FQDN("example.com.").labels


def test_eq_does_not_coerce_a_string():
    """Same policy as MACAddress: coercing would make == disagree with hash."""
    assert FQDN("example.com") != "example.com"
    assert FQDN.try_parse("example.com") == FQDN("example.com")


def test_ordering_groups_by_tld_not_by_text():
    """Sorted on reversed labels, which is what a list of names wants."""
    names = [FQDN("b.com"), FQDN("a.org"), FQDN("a.com")]
    assert [str(f) for f in sorted(names)] == ["a.com", "b.com", "a.org"]
    # Explicitly NOT the same as sorting the text.
    assert sorted(str(f) for f in names) == ["a.com", "a.org", "b.com"]


def test_full_ordering_operators():
    a, b = FQDN("a.com"), FQDN("b.com")
    assert a < b and a <= b and b > a and b >= a
    assert a <= FQDN("a.com") and a >= FQDN("a.com")
    assert not a > b and not b < a
    with pytest.raises(TypeError):
        a < "a.com"


def test_immutable():
    f = FQDN("example.com")
    with pytest.raises(AttributeError):
        f.labels = ()
    with pytest.raises(AttributeError):
        f._labels = ()
    with pytest.raises(AttributeError):
        del f._labels


def test_hashable_in_a_set_and_dict_key():
    mapping = {FQDN("a.com"): 1, FQDN("A.COM"): 2}
    assert len(mapping) == 1 and mapping[FQDN("a.com")] == 2


def test_pickle_round_trip():
    for text in ("www.example.com", "example.com."):
        f = FQDN(text)
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
        FQDN(literal)
    assert FQDN.is_valid(literal) is False
    assert FQDN.try_parse(literal) is None


def test_digit_labels_in_a_real_name_are_fine():
    """The address check must not catch legitimate names that look numeric.

    `4.3.2.1.in-addr.arpa` is the canonical case, and `0.pool.ntp.org` is one
    people actually type.
    """
    assert FQDN("4.3.2.1.in-addr.arpa").tld == "arpa"
    assert FQDN("0.pool.ntp.org").hostname == "0"
    assert FQDN("1.2.3.4.example.com").domain == FQDN("2.3.4.example.com")


def test_deriving_a_name_never_re_runs_the_address_check():
    """Walking down a numeric name must not trip over its own validation.

    `.domain` on `1.2.3.4.example.com` passes through forms that would be
    rejected as constructor input once enough labels are stripped; the derived
    path bypasses validation precisely so this works.
    """
    f = FQDN("1.2.3.4.sub")
    assert f.reverse() == FQDN("sub.4.3.2.1")
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
        FQDN(bad)


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
    assert FQDN.is_valid(name_of(253)) is True
    assert FQDN.is_valid(name_of(254)) is False
    # And the label boundary, likewise both ways.
    assert FQDN.is_valid("x" * 63 + ".com") is True
    assert FQDN.is_valid("x" * 64 + ".com") is False


def test_only_the_last_part_may_carry_the_root_dot():
    """Otherwise `FQDN("a.", "b")` silently produces a name with a hole."""
    with pytest.raises(ValueError, match="only the last part"):
        FQDN("a.", "b")
    assert FQDN("a", "b.") == FQDN("a.b.")


def test_non_string_parts_are_a_type_error():
    with pytest.raises(TypeError):
        FQDN(42)
    with pytest.raises(TypeError):
        FQDN(None)
    with pytest.raises(ValueError):
        FQDN()


def test_idna_encodes_a_non_ascii_name():
    """Via the stdlib, which is IDNA 2003 -- documented, not hidden."""
    assert str(FQDN("münchen.de")) == "xn--mnchen-3ya.de"
    assert FQDN("münchen.de") == FQDN("xn--mnchen-3ya.de")
    assert FQDN("MÜNCHEN.de") == FQDN("xn--mnchen-3ya.de")


def test_is_valid_never_raises_and_try_parse_raises_only_for_non_text():
    """`is_valid` answers for any object; `try_parse` answers for any *text*.

    A `None` or an `int` is a caller's bug, not unparseable text, so
    `try_parse` raises `TypeError` for it instead of returning the default.
    """
    for value in ("example.com", "10.0.0.1", "", None, 42, "a..b", object()):
        assert isinstance(FQDN.is_valid(value), bool)
    for text in ("example.com", "10.0.0.1", "", "a..b"):
        result = FQDN.try_parse(text)
        assert result is None or isinstance(result, FQDN)
    for value in (None, 42, object(), ["a", "b"]):
        with pytest.raises(TypeError):
            FQDN.try_parse(value)  # type: ignore[call-overload]
        with pytest.raises(TypeError):
            FQDN.parse(value)  # type: ignore[arg-type]


def test_exported_from_the_package():
    assert netimps.FQDN is FQDN
    assert "FQDN" in netimps.__all__
    assert "FQDNLike" in netimps.__all__


# --------------------------------------------------------------------------- #
# The Host bridge                                                              #
# --------------------------------------------------------------------------- #


def test_host_fqdn_narrows_a_name_and_asks_the_resolver_for_an_address(no_such_host):
    """A name is returned as written; an address is reverse-looked-up, and with
    no PTR record there is no name to give."""
    assert Host("www.example.com").fqdn() == FQDN("www.example.com")
    assert Host("10.0.0.5").fqdn() is None
    # A syntactically impossible name answers None rather than raising.
    assert Host("a..b").fqdn() is None


def test_host_keeps_its_own_contract(no_such_host):
    """The bridge is additive: Host still reports the original text."""
    host = Host("WWW.Example.COM")
    assert str(host) == "WWW.Example.COM"
    assert host.fqdn() == FQDN("www.example.com")


# --------------------------------------------------------------------------- #
# Network helpers: pass-throughs, asserted as such                             #
# --------------------------------------------------------------------------- #


def test_resolve_is_the_name_and_its_address(monkeypatch):
    """`resolve()` answers `(fqdn, ip)`, the same shape `Host.resolve()` does."""
    seen = {}

    def fake_resolve(query, rdtype, **kwargs):
        seen.update(query=query, rdtype=rdtype, kwargs=kwargs)
        return [netimps.parse("192.0.2.7")]

    monkeypatch.setattr(netimps._dns, "resolve", fake_resolve)
    name = FQDN("www.example.com")
    result = name.resolve(ipv6=True, ns="192.0.2.53")
    assert result == (name, netimps.parse("192.0.2.7"))
    assert result[0] is name
    assert seen["query"] == "www.example.com"
    assert seen["rdtype"] == "aaaa"
    assert seen["kwargs"]["ns"] == "192.0.2.53"


def test_resolve_passes_the_fully_qualified_form_through(monkeypatch):
    """A trailing dot is how a caller bypasses the search list, so it must
    survive the delegation rather than being normalised away."""
    seen = {}
    monkeypatch.setattr(
        netimps._dns,
        "resolve",
        lambda query, *a, **kw: seen.setdefault("query", query) and [],
    )
    FQDN("example.com.").resolve()
    assert seen["query"] == "example.com."


def test_ping_is_a_pass_through(monkeypatch):
    seen = {}

    def fake_ping(dst, **kwargs):
        seen["dst"] = dst
        seen["kwargs"] = kwargs
        return "pong"

    monkeypatch.setattr(netimps._ping, "ping", fake_ping)
    assert FQDN("example.com").ping(count=2) == "pong"
    assert seen == {"dst": "example.com", "kwargs": {"count": 2}}


def test_ip_returns_the_first_answer_or_none(monkeypatch):
    first, second = netimps.parse("192.0.2.1"), netimps.parse("192.0.2.2")
    monkeypatch.setattr(
        netimps._dns, "resolve", lambda query, *a, **kw: [first, second]
    )
    assert FQDN("example.com").ip() == first
    monkeypatch.setattr(netimps._dns, "resolve", lambda query, *a, **kw: [])
    assert FQDN("example.com").ip() is None


def test_ip_does_not_cache_unlike_host(monkeypatch):
    """Host caches because it is mutable; this type is immutable, and a cache
    on it would be a lie about freshness."""
    calls = []
    monkeypatch.setattr(
        netimps._dns,
        "resolve",
        lambda query, *a, **kw: calls.append(query) or [netimps.parse("192.0.2.1")],
    )
    f = FQDN("example.com")
    f.ip()
    f.ip()
    assert len(calls) == 2


# --------------------------------------------------------------------------- #
# Containment: the `ip in subnet` analogue                                     #
# --------------------------------------------------------------------------- #


def test_in_means_containment_like_ip_in_subnet():
    """``name in domain`` mirrors the stdlib's ``address in network``.

    This package is a thin layer over ``ipaddress``, so the stdlib idiom wins.
    An earlier version made ``in`` a *label* test, which reads plausibly and
    conflicts head-on: ``"com" in FQDN("www.example.com")`` is True as a label
    test and False as containment, and one expression cannot answer both.
    """
    import ipaddress

    # The precedent this follows.
    assert ipaddress.ip_address("10.0.0.5") in ipaddress.ip_network("10.0.0.0/24")

    assert FQDN("www.example.com") in FQDN("example.com")
    assert FQDN("a.b.example.com") in FQDN("example.com")
    assert FQDN("example.com") not in FQDN("www.example.com")
    assert FQDN("example.org") not in FQDN("example.com")
    # Not fooled by a shared text suffix across a label boundary.
    assert FQDN("notexample.com") not in FQDN("example.com")


def test_in_is_inclusive_where_is_subdomain_of_is_strict():
    """The pair mirrors ``<=`` against ``<``, and the difference is deliberate.

    A zone contains its own apex, exactly as a /24 contains its network
    address -- so ``in`` is the inclusive one, matching ipaddress.
    """
    f = FQDN("example.com")
    assert f in f
    assert not f.is_subdomain_of(f)


def test_in_accepts_a_string_and_ignores_qualification():
    assert "mail.example.com" in FQDN("example.com")
    assert FQDN("www.example.com.") in FQDN("example.com")
    assert FQDN("www.example.com") in FQDN("example.com.")


def test_in_is_a_total_predicate():
    """False, never an exception, so it stays safe inside a filter."""
    for junk in ("a..b", "", "10.0.0.1", 42, None, object()):
        assert junk not in FQDN("example.com")


def test_in_is_usable_as_a_filter():
    names = [FQDN("a.example.com"), FQDN("b.example.org"), FQDN("c.example.com")]
    zone = FQDN("example.com")
    assert [str(n) for n in names if n in zone] == ["a.example.com", "c.example.com"]


# --------------------------------------------------------------------------- #
# Text interop                                                                 #
# --------------------------------------------------------------------------- #


def test_str_gives_the_name():
    assert str(FQDN("www.example.com")) == "www.example.com"
    assert str(FQDN("www.example.com.")) == "www.example.com."
    assert "{}".format(FQDN("example.com")) == "example.com"
    assert "%s:443" % (FQDN("example.com"),) == "example.com:443"


def test_addition_with_a_string_gives_a_string():
    f = FQDN("example.com")
    assert f + "/health" == "example.com/health"
    assert isinstance(f + "/health", str)
    assert "https://" + f == "https://example.com"
    assert isinstance("https://" + f, str)
    # A fully qualified name contributes its dot, because + is text.
    assert FQDN("example.com.") + "/x" == "example.com./x"


def test_adding_two_names_raises_and_names_the_operator_that_works():
    """Text-concatenating two names gives garbage, so it is refused."""
    with pytest.raises(TypeError, match="to compose"):
        FQDN("www") + FQDN("example.com")


def test_adding_a_non_string_is_a_type_error():
    with pytest.raises(TypeError):
        FQDN("example.com") + 42
    with pytest.raises(TypeError):
        42 + FQDN("example.com")


# --------------------------------------------------------------------------- #
# Presentation and classification                                              #
# --------------------------------------------------------------------------- #


def test_unicode_decodes_punycode_for_display():
    """Labels are stored ASCII; this is the other direction, for humans."""
    assert FQDN("münchen.de").to_unicode() == "münchen.de"
    assert str(FQDN("münchen.de")) == "xn--mnchen-3ya.de"
    # Either spelling in gives the same pair out.
    assert FQDN("xn--mnchen-3ya.de").to_unicode() == "münchen.de"
    assert FQDN("example.com").to_unicode() == "example.com"
    assert FQDN("münchen.de.").to_unicode() == "münchen.de."


def test_unicode_passes_through_undecodable_punycode():
    """A display helper that raises is worse than one showing the stored form."""
    name = FQDN._from_labels(("xn--", "com"), False)
    assert name.to_unicode() == "xn--.com"


@pytest.mark.parametrize(
    "name, expected",
    [
        ("www.example.com", True),
        ("a-b.example.com", True),
        ("123.example.com", True),
        ("_dmarc.example.com", False),
        ("_sip._tcp.example.com", False),
        ("*.example.com", False),
        ("-bad.example.com", False),
        ("bad-.example.com", False),
    ],
)
def test_is_hostname_is_narrower_than_what_the_type_accepts(name, expected):
    """RFC 1123 LDH, reported rather than enforced.

    Underscore names are real and common -- SRV, DMARC, ACME -- so rejecting
    them at construction would make the type useless for that work. The
    constructor takes the broad DNS rule; this reports the narrow host rule.
    """
    assert FQDN(name).is_hostname() is expected
    # All of them are still valid names.
    assert FQDN.is_valid(name)


def test_is_wildcard_is_a_predicate_only():
    """No ``matches()``: DNS (RFC 4592) and TLS (RFC 6125) disagree on whether
    ``*.example.com`` covers ``a.b.example.com``, so choosing one silently would
    be wrong for half of callers."""
    assert FQDN("*.example.com").is_wildcard
    assert not FQDN("www.example.com").is_wildcard
    assert not hasattr(FQDN("*.example.com"), "matches")


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("a.example.com", "b.example.com", "example.com"),
        ("a.b.example.com", "c.d.example.com", "example.com"),
        ("www.example.com", "example.com", "example.com"),
        ("a.com", "b.com", "com"),
        ("example.com", "example.org", None),
    ],
)
def test_common_ancestor(a, b, expected):
    result = FQDN(a).common_ancestor(b)
    assert result == (FQDN(expected) if expected else None)


def test_common_ancestor_is_symmetric_in_labels():
    a, b = FQDN("x.example.com"), FQDN("y.example.com")
    assert a.common_ancestor(b).labels == b.common_ancestor(a).labels


# --------------------------------------------------------------------------- #
# Wire form                                                                    #
# --------------------------------------------------------------------------- #


def test_wire_encoding_delegates_to_the_packages_own_encoder():
    """So it cannot drift from what ``resolve_wire`` actually sends."""
    from netimps import _dnswire

    assert FQDN("www.example.com").encode() == b"\x03www\x07example\x03com\x00"
    assert FQDN("www.example.com").encode() == _dnswire.encode_name("www.example.com")


def test_wire_is_always_absolute():
    """There is no relative wire form, so the root terminator is unconditional."""
    assert FQDN("example.com").encode() == FQDN("example.com.").encode()
    assert FQDN("example.com").encode().endswith(b"\x00")


def test_wire_length_explains_the_253_vs_255_gap():
    """The printable limit is 253; the wire limit is 255.

    The difference is one length prefix per label plus the root terminator,
    which is exactly what this exposes.
    """
    f = FQDN("www.example.com")
    assert len(str(f)) == 15
    assert f.wire_length == 17
    assert f.wire_length == len(str(f)) + 2
    assert FQDN("a").wire_length == 3
