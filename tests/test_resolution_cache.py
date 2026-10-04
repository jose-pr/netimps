"""``cache=`` on ``resolve()``, ``Host`` and ``FQDN``.

Two repositories kept their own resolution cache with a TTL, one of them
without negative caching, so a name that does not resolve was asked on every
packet. Each test counts the runs of a fake ``nslookup`` on ``PATH``: the real
spawn and parse path, no patching, and a count that does not depend on timing.
"""

import pytest

import netimps
from netimps import (
    FQDN,
    RESOLUTION_CACHE_TTL,
    Host,
    IPv4Address,
    ResolutionError,
    clear_resolution_cache,
    resolve,
)

_ANSWER = (
    b"Server:\t\t192.0.2.53\nAddress:\t192.0.2.53#53\n\n"
    b"Non-authoritative answer:\n"
    b"Name:\texample.com\nAddress: 104.20.23.154\n"
)
_MISSING = "** server can't find nothere.example: NXDOMAIN\n"
_OUTAGE = "connection timed out; no servers could be reached"

#: One backend and no search list, so one resolve is exactly one program run.
ONE = dict(backends="nslookup", search=False)


@pytest.fixture(autouse=True)
def _empty_cache():
    clear_resolution_cache()
    yield
    clear_resolution_cache()


def test_the_default_is_never_to_cache(fake_program):
    """A caller's own cache was the only way to avoid asking twice."""
    fake = fake_program("nslookup", stdout=_ANSWER)
    resolve("example.com", "a", **ONE)
    resolve("example.com", "a", **ONE)
    assert len(fake.calls) == 2


def test_two_cached_lookups_make_one_backend_call(fake_program):
    fake = fake_program("nslookup", stdout=_ANSWER)
    first = resolve("example.com", "a", cache=True, **ONE)
    second = resolve("example.com", "a", cache=True, **ONE)
    assert first == second == [IPv4Address("104.20.23.154")]
    assert len(fake.calls) == 1


def test_a_cached_answer_is_a_copy(fake_program):
    fake_program("nslookup", stdout=_ANSWER)
    first = resolve("example.com", "a", cache=True, **ONE)
    first.append("corrupt")
    assert resolve("example.com", "a", cache=True, **ONE) == [
        IPv4Address("104.20.23.154")
    ]


def test_the_second_of_two_missed_lookups_makes_none(fake_program):
    """Negative caching: an empty answer is cached like any other."""
    fake = fake_program("nslookup", stdout=_MISSING, returncode=1)
    assert resolve("nothere.example", "a", cache=True, **ONE) == []
    assert resolve("nothere.example", "a", cache=True, **ONE) == []
    assert len(fake.calls) == 1


def test_a_changed_option_is_a_different_entry(fake_program):
    fake = fake_program("nslookup", stdout=_ANSWER)
    resolve("example.com", "a", cache=True, **ONE)
    resolve("example.com", "aaaa", cache=True, **ONE)
    resolve("example.com", "a", cache=True, ns="192.0.2.53", **ONE)
    resolve("example.com", "a", cache=True, timeout=2.0, **ONE)
    assert len(fake.calls) == 4
    resolve("example.com", "a", cache=True, ns="192.0.2.53", **ONE)
    assert len(fake.calls) == 4


def test_a_name_is_compared_without_case(fake_program):
    fake = fake_program("nslookup", stdout=_ANSWER)
    resolve("example.com", "a", cache=True, **ONE)
    resolve("EXAMPLE.Com", "a", cache=True, **ONE)
    assert len(fake.calls) == 1


def test_clearing_the_cache_asks_again(fake_program):
    fake = fake_program("nslookup", stdout=_ANSWER)
    resolve("example.com", "a", cache=True, **ONE)
    clear_resolution_cache()
    resolve("example.com", "a", cache=True, **ONE)
    assert len(fake.calls) == 2


def test_a_zero_ttl_is_always_stale(fake_program):
    """The same spelling as ``get_interfaces``: a number is the TTL, and zero is
    "refresh"."""
    fake = fake_program("nslookup", stdout=_ANSWER)
    resolve("example.com", "a", cache=0, **ONE)
    resolve("example.com", "a", cache=0, **ONE)
    assert len(fake.calls) == 2


def test_an_outage_is_not_cached_as_an_answer(fake_program):
    """Every backend failing to ask looks like ``[]`` without ``strict``; pinning
    it for a TTL would turn a blip into half a minute of "no such name"."""
    fake = fake_program("nslookup", stderr=_OUTAGE, returncode=1)
    assert resolve("example.com", "a", cache=True, **ONE) == []
    assert resolve("example.com", "a", cache=True, **ONE) == []
    assert len(fake.calls) == 2
    with pytest.raises(ResolutionError):
        resolve("example.com", "a", cache=True, strict=True, **ONE)
    with pytest.raises(ResolutionError):
        resolve("example.com", "a", cache=True, strict=True, **ONE)


def test_host_and_fqdn_share_the_cache(fake_program):
    fake = fake_program("nslookup", stdout=_ANSWER)
    options = dict(cache=True, ipv6=False, **ONE)
    assert Host("example.com").ip(**options) == IPv4Address("104.20.23.154")
    assert FQDN("example.com").ip(**options) == IPv4Address("104.20.23.154")
    assert Host("example.com").resolve(**options)[1] == IPv4Address("104.20.23.154")
    assert FQDN("example.com").resolve(**options)[1] == IPv4Address("104.20.23.154")
    assert len(fake.calls) == 1, "Host.ip asks the same question the others do"


def test_a_host_miss_is_cached_and_check_still_raises(fake_program):
    fake = fake_program("nslookup", stdout=_MISSING, returncode=1)
    host = Host("nothere.example")
    assert host.ip(cache=True, ipv6=False, **ONE) is None
    assert host.ip(cache=True, ipv6=False, **ONE) is None
    with pytest.raises(ResolutionError):
        host.ip(cache=True, ipv6=False, check=True, **ONE)
    assert len(fake.calls) == 2, "the check= call is its own entry; the rest share one"


def test_a_cached_host_call_does_not_write_the_memo(fake_program, monkeypatch):
    """``cache=`` is an option like any other: the per-object memo belongs to the
    call that passes none, which here asks the OS resolver and must get its own
    answer rather than the cached one."""
    import socket

    fake_program("nslookup", stdout=_ANSWER)
    other = ("192.0.2.9", 0)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", other)],
    )
    host = Host("example.com")
    assert host.ip(cache=True, ipv6=False, **ONE) == IPv4Address("104.20.23.154")
    assert host.ip() == IPv4Address("192.0.2.9")


def test_the_ttl_is_exported_as_a_number_of_seconds():
    assert isinstance(RESOLUTION_CACHE_TTL, float) and RESOLUTION_CACHE_TTL > 0
    assert "RESOLUTION_CACHE_TTL" in netimps.__all__
    assert "clear_resolution_cache" in netimps.__all__
