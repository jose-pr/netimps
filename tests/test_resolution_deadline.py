"""``deadline=`` bounds a whole resolution, and ``ping`` bounds its own lookup.

``timeout`` is one attempt and each backend reads it differently (dnspython and
the wire backend: the whole backend call; the OS resolver and nslookup: each
candidate name), so a chain of backends, a record-type pair and a search list
could each multiply it. ``deadline`` is the total for the call.
"""

import socket
import threading
import time

import pytest

import netimps
from netimps import (
    FQDN,
    Host,
    ResolutionError,
    ResolutionTimeoutError,
    _dns,
    _ping,
    resolve,
)

from fakedns import PortPairUnavailable, make_nameserver


@pytest.fixture
def two_silent(server):
    """Two nameservers that never answer ``silent.test``."""
    try:
        second = make_nameserver()
    except PortPairUnavailable as exc:  # pragma: no cover
        pytest.skip(str(exc))
    yield [
        "127.0.0.1:%d" % server.port,
        "127.0.0.1:%d" % second.port,
    ]
    second.close()


def test_a_deadline_bounds_two_silent_servers(two_silent):
    """``timeout`` alone would wait 5 s on each."""
    started = time.perf_counter()
    got = resolve(
        "silent.test", ns=two_silent, backends="wire", timeout=5.0, deadline=1.0
    )
    elapsed = time.perf_counter() - started
    assert got == []
    assert elapsed < 1.2, "took %.2fs for deadline=1.0" % (elapsed,)


def test_a_deadline_is_shared_by_every_backend_in_the_chain(two_silent, fake_program):
    """The wire backend uses the whole second, so nslookup is never started."""
    fake = fake_program("nslookup", hang=True)
    started = time.perf_counter()
    with pytest.raises(ResolutionTimeoutError):
        resolve(
            "silent.test",
            ns=two_silent,
            backends=["wire", "nslookup"],
            timeout=5.0,
            deadline=1.0,
            strict=True,
        )
    assert time.perf_counter() - started < 1.3
    assert fake.calls == []


def test_dnspython_is_cut_off_by_the_deadline(server):
    pytest.importorskip("dns.resolver")
    started = time.perf_counter()
    got = resolve(
        "silent.test",
        ns="127.0.0.1",
        port=server.port,
        backends="dnspython",
        search=False,
        timeout=5.0,
        deadline=0.6,
    )
    assert got == []
    assert time.perf_counter() - started < 1.2


@pytest.fixture
def hung_getaddrinfo(monkeypatch):
    released = threading.Event()

    def hang(*args, **kwargs):
        released.wait(30.0)
        return []

    monkeypatch.setattr(_dns._system._socket, "getaddrinfo", hang)
    yield
    released.set()


def test_a_search_list_is_not_one_timeout_per_candidate(hung_getaddrinfo):
    """Four candidates at ``timeout=5`` would be twenty seconds."""
    started = time.perf_counter()
    with pytest.raises(ResolutionTimeoutError):
        resolve(
            "host",
            backends="system",
            search=["a.test", "b.test", "c.test"],
            timeout=5.0,
            deadline=0.5,
            strict=True,
        )
    assert time.perf_counter() - started < 1.0


def test_a_record_type_pair_shares_the_deadline(server):
    """``("a", "aaaa")`` is two attempts; both are inside the one deadline."""
    started = time.perf_counter()
    got = resolve(
        "silent.test",
        ("a", "aaaa"),
        ns="127.0.0.1:%d" % server.port,
        backends="wire",
        timeout=5.0,
        deadline=0.6,
    )
    assert got == []
    assert time.perf_counter() - started < 1.2


def test_the_deadline_does_not_outlive_the_call(server):
    resolve("host.test", ns="127.0.0.1:%d" % server.port, backends="wire", deadline=5)
    assert _dns._common._DEADLINE.get() is None
    with pytest.raises(ResolutionError):
        resolve(
            "silent.test",
            ns="127.0.0.1:%d" % server.port,
            backends="wire",
            deadline=0.3,
            strict=True,
        )
    assert _dns._common._DEADLINE.get() is None


def test_a_deadline_that_is_not_hit_changes_nothing(server):
    got = resolve(
        "host.test", ns="127.0.0.1:%d" % server.port, backends="wire", deadline=10
    )
    assert got == [netimps.parse("10.0.0.5")]


def test_host_and_fqdn_take_a_deadline(two_silent):
    options = dict(ns=two_silent, backends="wire", timeout=5.0, deadline=0.5)
    for name, call in (
        ("Host.ip", lambda **kw: Host("silent.test").ip(**kw)),
        ("FQDN.ip", lambda **kw: FQDN("silent.test").ip(**kw)),
        ("Host.resolve", lambda **kw: Host("silent.test").resolve(**kw)),
        ("FQDN.resolve", lambda **kw: FQDN("silent.test").resolve(**kw)),
    ):
        started = time.perf_counter()
        call(**options)
        assert time.perf_counter() - started < 1.2, name
    with pytest.raises(ResolutionTimeoutError):
        Host("silent.test").ip(check=True, **options)
    started = time.perf_counter()
    assert Host("192.0.2.9").fqdn(**options) is None
    assert time.perf_counter() - started < 1.2


# --------------------------------------------------------------------------- #
# ping                                                                        #
# --------------------------------------------------------------------------- #


def _closed_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_ping_bounds_its_own_name_lookup_by_timeout(monkeypatch):
    """Measured on ec35558: 2.5 s for ``timeout=0.5`` with a 2 s lookup."""
    real = socket.getaddrinfo

    def slow(*args, **kwargs):
        time.sleep(2.0)
        return real("127.0.0.1", *args[1:], **kwargs)

    monkeypatch.setattr(_ping._probe._socket, "getaddrinfo", slow)
    started = time.perf_counter()
    result = netimps.ping("localhost", method="tcp", port=_closed_port(), timeout=0.5)
    assert time.perf_counter() - started < 1.0
    assert not result


def test_the_icmp_lookup_is_bounded_too(monkeypatch, fake_program):
    fake_program("ping", stdout="Reply from 127.0.0.1: bytes=32 time=1ms TTL=128\n")
    real = socket.getaddrinfo

    def slow(*args, **kwargs):
        time.sleep(6.0)
        return real("127.0.0.1", *args[1:], **kwargs)

    monkeypatch.setattr(_ping._probe._socket, "getaddrinfo", slow)
    started = time.perf_counter()
    netimps.ping("localhost", timeout=0.5)
    # The lookup's 0.5 s, plus a fake program's start: well short of the 6 s
    # an unbounded lookup takes, with room for a slow host.
    assert time.perf_counter() - started < 4.0


@pytest.mark.parametrize(
    "dst,answers,ipv6,expected",
    [
        ("::1", [], None, True),
        ("127.0.0.1", [], None, False),
        ("localhost", ["::1"], None, True),
        ("localhost", ["127.0.0.1"], None, False),
        ("::1", [], False, False),
        ("127.0.0.1", [], True, True),
    ],
)
def test_the_family_of_src_follows_the_destination(
    monkeypatch, dst, answers, ipv6, expected
):
    """A literal ``dst`` decides for itself, so ``::1`` asks for a v6 source.

    Measured on ec35558: ``ping("::1", src=<loopback Interface>)`` pinned the
    interface's IPv4 address as the source of an IPv6 probe and was falsy.
    """
    asked = []

    def fake_source(src, want_ipv6, strict):
        asked.append(want_ipv6)
        return None  # no usable address: ping returns before it spawns anything

    monkeypatch.setattr(_ping._run, "_interface_address", fake_source)
    monkeypatch.setattr(
        _ping._probe._socket,
        "getaddrinfo",
        lambda host, *a, **k: [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (address, 0),
            )
            for address in answers
        ],
    )
    netimps.ping(dst, src="127.0.0.1", ipv6=ipv6)
    assert asked == [expected]
