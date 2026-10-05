"""``ResolutionError`` is an ``OSError``; ``NoAnswerError`` is its leaf.

A name lookup that fails is an ``OSError`` in the standard library
(``socket.gaierror``), so a caller who wraps a connect in ``except OSError``
expects it. The leaf says the lookup *completed* and found nothing, which is
what ``retry`` should not repeat.
"""

import socket
import time

import pytest

import netimps

# Private: the resolver package: its seams are patched where they are read and its search orders pinned.
from netimps import (
    FQDN,
    Host,
    NoAnswerError,
    ResolutionError,
    ResolutionTimeoutError,
    _dns,
    resolve_dnspython,
    retry,
)


def test_resolution_error_is_an_os_error():
    assert issubclass(ResolutionError, OSError)
    assert issubclass(ResolutionTimeoutError, OSError)
    assert issubclass(NoAnswerError, ResolutionError)
    assert issubclass(NoAnswerError, netimps.NetimpsError)
    assert str(ResolutionError("could not ask")) == "could not ask"


def test_an_outage_is_caught_by_except_oserror(monkeypatch):
    def down(*args, **kwargs):
        raise socket.gaierror(socket.EAI_AGAIN, "resolver unreachable")

    monkeypatch.setattr(socket, "getaddrinfo", down)
    with pytest.raises(OSError) as caught:
        Host("db.internal").ip(check=True)
    assert type(caught.value) is ResolutionError


def test_check_raises_no_answer_for_a_name_that_does_not_exist(no_such_host):
    with pytest.raises(NoAnswerError, match="x.invalid"):
        Host("x.invalid").ip(check=True)
    with pytest.raises(NoAnswerError):
        FQDN("x.invalid").ip(check=True)
    with pytest.raises(NoAnswerError):
        Host("x.invalid").resolve(check=True)


def test_check_raises_no_answer_for_an_address_with_no_reverse_name(no_such_host):
    with pytest.raises(NoAnswerError, match="reverse"):
        Host("192.0.2.9").fqdn(check=True)


def test_an_outage_under_check_is_not_a_no_answer(monkeypatch):
    def down(*args, **kwargs):
        raise socket.gaierror(socket.EAI_AGAIN, "resolver unreachable")

    monkeypatch.setattr(socket, "getaddrinfo", down)
    with pytest.raises(ResolutionError) as caught:
        FQDN("db.internal").ip(check=True)
    assert not isinstance(caught.value, NoAnswerError)


def test_an_empty_host_is_not_a_lookup_that_completed():
    with pytest.raises(ResolutionError) as caught:
        Host("").ip(check=True)
    assert not isinstance(caught.value, NoAnswerError)


def test_retry_repeats_an_outage_by_default():
    calls = []

    def attempt():
        calls.append(1)
        raise ResolutionError("resolver unreachable")

    with pytest.raises(ResolutionError):
        retry(attempt, attempts=3, delay=0.0, jitter=0.0)
    assert len(calls) == 3


def test_retry_can_leave_out_a_name_that_does_not_exist():
    calls = []

    def attempt():
        calls.append(1)
        raise NoAnswerError("x.invalid has no address record")

    with pytest.raises(NoAnswerError):
        retry(
            attempt,
            attempts=3,
            delay=0.0,
            jitter=0.0,
            retryable=(ConnectionError, TimeoutError),
        )
    assert len(calls) == 1


def test_a_passed_deadline_is_not_rewritten_by_the_dnspython_socket_handler():
    """The deadline is a ``ResolutionTimeoutError``, which is an ``OSError``
    now; the handler for socket failures must not turn it into a plain
    ``ResolutionError``."""
    pytest.importorskip("dns.resolver")
    token = _dns._common._DEADLINE.set(time.monotonic() - 1.0)
    try:
        with pytest.raises(ResolutionTimeoutError, match="deadline"):
            resolve_dnspython("host.test", "a", ns="127.0.0.1", search=False)
    finally:
        _dns._common._DEADLINE.reset(token)


# --------------------------------------------------------------------------- #
# A query that is no name                                                      #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("empty", ["", ".", "  "])
def test_an_empty_query_is_refused_by_every_entry_point(empty):
    """The OS and dnspython applied the search list to an empty name and
    answered with the search domain's own records; ``nslookup`` refused it."""
    for entry in (
        netimps.resolve,
        netimps.resolve_system,
        netimps.resolve_nslookup,
        netimps.resolve_dnspython,
    ):
        with pytest.raises(netimps.NetimpsValueError, match="empty query"):
            entry(empty)
    with pytest.raises(netimps.NetimpsValueError, match="empty query"):
        netimps.resolve_wire(empty, ns="127.0.0.1")
    with pytest.raises(netimps.NetimpsValueError, match="empty query"):
        netimps.resolve_doh(empty, "https://127.0.0.1/dns-query")


@pytest.mark.parametrize("name", ["a..b", "x" * 70 + ".test"])
def test_a_name_the_codec_refuses_is_a_value_error_from_the_os_resolver(
    name, allow_resolver
):
    """It was the codec's own ``UnicodeEncodeError``, from inside
    ``getaddrinfo``. The guard is lifted because the real call is what
    refuses; the codec fails before anything is asked of a resolver."""
    with pytest.raises(netimps.NetimpsValueError, match="not a name that can"):
        netimps.resolve_system(name, search=False)


def test_an_empty_host_still_answers_none():
    """``Host("")`` asks nothing, so the refusal above never reaches it."""
    assert netimps.Host("").ip() is None
    assert netimps.Host(None).ip() is None
