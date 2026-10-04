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
        retry(attempt, attempts=3, delay=0.0, jitter=0.0, _sleep=lambda s: None)
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
            _sleep=lambda s: None,
        )
    assert len(calls) == 1


def test_a_passed_deadline_is_not_rewritten_by_the_dnspython_socket_handler():
    """The deadline is a ``ResolutionTimeoutError``, which is an ``OSError``
    now; the handler for socket failures must not turn it into a plain
    ``ResolutionError``."""
    pytest.importorskip("dns.resolver")
    token = _dns._DEADLINE.set(time.monotonic() - 1.0)
    try:
        with pytest.raises(ResolutionTimeoutError, match="deadline"):
            resolve_dnspython("host.test", "a", ns="127.0.0.1", search=False)
    finally:
        _dns._DEADLINE.reset(token)
