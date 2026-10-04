"""An outage is not an empty answer, in every resolver backend.

A resolver that could not be asked (a silent server, a SERVFAIL, a temporary
``getaddrinfo`` failure, ``nslookup`` printing "No response from server") raises
``ResolutionError`` or ``ResolutionTimeoutError``; a resolver that answered "no
such name" or "no record of that type" returns ``[]``. The two used to look the
same from the dnspython, system and (on Windows) nslookup backends, so
``strict=True`` could not raise and ``cache=`` stored the outage.

dnspython runs for real against the fake nameserver on loopback; the OS resolver
is replaced where it meets the process (``getaddrinfo``), and ``nslookup`` is a
fake program on ``PATH``.
"""

import socket
import sys

import pytest

import netimps
from netimps import (
    IPv4Address,
    ResolutionError,
    ResolutionTimeoutError,
    _dns,
    clear_resolution_cache,
    resolve,
    resolve_dnspython,
    resolve_nslookup,
    resolve_system,
)

dns_resolver = pytest.importorskip("dns.resolver")


@pytest.fixture(autouse=True)
def _empty_cache():
    clear_resolution_cache()
    yield
    clear_resolution_cache()


def ns(server):
    return "127.0.0.1:%d" % server.port


def dnspython(server, name, rdtype="a", **kwargs):
    return resolve_dnspython(
        name,
        rdtype,
        ns="127.0.0.1",
        port=server.port,
        search=False,
        timeout=kwargs.pop("timeout", 2.0),
        **kwargs,
    )


def gai_error(code):
    def fail(*args, **kwargs):
        raise socket.gaierror(code, "scripted")

    return fail


# --------------------------------------------------------------------------- #
# dnspython                                                                   #
# --------------------------------------------------------------------------- #


def test_dnspython_answers_no_such_name_and_no_such_record_with_empty(server):
    assert dnspython(server, "missing.test") == []
    assert dnspython(server, "host.test", "mx") == []


def test_dnspython_raises_a_timeout_for_a_silent_server(server):
    """Measured on ec35558: ``[]`` for a server that never answered."""
    with pytest.raises(ResolutionTimeoutError):
        dnspython(server, "silent.test", timeout=0.5)


def test_dnspython_raises_when_every_server_fails(server):
    """SERVFAIL from the only server is ``NoNameservers`` in dnspython."""
    with pytest.raises(ResolutionError) as caught:
        dnspython(server, "broken.test")
    assert not isinstance(caught.value, ResolutionTimeoutError)


def test_dnspython_raises_when_there_is_no_resolver_configuration(monkeypatch):
    """The constructor raising used to escape ``resolve()`` as dnspython's own class."""

    def no_configuration(self, *args, **kwargs):
        raise dns_resolver.NoResolverConfiguration("no resolv.conf")

    monkeypatch.setattr(dns_resolver.Resolver, "__init__", no_configuration)
    with pytest.raises(ResolutionError, match="no resolv.conf"):
        resolve_dnspython("host.test", "a")
    with pytest.raises(ResolutionError, match="no resolv.conf"):
        resolve("host.test", "a", backends="dnspython", strict=True)


def test_the_system_search_list_is_empty_without_resolver_configuration(monkeypatch):
    def no_configuration(self, *args, **kwargs):
        raise dns_resolver.NoResolverConfiguration("no resolv.conf")

    monkeypatch.setattr(dns_resolver.Resolver, "__init__", no_configuration)
    assert _dns._system_search_domains() == []


def test_dnspython_does_not_rewrite_a_programming_error(monkeypatch):
    """Everything was a ``ValueError("invalid DNS query")``, an ``AssertionError`` too."""

    def broken(self, *args, **kwargs):
        raise AssertionError("a bug in the caller's patch")

    monkeypatch.setattr(dns_resolver.Resolver, "resolve", broken)
    with pytest.raises(AssertionError, match="a bug"):
        resolve_dnspython("host.test", "a", ns="127.0.0.1", search=False)


def test_dnspython_maps_an_os_error_to_a_resolution_error(monkeypatch):
    def refused(self, *args, **kwargs):
        raise OSError(99, "cannot assign the requested address")

    monkeypatch.setattr(dns_resolver.Resolver, "resolve", refused)
    with pytest.raises(ResolutionError, match="cannot assign"):
        resolve_dnspython("host.test", "a", ns="127.0.0.1", search=False)


def test_dnspython_still_refuses_a_malformed_name_and_an_unknown_type(server):
    with pytest.raises(ValueError, match="invalid DNS query"):
        dnspython(server, "a..b")
    with pytest.raises(ValueError, match="invalid DNS query"):
        dnspython(server, "host.test", "bogus")


# --------------------------------------------------------------------------- #
# The missing extra                                                           #
# --------------------------------------------------------------------------- #


@pytest.fixture
def no_dnspython(monkeypatch):
    for name in ("dns", "dns.resolver", "dns.name", "dns.exception"):
        monkeypatch.setitem(sys.modules, name, None)


def test_has_dns_says_whether_the_extra_is_installed(no_dnspython):
    assert _dns.has_dns() is False


def test_has_dns_is_true_where_dnspython_is_installed():
    assert _dns.has_dns() is True


def test_the_missing_extra_is_named_where_it_is_used(no_dnspython):
    with pytest.raises(ResolutionError, match=r"netimps\[dns\]"):
        resolve_dnspython("host.test", "a")


def test_a_record_type_only_dnspython_serves_raises_when_it_is_missing(no_dnspython):
    """``[]`` said "no such record" for a backend that was never there."""
    with pytest.raises(ResolutionError, match=r"netimps\[dns\]"):
        resolve("mail.test", "mx", backends=["dnspython"])
    with pytest.raises(ResolutionError, match=r"netimps\[dns\]"):
        resolve("host.test", "bogus", backends=["dnspython", "system"])


def test_an_address_lookup_falls_back_without_the_extra(no_dnspython, monkeypatch):
    monkeypatch.setattr(
        _dns._socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, 0, 0, "", ("10.0.0.5", 0))],
    )
    assert resolve("host.test", backends=["dnspython", "system"]) == [
        IPv4Address("10.0.0.5")
    ]


def test_the_wire_backend_serves_a_record_type_without_the_extra(no_dnspython, server):
    assert resolve("mail.test", "mx", ns=ns(server)) == ["10 mx.mail.test"]


# --------------------------------------------------------------------------- #
# The OS resolver                                                             #
# --------------------------------------------------------------------------- #


def test_the_system_backend_answers_no_such_name_with_empty(monkeypatch):
    monkeypatch.setattr(_dns._socket, "getaddrinfo", gai_error(socket.EAI_NONAME))
    assert resolve_system("nothere.test", "a") == []


@pytest.mark.parametrize("code", [getattr(socket, "EAI_AGAIN"), socket.EAI_FAIL])
def test_the_system_backend_raises_for_a_temporary_failure(monkeypatch, code):
    """Measured on ec35558: ``[]`` for ``EAI_AGAIN``."""
    monkeypatch.setattr(_dns._socket, "getaddrinfo", gai_error(code))
    with pytest.raises(ResolutionError, match="scripted"):
        resolve_system("host.test", "a")


def test_a_reverse_lookup_tells_no_record_from_a_failure(monkeypatch):
    def host_not_found(address):
        raise socket.herror(1, "Unknown host")

    monkeypatch.setattr(_dns._socket, "gethostbyaddr", host_not_found)
    assert resolve_system("192.0.2.9", "ptr") == []

    def try_again(address):
        raise socket.herror(2, "Host name lookup failure")

    monkeypatch.setattr(_dns._socket, "gethostbyaddr", try_again)
    with pytest.raises(ResolutionError, match="Host name lookup failure"):
        resolve_system("192.0.2.9", "ptr")


def test_strict_raises_for_a_system_outage_and_the_default_answers_empty(monkeypatch):
    monkeypatch.setattr(_dns._socket, "getaddrinfo", gai_error(socket.EAI_AGAIN))
    assert resolve("host.test", "a", backends="system", search=False) == []
    with pytest.raises(ResolutionError):
        resolve("host.test", "a", backends="system", search=False, strict=True)


def test_an_outage_is_not_cached(monkeypatch):
    calls = []

    def fail(*args, **kwargs):
        calls.append(args)
        raise socket.gaierror(socket.EAI_AGAIN, "scripted")

    monkeypatch.setattr(_dns._socket, "getaddrinfo", fail)
    for _ in range(2):
        assert resolve("host.test", "a", backends="system", cache=True) == []
    assert len(calls) == 2, "the second lookup was answered from the cache"


def test_a_name_that_does_not_exist_is_still_cached(monkeypatch):
    calls = []

    def missing(*args, **kwargs):
        calls.append(args)
        raise socket.gaierror(socket.EAI_NONAME, "scripted")

    monkeypatch.setattr(_dns._socket, "getaddrinfo", missing)
    for _ in range(2):
        assert resolve("host.test", "a", backends="system", cache=True) == []
    assert len(calls) == 1


def test_an_outage_through_dnspython_is_not_cached(server):
    for _ in range(2):
        assert (
            resolve(
                "silent.test",
                "a",
                ns="127.0.0.1",
                port=server.port,
                backends="dnspython",
                timeout=0.4,
                search=False,
                cache=True,
            )
            == []
        )
    assert len(server.peers) >= 2, "the second lookup never reached the server"


# --------------------------------------------------------------------------- #
# nslookup                                                                    #
# --------------------------------------------------------------------------- #

#: Windows against a server that does not answer: exit 0, on standard output.
_WINDOWS_NO_RESPONSE = (
    b"Server:  UnKnown\r\nAddress:  127.0.0.1\r\n\r\n"
    b"DNS request timed out.\r\n    timeout was 2 seconds.\r\n"
    b"*** UnKnown can't find host.test.: No response from server\r\n"
)


def test_nslookup_reads_no_response_from_server_as_an_outage(fake_program):
    """The marker "can't find" is shared by "no such name" and by this."""
    fake_program("nslookup", stdout=_WINDOWS_NO_RESPONSE)
    with pytest.raises(ResolutionError, match="No response from server"):
        resolve_nslookup("host.test", search=False)
    with pytest.raises(ResolutionError):
        resolve(
            "host.test",
            "a",
            ns="127.0.0.1",
            backends="nslookup",
            search=False,
            strict=True,
        )


@pytest.mark.parametrize(
    "reason", ["SERVFAIL", "REFUSED", "No response from server", "Query refused"]
)
def test_nslookup_reads_a_failure_after_the_colon_as_an_outage(fake_program, reason):
    fake_program(
        "nslookup",
        stderr=("** server can't find host.test: %s\n" % reason).encode(),
        returncode=1,
    )
    with pytest.raises(ResolutionError, match=reason):
        resolve_nslookup("host.test", search=False)


@pytest.mark.parametrize(
    "line",
    [
        "** server can't find host.test: NXDOMAIN",
        "*** UnKnown can't find host.test: Non-existent domain",
        "*** Can't find host.test: No answer",
    ],
)
def test_nslookup_reads_no_such_name_and_no_such_record_as_empty(fake_program, line):
    fake_program("nslookup", stderr=(line + "\n").encode(), returncode=1)
    assert resolve_nslookup("host.test", search=False) == []
