"""Suite-wide guards.

The repo's ``AGENTS.md`` has always said "tests must never hit the network".
That was aspirational: a review on 2026-09-20 measured eleven off-host
lookups, including three for the developer's own hostname. None of them
changed an assertion *on that machine* -- but simulating a wildcard resolver
(the kind many ISP and corporate networks run, which answers every name)
turned the suite red, because several tests assert that a name does **not**
resolve.

So the invariant is enforced here rather than trusted. Any test that reaches
the resolver for a non-local name now fails loudly, at the point of the call,
naming itself -- instead of passing until it meets an unusual network.

A test that genuinely needs a resolution result fakes it, as the DNS tests
already do. A test that needs the guard lifted asks for the ``allow_resolver``
fixture, which documents itself in the test body.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

#: Names answered from the host's own configuration rather than a name server.
_LOCAL_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "", "0.0.0.0", "::", "::1"}
)


def _is_local(host: object) -> bool:
    """True when resolving ``host`` cannot reach a name server.

    Two cases, and the second is easy to get wrong. ``localhost`` and friends
    come out of the hosts file. And an **address literal is not a lookup at
    all** -- ``getaddrinfo("1.1.1.1", ...)`` parses four numbers and returns;
    no packet leaves the machine, and no resolver has an opinion about it. A
    guard that blocks those is not enforcing "never hit the network", it is
    blocking arithmetic, and it would push tests into mocking things that were
    never remote.

    Everything else is a question for somebody else's machine.
    """
    if host is None:
        return True
    text = str(host)
    if text in _LOCAL_NAMES:
        return True
    try:
        ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    return True


class ResolverEscape(AssertionError):
    """A test asked the resolver about a name it does not own.

    Raised instead of returning an answer, because a silent answer is exactly
    what makes this class of flake invisible: the test passes here and fails on
    a network whose resolver has a different opinion.
    """


@pytest.fixture(autouse=True)
def _no_off_host_resolution(request, monkeypatch):
    """Fail any off-host name resolution for the duration of each test."""
    # Both opt-outs step aside explicitly rather than relying on which fixture
    # happens to patch last.
    if {"allow_resolver", "no_such_host"} & set(request.fixturenames):
        return

    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname = socket.gethostbyname
    real_gethostbyaddr = socket.gethostbyaddr
    test_id = request.node.nodeid

    def guard(name, real, host, *args, **kwargs):
        if not _is_local(host):
            raise ResolverEscape(
                "%s called socket.%s(%r); tests must never hit the network. "
                "Fake the lookup, or request the `allow_resolver` fixture and "
                "say in the test why the real resolver is needed."
                % (test_id, name, host)
            )
        return real(host, *args, **kwargs)

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *a, **k: guard("getaddrinfo", real_getaddrinfo, host, *a, **k),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda host, *a, **k: guard("gethostbyname", real_gethostbyname, host, *a, **k),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda host, *a, **k: guard("gethostbyaddr", real_gethostbyaddr, host, *a, **k),
    )


@pytest.fixture
def allow_resolver():
    """Opt out of :func:`_no_off_host_resolution` for one test.

    Requesting it is the documentation: it marks the test as one that depends
    on the host's resolver, so the next person reading a failure knows the
    network is a suspect.
    """
    return True


@pytest.fixture
def no_such_host(monkeypatch):
    """Make every off-host name fail to resolve, deterministically.

    A surprising number of tests here mean "given a name that does not
    resolve..." and get it by picking something in ``.invalid`` and trusting
    the resolver to say NXDOMAIN. That works until it meets a resolver that
    answers everything -- the wildcard/NXDOMAIN-hijacking kind many ISP and
    corporate networks run -- and then the assertion inverts. It is not a
    hypothetical: simulating one turned ``test_addr_rejects_nonsense`` red,
    because the CLI decided a nonsense string was a hostname.

    Requesting this fixture says "the name not resolving is the precondition",
    and makes it true regardless of whose network the tests run on.
    """
    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname = socket.gethostbyname
    real_gethostbyaddr = socket.gethostbyaddr

    def fail(name, real, host, *args, **kwargs):
        if _is_local(host):
            return real(host, *args, **kwargs)
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *a, **k: fail("getaddrinfo", real_getaddrinfo, host, *a, **k),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda host, *a, **k: fail("gethostbyname", real_gethostbyname, host, *a, **k),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda host, *a, **k: fail("gethostbyaddr", real_gethostbyaddr, host, *a, **k),
    )
    return True
