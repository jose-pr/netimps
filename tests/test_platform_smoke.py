"""Non-mocked checks against the platform's own binaries, loopback only.

**Nothing in this file may be mocked.** That is the entire point of it.

Every other ping test in this suite fakes ``subprocess.run`` and then asserts
the argv the library *builds*. That is a useful thing to assert, and it is also
how macOS shipped broken for months while CI stayed green: the suite happily
confirmed that ``ping(ipv6=True)`` puts ``-6`` in the argv, and macOS ``ping``
answers ``invalid option -- 6`` and exits 64. An assertion about our own
argv can never catch a flag the platform does not have.

So these tests run the real binary. They are deliberately confined to
loopback -- ``127.0.0.1``, ``::1``, ``localhost`` -- so they send no packet off
the host and depend on no name server, which keeps them compatible with the
"tests must never hit the network" invariant in the repo's ``AGENTS.md``.

If one of these fails, the library is genuinely broken on that platform. Do not
mock it to make it pass.
"""

from __future__ import annotations

import shutil
import socket

import pytest

import netimps

pytestmark = pytest.mark.skipif(
    shutil.which("ping") is None,
    reason="no ping binary on PATH; nothing to smoke-test against",
)


def _has_ipv6_loopback() -> bool:
    """True when ``::1`` is actually usable on this host.

    Some containers are built without IPv6. Binding is the cheap proof, and it
    avoids skipping on a host where v6 works but the first ping happens to fail
    -- which is the failure this file exists to surface.
    """
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))
        return True
    except OSError:
        return False


needs_ipv6 = pytest.mark.skipif(
    not _has_ipv6_loopback(), reason="host has no usable IPv6 loopback"
)


def test_ping_ipv4_loopback_answers():
    result = netimps.ping("127.0.0.1")
    assert result, "the platform ping binary did not confirm 127.0.0.1"
    assert result.rtt_ms is not None, "a loopback reply must carry an RTT"


def test_ping_ipv4_loopback_with_explicit_family():
    """``ipv6=False`` must not be the thing that breaks a working ping.

    macOS ``ping`` has no ``-4`` flag at all -- it exits 64 -- so asking
    explicitly for the family the destination already is used to be enough to
    turn a healthy ping falsy.
    """
    assert netimps.ping("127.0.0.1", ipv6=False)


@needs_ipv6
def test_ping_ipv6_loopback_answers():
    """macOS reaches IPv6 through a separate ``ping6`` binary, not ``ping -6``."""
    assert netimps.ping("::1")


@needs_ipv6
def test_ping_ipv6_loopback_with_explicit_family():
    assert netimps.ping("::1", ipv6=True)


def test_ping_localhost_by_name():
    """Resolution of ``localhost`` is local (hosts file/NSS), not a lookup."""
    assert netimps.ping("localhost")


def test_ping_honours_an_explicit_source_address():
    """``src=`` must pin the source, not fail.

    BSD spells this ``-S``; ``-I`` is multicast-only there and is rejected with
    "-I, -L, -T flags cannot be used with unicast destination".
    """
    assert netimps.ping("127.0.0.1", src="127.0.0.1")


def test_ping_accepts_a_ttl():
    """``ttl=`` must not be silently reinterpreted.

    BSD ``-t`` is an overall deadline and ``-m`` is the hop limit; Linux is the
    other way round, and Linux ``-m`` is a firewall mark. A TTL large enough to
    reach loopback must simply succeed on all three.
    """
    assert netimps.ping("127.0.0.1", ttl=64)


def test_ping_reports_a_ttl_for_a_loopback_reply():
    """BSD ``ping6`` prints ``hlim=``, not ``ttl=``.

    Windows does not report a hop limit for IPv6 at all, so this only asserts
    the v4 case, where every platform prints one.
    """
    assert netimps.ping("127.0.0.1").ttl is not None


def test_ping_rejects_a_flag_shaped_destination():
    """A destination that is really an option is a caller bug, not a down host.

    Windows ``ping -?`` prints usage and exits 0. Because nothing resolves, the
    reply-address check used to be skipped entirely and the bare exit code was
    taken as proof of a reply -- so ``ping('-?')`` came back **truthy** for a
    host that was never contacted.

    It raises now rather than returning falsy, for the same reason ``resolve``
    raises on a malformed query: a typo'd destination should not be
    indistinguishable from an unreachable one.
    """
    for destination in ("-?", "-h", "--help", "-n", "-c"):
        with pytest.raises(ValueError, match="option"):
            netimps.ping(destination)


def test_ping_still_reports_an_empty_destination_as_falsy():
    """``ping("")`` stays falsy -- that contract predates the flag check."""
    assert not netimps.ping("")


def test_tcp_probe_reaches_loopback():
    """``method="tcp"`` against a real listener, with no fakes in the way."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        assert netimps.ping("127.0.0.1", method="tcp", port=port)


@needs_ipv6
def test_tcp_probe_reaches_ipv6_loopback():
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
        server.bind(("::1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        assert netimps.ping("::1", method="tcp", port=port)
