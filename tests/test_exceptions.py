"""The exception hierarchy: the bases each class has, and the one place every
class is defined.

A base that is wrong here is invisible to a caller until an ``except`` clause
they wrote against the builtin (or against the package base) stops matching.
"""

import copy
import errno
import pickle
import socket
import struct
import threading
from pathlib import Path

import pytest

import netimps

# Private: the resolver package: its seams are patched where they are read and its search orders pinned.
from netimps import (
    AddressInUseError,
    DeviceBindingUnsupportedError,
    DNSDecodeError,
    NetimpsError,
    NetimpsValueError,
    NoAnswerError,
    ResolutionError,
    ResolutionTimeoutError,
    _dns,
)

# Private: the name codec under test.
from netimps._fqdn import _wire as _namewire

#: Each class with its direct bases, in declaration order.
_BASES = [
    (NetimpsError, (Exception,)),
    (NetimpsValueError, (NetimpsError, ValueError)),
    (ResolutionError, (NetimpsError, OSError)),
    (NoAnswerError, (ResolutionError,)),
    (ResolutionTimeoutError, (ResolutionError, TimeoutError)),
    (DNSDecodeError, (NetimpsValueError,)),
    (AddressInUseError, (NetimpsError, OSError)),
    (DeviceBindingUnsupportedError, (NetimpsError, OSError)),
]
_IDS = [cls.__name__ for cls, _ in _BASES]


@pytest.mark.parametrize("cls, bases", _BASES, ids=_IDS)
def test_each_exception_has_exactly_its_documented_bases(cls, bases):
    """A dropped builtin co-parent (``ValueError``, ``TimeoutError``,
    ``OSError``) silently breaks every caller's existing ``except``."""
    assert cls.__bases__ == bases


@pytest.mark.parametrize("cls, bases", _BASES, ids=_IDS)
def test_every_exception_is_exported_from_the_root(cls, bases):
    """A class missing from the root `__all__` is not API a caller may catch."""
    assert getattr(netimps, cls.__name__) is cls
    assert cls.__name__ in netimps.__all__


@pytest.mark.parametrize("cls, bases", _BASES, ids=_IDS)
@pytest.mark.parametrize(
    "roundtrip",
    [
        copy.copy,
        copy.deepcopy,
        lambda e: pickle.loads(pickle.dumps(e)),
        lambda e: pickle.loads(pickle.dumps(e, protocol=0)),
    ],
    ids=["copy", "deepcopy", "pickle", "pickle0"],
)
def test_every_exception_survives_copy_and_pickle(cls, bases, roundtrip):
    """A worker process or a retry wrapper copies the exception it re-raises;
    the class, the arguments and (for an OSError) the errno must come back."""
    error = cls(errno.ENOPROTOOPT, "no option") if OSError in cls.__mro__ else cls("x")
    clone = roundtrip(error)
    assert type(clone) is cls
    assert clone.args == error.args
    if isinstance(error, OSError):
        assert clone.errno == error.errno


def test_every_exception_class_is_defined_in_one_module():
    """A class defined elsewhere is a second home for a name the root
    re-exports, and an `import` cycle waiting to happen."""
    src = Path(netimps.__file__).parent
    homes = {
        path.name
        for path in src.glob("*.py")
        if any(
            line.startswith("class ") and "Error" in line.split("(")[0]
            for line in path.read_text(encoding="utf-8").splitlines()
        )
    }
    assert homes == {"_exceptions.py"}


def test_a_timeout_is_caught_as_a_resolution_error_and_as_a_timeout():
    """The chain moves on for ``ResolutionError``; a caller's deadline handling
    catches ``TimeoutError``. One exception has to satisfy both."""
    error = ResolutionTimeoutError("deadline")
    for catches in (ResolutionError, TimeoutError, NetimpsError):
        with pytest.raises(catches):
            raise error


def test_a_decode_error_is_a_value_error_and_a_package_error():
    """Every ``except ValueError`` written against the old private class."""
    for catches in (ValueError, NetimpsValueError, NetimpsError):
        with pytest.raises(catches):
            _namewire.encode_name("a..b")


def test_the_address_in_use_error_keeps_its_errno():
    """Two co-parents must not cost the ``errno`` attribute, and the class must
    still not be a ``PermissionError``."""
    error = AddressInUseError(98, "taken")
    assert error.errno == 98
    assert isinstance(error, OSError)
    assert not isinstance(error, PermissionError)


# --------------------------------------------------------------------------- #
# Where a deadline becomes ResolutionTimeoutError.
# --------------------------------------------------------------------------- #
def test_a_hung_system_lookup_raises_the_timeout_error(monkeypatch):
    """`resolve_system`'s deadline must be catchable as a ``TimeoutError``."""
    released = threading.Event()

    def _hang(*args, **kwargs):
        released.wait(30.0)
        return []

    monkeypatch.setattr(_dns._system._socket, "getaddrinfo", _hang)
    try:
        with pytest.raises(ResolutionTimeoutError):
            netimps.resolve_system("slow.example.invalid", timeout=0.05)
    finally:
        released.set()


def test_an_nslookup_timeout_raises_the_timeout_error(fake_program):
    """A hung nslookup is killed and the caller sees the package's timeout error."""
    fake_program("nslookup", hang=True)
    with pytest.raises(ResolutionTimeoutError):
        netimps.resolve_nslookup("example.com", timeout=1, search=False)


def test_a_missing_nslookup_is_a_resolution_error_but_not_a_timeout(
    tmp_path, monkeypatch
):
    """A missing binary is not a deadline; the two must stay distinguishable."""
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ResolutionError) as caught:
        netimps.resolve_nslookup("example.com")
    assert not isinstance(caught.value, TimeoutError)


def test_a_silent_nameserver_raises_the_timeout_error():
    """No answer inside the deadline from a server that is up but quiet."""
    quiet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    quiet.bind(("127.0.0.1", 0))
    try:
        with pytest.raises(ResolutionTimeoutError):
            netimps.resolve_wire(
                "host.test", ns="127.0.0.1:%d" % quiet.getsockname()[1], timeout=0.2
            )
    finally:
        quiet.close()


def test_a_doh_socket_timeout_raises_the_timeout_error():
    """A caller-supplied fetch that times out must surface as the deadline."""

    def _fetch(url, body, headers, timeout):
        raise socket.timeout("timed out")

    with pytest.raises(ResolutionTimeoutError):
        netimps.resolve_doh("host.test", "https://doh.invalid/q", fetch=_fetch)


# --------------------------------------------------------------------------- #
# Where DNSDecodeError goes.
# --------------------------------------------------------------------------- #
def test_doh_chains_an_unreadable_reply_as_the_cause():
    """A garbage body is a `ResolutionError`; the codec's reason is its cause,
    not lost behind a formatted string."""

    def _fetch(url, body, headers, timeout):
        return b"\x00\x01"

    with pytest.raises(ResolutionError) as caught:
        netimps.resolve_doh("host.test", "https://doh.invalid/q", fetch=_fetch)
    assert isinstance(caught.value.__cause__, DNSDecodeError)


def test_doh_raises_the_decode_error_for_a_name_it_cannot_encode():
    """Nothing is sent for a name the codec cannot write."""

    def _fetch(url, body, headers, timeout):  # pragma: no cover - never reached
        raise AssertionError("nothing may be sent for an unencodable name")

    with pytest.raises(DNSDecodeError):
        netimps.resolve_doh("a..b", "https://doh.invalid/q", fetch=_fetch)


def test_wire_chains_an_unreadable_reply_as_the_cause():
    """A reply to this query that the codec cannot read is "no server
    answered", with the codec's reason as the cause. A datagram that is not a
    reply to the query is discarded instead, and the wait goes on."""
    junk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    junk.bind(("127.0.0.1", 0))
    junk.settimeout(2)

    def _answer():
        try:
            data, peer = junk.recvfrom(4096)
            end = _namewire.read_labels(data, 12)[1] + 4
            # A reply to this query (its id and question) that stops inside
            # the first record.
            unreadable = (
                data[:2]
                + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                + data[12:end]
                + b"\xc0\x0c\x00"
            )
            junk.sendto(unreadable, peer)
        except OSError:
            pass

    thread = threading.Thread(target=_answer, daemon=True)
    thread.start()
    try:
        with pytest.raises(ResolutionError) as caught:
            netimps.resolve_wire(
                "host.test", ns="127.0.0.1:%d" % junk.getsockname()[1], timeout=1
            )
    finally:
        thread.join(3)
        junk.close()
    assert isinstance(caught.value.__cause__, DNSDecodeError)


# --------------------------------------------------------------------------- #
# Which ValueError is the package's, and which is the caller's own mistake.
# --------------------------------------------------------------------------- #
_MALFORMED_TEXT = [
    pytest.param(lambda: netimps.parse("not an address"), id="parse"),
    pytest.param(
        lambda: netimps.parse("10.0.0.0/33", netimps.IPNetwork), id="parse-net"
    ),
    pytest.param(lambda: netimps.parse("::1", netimps.IPv4Address), id="parse-family"),
    pytest.param(lambda: netimps.MACAddress("not a mac"), id="MACAddress"),
    pytest.param(lambda: netimps.FQDN("a..b"), id="FQDN"),
    pytest.param(lambda: netimps.split_host("[::1"), id="split_host"),
    pytest.param(lambda: netimps.split_host("host:notaport"), id="split_host-port"),
    pytest.param(lambda: netimps.join_host("", 80), id="join_host"),
    pytest.param(lambda: netimps.resolve_nslookup("-evil"), id="nslookup-query"),
]


@pytest.mark.parametrize("call", _MALFORMED_TEXT)
def test_malformed_text_raises_the_package_value_error(call):
    """A caller catching `NetimpsValueError` must see every text-to-value
    failure, and `except ValueError` must keep working for them."""
    with pytest.raises(NetimpsValueError) as caught:
        call()
    assert isinstance(caught.value, ValueError)


def test_parse_chains_the_ipaddress_error_as_the_cause():
    with pytest.raises(NetimpsValueError) as caught:
        netimps.parse("10.0.0.0/33", netimps.IPNetwork)
    assert isinstance(caught.value.__cause__, ValueError)


def test_a_caller_option_error_is_a_plain_value_error():
    """A bad option is the caller's mistake, not something netimps reports:
    it must be distinguishable by type from a malformed-text failure."""
    with pytest.raises(ValueError) as caught:
        netimps.tcp_check("127.0.0.1", 70000)
    assert not isinstance(caught.value, NetimpsError)


def test_a_custom_parse_callable_keeps_its_own_error():
    """`parse` wraps only the package's builders, not a caller's callable."""

    def picky(value):
        raise ValueError("mine")

    with pytest.raises(ValueError) as caught:
        netimps.parse("x", picky)
    assert not isinstance(caught.value, NetimpsError)


@pytest.mark.parametrize("pktinfo", [True, False])
def test_udp_recv_timeout_is_the_builtin_timeout_error(pktinfo):
    """On 3.9 `socket.timeout` is only an `OSError`; a caller catching
    `TimeoutError` around `recv` would miss it. A real socket with a real
    timeout, through both receive paths: `recvmsg` when the endpoint asks for
    pktinfo, `recvfrom` when it does not. On Windows the `recvmsg` path used to
    fail at once with `BlockingIOError` instead of waiting."""
    sock = netimps.bind("127.0.0.1", 0)
    sock.settimeout(0.05)
    try:
        with netimps.UDPEndpoint(sock, pktinfo=pktinfo) as endpoint:
            with pytest.raises(TimeoutError):
                endpoint.recv()
    finally:
        sock.close()
