"""What ``bind()`` does when told nothing: family, ICMP errors, error text, buffers.

Each test pins the difference from what a caller wrote by hand around the old
defaults: computing the family before every call, passing ``connreset=False`` on
every datagram bind, and joining ``bind_error_hint`` onto the exception.
"""

import errno
import logging
import socket
import time

import pytest

import netimps
from netimps import AddressInUseError, bind, bind_error_hint, set_buffer_size


def _closed_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def _ipv6_loopback_works() -> bool:
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        probe.bind(("::1", 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


requires_ipv6 = pytest.mark.skipif(
    not _ipv6_loopback_works(), reason="this host cannot bind ::1"
)


# --------------------------------------------------------------------------- #
# family                                                                       #
# --------------------------------------------------------------------------- #


@requires_ipv6
def test_an_ipv6_literal_is_bound_as_ipv6_without_a_family():
    """A caller used to compute ``family=`` from the address before every call.

    The old default was ``AF_INET``, so ``bind("::1")`` failed with a
    ``gaierror`` from the socket layer.
    """
    sock = bind("::1", 0)
    try:
        assert sock.family == socket.AF_INET6
        assert sock.getsockname()[0] == "::1"
    finally:
        sock.close()


@requires_ipv6
def test_an_ipv6_address_object_and_a_stream_socket_infer_too():
    sock = bind(netimps.IPv6Address("::1"), 0, kind=socket.SOCK_STREAM, listen=1)
    try:
        assert sock.family == socket.AF_INET6
    finally:
        sock.close()


@pytest.mark.parametrize("address", ["", "127.0.0.1", "0.0.0.0", "localhost"])
def test_the_wildcard_an_ipv4_literal_and_an_ipv4_name_stay_ipv4(address):
    """The wildcard says nothing about the family, so it keeps meaning IPv4.

    ``localhost`` has both families on most hosts; it keeps binding as IPv4,
    as it did when the default was a constant.
    """
    sock = bind(address, 0)
    try:
        assert sock.family == socket.AF_INET
    finally:
        sock.close()


def test_an_explicit_family_still_wins_over_inference():
    if not socket.has_ipv6:
        pytest.skip("no IPv6 in this interpreter")
    sock = bind("", 0, family=socket.AF_INET6)
    try:
        assert sock.family == socket.AF_INET6
    finally:
        sock.close()


@requires_ipv6
def test_an_interface_with_an_ipv6_address_gives_an_ipv6_socket():
    loopback = next((i for i in netimps.get_interfaces() if i.is_loopback), None)
    if loopback is None or not any(ip.ip.version == 6 for ip in loopback.ips):
        pytest.skip("no loopback interface with an IPv6 address")
    sock = bind(port=0, interface=netimps.IPv6Address("::1"))
    try:
        assert sock.family == socket.AF_INET6
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# connreset                                                                    #
# --------------------------------------------------------------------------- #


def _what_a_receive_does_after_an_unreachable_send(sock: socket.socket) -> str:
    sock.settimeout(1.0)
    sock.sendto(b"x", ("127.0.0.1", _closed_udp_port()))
    time.sleep(0.2)
    try:
        sock.recvfrom(100)
    except ConnectionResetError:
        return "reset"
    except socket.timeout:
        return "quiet"
    return "data"


def test_an_unconnected_udp_socket_from_bind_ignores_an_icmp_unreachable():
    """A server loop died on a packet some other host did not want.

    Both protocol libraries passed ``connreset=False`` on every datagram bind.
    Ground truth comes from the platform: a bare stdlib socket tells whether
    this host reports the error at all (Windows does, POSIX does not for an
    unconnected socket), and ``bind()`` must then not.
    """
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw.bind(("127.0.0.1", 0))
    try:
        platform_reports = (
            _what_a_receive_does_after_an_unreachable_send(raw) == "reset"
        )
    finally:
        raw.close()

    sock = bind("127.0.0.1", 0)
    try:
        assert _what_a_receive_does_after_an_unreachable_send(sock) == "quiet"
    finally:
        sock.close()

    kept = bind("127.0.0.1", 0, connreset=True)
    try:
        expected = "reset" if platform_reports else "quiet"
        assert _what_a_receive_does_after_an_unreachable_send(kept) == expected
    finally:
        kept.close()


def test_connreset_false_still_forces_it_off():
    sock = bind("127.0.0.1", 0, connreset=False)
    try:
        assert _what_a_receive_does_after_an_unreachable_send(sock) == "quiet"
    finally:
        sock.close()


def test_a_stream_socket_is_not_touched_by_the_default(monkeypatch):
    """The default switches ``SIO_UDP_CONNRESET`` off for datagrams only.

    A stream socket has nothing to observe, so the call is watched instead:
    there is no public route to "was this option touched".
    """
    calls = []
    monkeypatch.setattr(
        netimps._sockets._bind,
        "disable_connreset",
        lambda sock: calls.append(sock.type),
    )
    bind("127.0.0.1", 0, kind=socket.SOCK_STREAM).close()
    assert calls == []
    bind("127.0.0.1", 0).close()
    assert calls == [socket.SOCK_DGRAM]


# --------------------------------------------------------------------------- #
# error text                                                                   #
# --------------------------------------------------------------------------- #


def test_an_in_use_bind_carries_the_hint_in_its_message():
    """Callers joined ``bind_error_hint`` onto the exception themselves."""
    holder = bind("127.0.0.1", 0, reuse_address=False)
    port = holder.getsockname()[1]
    try:
        with pytest.raises(AddressInUseError) as caught:
            bind("127.0.0.1", port, reuse_address=False)
    finally:
        holder.close()
    hint = bind_error_hint(caught.value.__cause__, port)
    assert hint and hint in str(caught.value)


def test_another_failure_keeps_its_class_and_gains_the_hint():
    with pytest.raises(OSError) as caught:
        bind("192.0.2.99", 9)  # not a local address
    hint = bind_error_hint(caught.value.__cause__, 9)
    assert hint, "this host gave an error the hint does not recognise"
    assert hint in str(caught.value)
    assert not isinstance(caught.value, AddressInUseError)
    assert caught.value.errno == caught.value.__cause__.errno
    assert type(caught.value) is type(caught.value.__cause__)


# --------------------------------------------------------------------------- #
# set_buffer_size                                                              #
# --------------------------------------------------------------------------- #


class _StingySocket:
    """Grants half of any buffer it is asked for, as a capped kernel does."""

    def __init__(self):
        self.values = {socket.SO_RCVBUF: 1000, socket.SO_SNDBUF: 1000}

    def getsockopt(self, level, option):
        return self.values[option]

    def setsockopt(self, level, option, value):
        self.values[option] = value // 2


def test_a_shortfall_is_logged_once_for_the_socket(caplog):
    """Both protocol libraries wrapped ``set_buffer_size`` to log this.

    The kernel agrees to a ``setsockopt`` and grants less; the stand-in does
    exactly that, since Windows grants 2 GiB and cannot show it.
    """
    sock = _StingySocket()
    with caplog.at_level(logging.WARNING, logger="netimps._sockets"):
        assert set_buffer_size(sock, receive=8000, send=8000) == (4000, 4000)
        set_buffer_size(sock, receive=9000)
    records = [r for r in caplog.records if r.name == "netimps._sockets"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert "SO_RCVBUF" in records[0].getMessage()
    assert "8000" in records[0].getMessage()


def test_no_warning_when_the_request_is_met(caplog):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with caplog.at_level(logging.DEBUG, logger="netimps"):
            granted = set_buffer_size(sock, receive=1024, send=1024)
        assert min(granted) >= 1024
    finally:
        sock.close()
    assert caplog.records == []


def test_the_library_installs_no_log_handler():
    import logging as stdlib_logging

    assert stdlib_logging.getLogger("netimps._sockets").handlers == []
    assert stdlib_logging.getLogger("netimps").handlers == []
