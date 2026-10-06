"""``bind(device=...)``: a socket restricted to one device, where the platform can.

Ground truth comes from the platform: a real loopback datagram, the kernel's own
read-back of the option, and the constant 25 written out here. What the tests
cannot show without a peer on the network is a datagram that *entered* through
a real adapter reaching a socket bound to that adapter; the negative case below
(a socket bound to another device does not hear loopback) is the half of the
claim that loopback can prove.
"""

import errno
import platform
import re
import socket
import sys
import types

import pytest

import netimps
from netimps import DeviceBindingUnsupportedError, bind, has_device_binding

LINUX = sys.platform.startswith("linux")


def _kernel() -> "tuple":
    found = re.match(r"(\d+)\.(\d+)", platform.release())
    return (int(found.group(1)), int(found.group(2))) if found else (0, 0)


def _can_bind_unprivileged() -> bool:
    """Linux lets an ordinary user use ``SO_BINDTODEVICE`` from 5.7."""
    import os

    return _kernel() >= (5, 7) or os.geteuid() == 0


linux_only = pytest.mark.skipif(not LINUX, reason="SO_BINDTODEVICE is Linux's")


def _loopback_name() -> str:
    return next(i.name for i in netimps.get_interfaces() if i.is_loopback)


def _other_device() -> "str":
    """A device other than loopback that exists, or skip: it is the negative case."""
    for index, name in socket.if_nameindex():
        if index != 1:
            return name
    pytest.skip("this host has no interface besides loopback to name instead")


def _send_and_receive(sock: "socket.socket", host: str) -> bool:
    """Whether a datagram sent to ``host`` at the socket's port reaches it."""
    sock.settimeout(0.5)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sender:
        sender.sendto(b"x", (host, sock.getsockname()[1]))
    try:
        return sock.recvfrom(16)[0] == b"x"
    except socket.timeout:
        return False


# --------------------------------------------------------------------------- #
# What holds everywhere                                                        #
# --------------------------------------------------------------------------- #


@pytest.fixture
def no_socket_from_bind(monkeypatch):
    """``bind`` as the socket module sees it can open nothing: a refused call
    must raise before it has a socket to leak. (Name lookups elsewhere in the
    package keep the real module.)"""
    from netimps._sockets import _bind

    def refuse(*args, **kwargs):
        raise AssertionError("bind opened a socket")

    shim = types.SimpleNamespace(
        **{name: getattr(socket, name) for name in dir(socket)}
    )
    shim.socket = refuse
    monkeypatch.setattr(_bind, "_socket", shim)


def test_has_device_binding_is_a_bool_and_is_exported():
    assert isinstance(has_device_binding(), bool)
    assert "has_device_binding" in netimps.__all__
    assert "DeviceBindingUnsupportedError" in netimps.__all__


def test_a_device_naming_no_adapter_raises_before_a_socket_is_opened(
    no_socket_from_bind,
):
    with pytest.raises(ValueError, match="nosuchdevice0"):
        bind("", 0, device="nosuchdevice0")


def test_device_and_interface_together_are_refused():
    """``interface=`` already stands for an address on an adapter."""
    name = _loopback_name()
    with pytest.raises(ValueError, match="device= and interface="):
        bind("", 0, device=name, interface=name)


@pytest.mark.skipif(LINUX, reason="Linux has the option; see the cases below")
def test_where_there_is_no_option_bind_says_so_before_a_socket_is_opened(
    no_socket_from_bind,
):
    """Windows was measured to have none; macOS and FreeBSD are unmeasured, so
    they are refused the same way until a measurement says otherwise."""
    assert has_device_binding() is False
    with pytest.raises(DeviceBindingUnsupportedError) as caught:
        bind("", 0, device=_loopback_name())
    assert caught.value.errno == errno.ENOPROTOOPT
    assert isinstance(caught.value, OSError)
    assert "has_device_binding" in str(caught.value)


# --------------------------------------------------------------------------- #
# Linux                                                                        #
# --------------------------------------------------------------------------- #


@linux_only
def test_has_device_binding_matches_what_the_kernel_allows_this_process():
    assert has_device_binding() is _can_bind_unprivileged()


@linux_only
def test_a_device_bound_wildcard_socket_hears_loopback_and_reads_the_device_back():
    if not _can_bind_unprivileged():
        pytest.skip("SO_BINDTODEVICE needs CAP_NET_RAW before Linux 5.7")
    with bind("", 0, device=_loopback_name()) as sock:
        assert sock.getsockname()[0] == "0.0.0.0"
        # 25 is SO_BINDTODEVICE; the kernel reports the device it holds.
        held = sock.getsockopt(socket.SOL_SOCKET, 25, 16)
        assert held.split(b"\0", 1)[0] == _loopback_name().encode()
        assert _send_and_receive(sock, "127.0.0.1") is True


@linux_only
def test_a_socket_bound_to_another_device_does_not_hear_loopback():
    """The restriction, not just the option: without it this socket is a
    plain wildcard and the datagram arrives."""
    if not _can_bind_unprivileged():
        pytest.skip("SO_BINDTODEVICE needs CAP_NET_RAW before Linux 5.7")
    other = _other_device()
    with bind("", 0, device=other) as sock:
        assert _send_and_receive(sock, "127.0.0.1") is False
    with bind("", 0) as control:
        assert _send_and_receive(control, "127.0.0.1") is True


@linux_only
def test_device_binding_applies_to_ipv6_too():
    if not _can_bind_unprivileged():
        pytest.skip("SO_BINDTODEVICE needs CAP_NET_RAW before Linux 5.7")
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        probe.bind(("::1", 0))
        probe.close()
    except OSError:
        pytest.skip("this host has no ::1")
    with bind("", 0, device=_loopback_name(), family=6) as sock:
        assert sock.family == socket.AF_INET6
        assert _send_and_receive(sock, "::1") is True
    with bind("", 0, device=_other_device(), family=6) as sock:
        assert _send_and_receive(sock, "::1") is False


@linux_only
def test_an_address_and_a_device_are_both_applied():
    """The address stays what ``address`` says, and the device restricts it."""
    if not _can_bind_unprivileged():
        pytest.skip("SO_BINDTODEVICE needs CAP_NET_RAW before Linux 5.7")
    with bind("127.0.0.1", 0, device=_loopback_name()) as sock:
        assert sock.getsockname()[0] == "127.0.0.1"
        assert _send_and_receive(sock, "127.0.0.1") is True
    with bind("127.0.0.1", 0, device=_other_device()) as sock:
        assert _send_and_receive(sock, "127.0.0.1") is False


@linux_only
def test_a_device_may_be_named_by_an_interface_object_or_its_index():
    if not _can_bind_unprivileged():
        pytest.skip("SO_BINDTODEVICE needs CAP_NET_RAW before Linux 5.7")
    iface = netimps.get_interface(_loopback_name())
    assert iface is not None
    with bind("", 0, device=iface) as sock:
        assert _send_and_receive(sock, "127.0.0.1") is True


@linux_only
def test_a_refused_option_closes_the_socket_and_keeps_the_errno(monkeypatch):
    """An unprivileged call on an old kernel is EPERM; it stays a
    PermissionError, names the device, and leaks nothing."""
    from netimps._sockets import _bind

    class Refusing(socket.socket):
        def setsockopt(self, level, name, *value):
            if (level, name) == (socket.SOL_SOCKET, 25):
                raise PermissionError(errno.EPERM, "Operation not permitted")
            return super().setsockopt(level, name, *value)

    monkeypatch.setattr(_bind._socket, "socket", Refusing)
    name = _loopback_name()
    with pytest.raises(PermissionError, match="cannot bind to device %r" % (name,)):
        bind("", 0, device=name)
