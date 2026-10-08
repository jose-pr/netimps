"""`bind_listen`: the sockets a listen specification names, bound.

Loopback and port 0 only. Each test asserts what arrived where, and what is
left open, rather than what was called; the few that watch a call do so because
the platform cannot be made to refuse (a device bind) or to fail (a taken port
in the middle of a list).
"""

from __future__ import annotations

import logging
import socket
import types
import typing as ty

import pytest

import netimps
from netimps import (
    AddressInUseError,
    DeviceBindingUnsupportedError,
    Interface,
    NetimpsValueError,
    UDPEndpoint,
    bind_listen,
    parse_listen,
)

# Private: the module whose globals the code reads, so a test can stand in for the platform.
from netimps._listen import _binding

INET = socket.AF_INET
INET6 = socket.AF_INET6


@pytest.fixture
def listen() -> "ty.Iterator[ty.Callable[..., ty.Tuple[UDPEndpoint, ...]]]":
    """`bind_listen`, closing every endpoint it returned when the test ends."""
    made: "ty.List[UDPEndpoint]" = []

    def call(*args: ty.Any, **kwargs: ty.Any) -> "ty.Tuple[UDPEndpoint, ...]":
        endpoints = bind_listen(*args, **kwargs)
        made.extend(endpoints)
        return endpoints

    yield call
    for endpoint in made:
        endpoint.close()


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    """Records every socket `_binding.bind` returned and every call it got."""
    seen = types.SimpleNamespace(sockets=[], calls=[])
    real = _binding.bind

    def watched(*args: ty.Any, **kwargs: ty.Any) -> "socket.socket":
        seen.calls.append((args, kwargs))
        sock = real(*args, **kwargs)
        seen.sockets.append(sock)
        return sock

    monkeypatch.setattr(_binding, "bind", watched)
    return seen


def _has_loopback_v6() -> bool:
    try:
        probe = socket.socket(INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        probe.bind(("::1", 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


needs_v6 = pytest.mark.skipif(
    not _has_loopback_v6(), reason="this host has no ::1 to bind"
)


def _port(endpoint: UDPEndpoint) -> int:
    return int(endpoint.socket.getsockname()[1])


def _host(endpoint: UDPEndpoint) -> str:
    return str(endpoint.socket.getsockname()[0])


def _send(host: str, port: int, payload: bytes = b"ping") -> None:
    sender = socket.socket(INET6 if ":" in host else INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(payload, (host, port))
    finally:
        sender.close()


def _receives(endpoint: UDPEndpoint, wait: float = 5.0) -> bytes:
    endpoint.socket.settimeout(wait)
    return endpoint.recv().data


def _hears_nothing(endpoint: UDPEndpoint) -> bool:
    endpoint.socket.settimeout(0.3)
    try:
        endpoint.recv()
    except TimeoutError:
        return True
    return False


def _free_port() -> int:
    """A port both families can take: read from a wildcard socket, then released."""
    sock = netimps.bind("", 0)
    try:
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _loopback() -> Interface:
    for adapter in netimps.get_interfaces():
        if adapter.index and adapter.is_loopback:
            return adapter
    pytest.skip("this host has no loopback adapter with an index")


def _another_adapter() -> Interface:
    for adapter in netimps.get_interfaces():
        if adapter.index and not adapter.is_loopback:
            return adapter
    pytest.skip("this host has no second adapter with an index")


def _all_closed(sockets: "ty.Iterable[socket.socket]") -> bool:
    return all(sock.fileno() == -1 for sock in sockets)


# -- an address ---------------------------------------------------------------------------


def test_an_address_is_one_socket_bound_to_it_without_packet_info(
    listen: ty.Any,
) -> None:
    (endpoint,) = listen("127.0.0.1:0")
    assert _host(endpoint) == "127.0.0.1"
    assert not endpoint.has_pktinfo
    assert endpoint.interfaces == ()
    _send("127.0.0.1", _port(endpoint))
    assert _receives(endpoint) == b"ping"


def test_a_parsed_specification_is_bound_as_it_is(listen: ty.Any) -> None:
    (endpoint,) = listen(parse_listen("127.0.0.1:0"))
    assert _host(endpoint) == "127.0.0.1"


def test_the_endpoints_come_in_the_order_written(listen: ty.Any) -> None:
    if not _has_loopback_v6():
        pytest.skip("this host has no ::1 to bind")
    first, second = listen("[::1]:0,127.0.0.1:0")
    assert (_host(first), _host(second)) == ("::1", "127.0.0.1")
    first, second = listen("127.0.0.1:0,[::1]:0")
    assert (_host(first), _host(second)) == ("127.0.0.1", "::1")


def test_default_ports_are_given_to_a_binding_without_one(listen: ty.Any) -> None:
    port = _free_port()
    (endpoint,) = listen("127.0.0.1", port)
    assert _port(endpoint) == port


# -- the wildcard -------------------------------------------------------------------------


def test_a_wildcard_is_one_socket_with_packet_info(listen: ty.Any) -> None:
    if not netimps.has_pktinfo(INET):
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    (endpoint,) = listen("*:0")
    assert _host(endpoint) == "0.0.0.0"
    assert endpoint.has_pktinfo and endpoint.interfaces == ()
    _send("127.0.0.1", _port(endpoint))
    datagram = endpoint.recv()
    assert datagram.data == b"ping"
    assert datagram.interface_index


@pytest.mark.parametrize("spec", ["*:{p},[::]:{p}", "[::]:{p},*:{p}"])
@needs_v6
def test_both_wildcards_on_one_port_are_two_sockets_that_do_not_overlap(
    listen: ty.Any, spec: str
) -> None:
    port = _free_port()
    endpoints = listen(spec.format(p=port))
    assert len(endpoints) == 2
    by_host = {_host(e): e for e in endpoints}
    v4, v6 = by_host["0.0.0.0"], by_host["::"]
    _send("127.0.0.1", port, b"four")
    assert _receives(v4) == b"four"
    assert _hears_nothing(v6)
    _send("::1", port, b"six")
    assert _receives(v6) == b"six"
    assert _hears_nothing(v4)


@needs_v6
def test_an_ipv6_socket_is_ipv6_only(listen: ty.Any) -> None:
    (endpoint,) = listen("[::1]:0")
    assert endpoint.socket.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
    (wild,) = listen("*:0", family=INET6)
    assert _host(wild) == "::"
    assert wild.socket.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1


def test_broadcast_is_set_on_an_ipv4_socket_when_asked(listen: ty.Any) -> None:
    (plain,) = listen("127.0.0.1:0")
    (loud,) = listen("127.0.0.1:0", broadcast=True)
    assert not plain.socket.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST)
    assert loud.socket.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST)


@needs_v6
def test_broadcast_asked_of_an_ipv6_socket_is_not_an_error(listen: ty.Any) -> None:
    (endpoint,) = listen("[::1]:0", broadcast=True)
    assert endpoint.socket.family == INET6


# -- one socket for each address ----------------------------------------------------------


def _held(family: int) -> "ty.Set[str]":
    return {
        str(entry.ip).partition("%")[0]
        for _a, entry in netimps.iter_addresses(family=family)
    }


def test_per_address_is_one_socket_for_each_address_and_none_on_a_wildcard(
    listen: ty.Any,
) -> None:
    endpoints = listen("*:0", per_address=True)
    hosts = {_host(e).partition("%")[0] for e in endpoints}
    assert "0.0.0.0" not in hosts
    assert hosts == _held(INET)
    assert len(endpoints) == len(hosts)
    assert not any(e.has_pktinfo for e in endpoints)
    port = _port(next(e for e in endpoints if _host(e) == "127.0.0.1"))
    _send("127.0.0.1", port)
    assert _receives(next(e for e in endpoints if _host(e) == "127.0.0.1")) == b"ping"


@needs_v6
def test_per_address_of_family_six_binds_what_the_host_holds(listen: ty.Any) -> None:
    held = _held(INET6)
    if not held:
        pytest.skip("this host holds no IPv6 address")
    endpoints = listen("*:0", per_address=True, family=INET6)
    hosts = {_host(e).partition("%")[0] for e in endpoints}
    assert "::" not in hosts
    assert hosts == held
    assert "::1" in hosts


def test_without_packet_info_a_wildcard_is_one_socket_for_each_address(
    listen: ty.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_binding, "has_pktinfo", lambda family=INET: False)
    endpoints = listen("*:0")
    assert "0.0.0.0" not in {_host(e) for e in endpoints}
    assert {_host(e) for e in endpoints} == _held(INET)


def test_per_address_false_keeps_one_wildcard_socket_without_packet_info(
    listen: ty.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_binding, "has_pktinfo", lambda family=INET: False)
    (endpoint,) = listen("*:0", per_address=False)
    assert _host(endpoint) == "0.0.0.0"


def test_an_address_named_twice_is_bound_once(
    listen: ty.Any, spy: types.SimpleNamespace
) -> None:
    port = _free_port()
    endpoints = listen(f"127.0.0.1:{port},*:{port}", per_address=True)
    assert [_host(e) for e in endpoints].count("127.0.0.1") == 1
    assert len(spy.sockets) == len(endpoints)


# -- interfaces ---------------------------------------------------------------------------


def test_an_interface_is_one_wildcard_socket_limited_to_it(listen: ty.Any) -> None:
    if not netimps.has_pktinfo(INET):
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    loop = _loopback()
    (endpoint,) = listen((loop, 0))
    assert _host(endpoint) == "0.0.0.0"
    assert endpoint.interfaces == (loop,)
    assert endpoint.has_pktinfo
    _send("127.0.0.1", _port(endpoint))
    datagram = endpoint.recv()
    assert datagram.data == b"ping"
    assert endpoint.admits(datagram)


def test_an_interface_is_found_by_name_and_by_mac(listen: ty.Any) -> None:
    if not netimps.has_pktinfo(INET):
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    loop = _loopback()
    if ":" in loop.name or "/" in loop.name or "," in loop.name:
        pytest.skip("the loopback adapter's name cannot be spelled in text")
    (by_name,) = listen(f"{loop.name}:0")
    assert by_name.interfaces == (loop,)
    adapter = next(
        (
            a
            for a in netimps.get_interfaces()
            if a.index and a.mac is not None and not a.is_loopback
        ),
        None,
    )
    if adapter is None:
        pytest.skip("this host has no adapter with a MAC")
    (by_mac,) = listen((adapter.mac, 0), device_binding=False)
    assert adapter.index in {i.index for i in by_mac.interfaces}


def test_an_endpoint_limited_to_another_adapter_hears_loopback_and_does_not_admit_it(
    listen: ty.Any,
) -> None:
    if not netimps.has_pktinfo(INET):
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    other = _another_adapter()
    # Without the device bind, the kernel delivers the loopback datagram and
    # `admits` is what refuses it.
    (endpoint,) = listen((other, 0), device_binding=False)
    assert endpoint.interfaces == (other,)
    _send("127.0.0.1", _port(endpoint))
    endpoint.socket.settimeout(5.0)
    datagram = endpoint.recv()
    assert datagram.data == b"ping"
    assert not endpoint.admits(datagram)


def test_a_mac_several_adapters_carry_gives_every_one_and_no_device(
    listen: ty.Any, spy: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not netimps.has_pktinfo(INET):
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    first, second = Interface("a", 7), Interface("b", 9)
    monkeypatch.setattr(
        _binding, "iter_interfaces", lambda selector: iter([first, second])
    )
    monkeypatch.setattr(_binding, "has_device_binding", lambda: True)
    (endpoint,) = listen("aa-bb-cc-dd-ee-ff:0")
    assert endpoint.interfaces == (first, second)
    (call,) = spy.calls
    assert "device" not in call[1]


def test_an_adapter_found_twice_is_kept_once(
    listen: ty.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not netimps.has_pktinfo(INET):
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    a = Interface("a", 7)
    monkeypatch.setattr(_binding, "iter_interfaces", lambda selector: iter([a]))
    (endpoint,) = listen("x:0,y:0", device_binding=False)
    assert endpoint.interfaces == (a,)


def test_a_selector_that_matches_nothing_is_refused_and_opens_nothing(
    spy: types.SimpleNamespace,
) -> None:
    with pytest.raises(
        NetimpsValueError, match="no interface matches 'no-such-adapter-7'"
    ) as raised:
        bind_listen("127.0.0.1:0,no-such-adapter-7:0")
    assert "host name is never resolved" in str(raised.value)
    assert spy.sockets == [] and spy.calls == []


def test_a_mac_that_matches_nothing_is_refused_without_the_hint(
    spy: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_binding, "iter_interfaces", lambda selector: iter([]))
    with pytest.raises(NetimpsValueError, match="no interface matches") as raised:
        bind_listen("aa-bb-cc-dd-ee-ff:0")
    assert "host name" not in str(raised.value)
    assert spy.sockets == []


def test_an_adapter_without_an_index_does_not_match(
    spy: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        _binding, "iter_interfaces", lambda s: iter([Interface("a", 0)])
    )
    with pytest.raises(NetimpsValueError, match="no interface matches"):
        bind_listen("a:0")
    assert spy.sockets == []


def test_an_interface_binding_is_refused_with_per_address(
    spy: types.SimpleNamespace,
) -> None:
    with pytest.raises(NetimpsValueError, match="per_address"):
        bind_listen((_loopback(), 0), per_address=True)
    assert spy.sockets == []


def test_an_interface_binding_is_refused_where_no_packet_info_is_reported(
    spy: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_binding, "has_pktinfo", lambda family=INET: False)
    for per_address in (None, False):
        with pytest.raises(NetimpsValueError, match="packet info"):
            bind_listen((_loopback(), 0), per_address=per_address)
    assert spy.sockets == []


# -- the device ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not netimps.has_device_binding(), reason="this platform has no device binding"
)
def test_where_the_platform_can_an_endpoint_limited_to_loopback_is_device_bound(
    listen: ty.Any,
) -> None:
    loop = _loopback()
    (endpoint,) = listen((loop, 0))
    option = getattr(socket, "SO_BINDTODEVICE")
    bound = endpoint.socket.getsockopt(socket.SOL_SOCKET, option, 16)
    assert bound.rstrip(b"\0").decode() == loop.name
    (free,) = listen((loop, 0), device_binding=False)
    assert free.socket.getsockopt(socket.SOL_SOCKET, option, 16).rstrip(b"\0") == b""


@pytest.mark.parametrize(
    "refusal",
    [DeviceBindingUnsupportedError("no device here"), PermissionError("not permitted")],
    ids=["unsupported", "permission"],
)
def test_a_refused_device_bind_is_repeated_without_it_and_said_once(
    listen: ty.Any,
    spy: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    refusal: Exception,
) -> None:
    if not netimps.has_pktinfo(INET):
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    loop = _loopback()
    monkeypatch.setattr(_binding, "has_device_binding", lambda: True)
    real = _binding.bind

    def refusing(*args: ty.Any, **kwargs: ty.Any) -> "socket.socket":
        if "device" in kwargs:
            raise refusal
        return real(*args, **kwargs)

    monkeypatch.setattr(_binding, "bind", refusing)
    with caplog.at_level(logging.DEBUG, logger="netimps._listen"):
        (endpoint,) = listen((loop, 0))
    assert endpoint.interfaces == (loop,)
    _send("127.0.0.1", _port(endpoint))
    assert _receives(endpoint) == b"ping"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and warnings[0].name == "netimps._listen"
    assert loop.name in warnings[0].getMessage()


def test_a_second_refused_device_bind_in_one_call_is_not_said_again(
    listen: ty.Any,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    if not netimps.has_pktinfo(INET):
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    loop = _loopback()
    monkeypatch.setattr(_binding, "has_device_binding", lambda: True)
    real = _binding.bind

    def refusing(*args: ty.Any, **kwargs: ty.Any) -> "socket.socket":
        if "device" in kwargs:
            raise PermissionError("not permitted")
        return real(*args, **kwargs)

    monkeypatch.setattr(_binding, "bind", refusing)
    with caplog.at_level(logging.WARNING, logger="netimps._listen"):
        first, second = _free_port(), _free_port()
        if first == second:
            pytest.skip("the host handed out one port twice")
        endpoints = listen([(loop, first), (loop, second)])
    assert len(endpoints) == 2
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1


def test_an_error_the_repeat_raises_is_the_real_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_binding, "has_device_binding", lambda: True)

    def refusing(*args: ty.Any, **kwargs: ty.Any) -> "socket.socket":
        raise (
            DeviceBindingUnsupportedError("no device")
            if "device" in kwargs
            else (AddressInUseError("taken"))
        )

    monkeypatch.setattr(_binding, "bind", refusing)
    with pytest.raises(AddressInUseError):
        bind_listen((_loopback(), 0))


# -- a failure leaves nothing open --------------------------------------------------------


def test_a_taken_port_raises_address_in_use_and_leaves_no_socket_of_the_call_open(
    listen: ty.Any, spy: types.SimpleNamespace
) -> None:
    (holder,) = listen("127.0.0.1:0")
    taken = _port(holder)
    held_before = len(spy.sockets)
    with pytest.raises(AddressInUseError):
        bind_listen(f"127.0.0.1:0,127.0.0.1:{taken}")
    mine = spy.sockets[held_before:]
    # The first entry opened; the taken port failed inside `bind`, which closes it.
    assert len(mine) == 1
    assert _all_closed(mine)
    assert holder.socket.fileno() >= 0


def test_a_second_bind_of_a_wildcard_port_is_refused(listen: ty.Any) -> None:
    (holder,) = listen("*:0")
    with pytest.raises(AddressInUseError):
        bind_listen(f"*:{_port(holder)}")


def test_an_error_from_the_endpoint_closes_what_was_opened(
    spy: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    made: "ty.List[UDPEndpoint]" = []

    class Failing(UDPEndpoint):
        def __init__(self, sock: "socket.socket", **kwargs: ty.Any) -> None:
            if made:
                raise RuntimeError("the second endpoint fails")
            super().__init__(sock, **kwargs)
            made.append(self)

    monkeypatch.setattr(_binding, "UDPEndpoint", Failing)
    with pytest.raises(RuntimeError, match="second endpoint"):
        bind_listen("127.0.0.1:0,127.0.0.1:{}".format(_free_port()))
    assert len(spy.sockets) == 2
    assert _all_closed(spy.sockets)


def test_a_bad_specification_opens_nothing(spy: types.SimpleNamespace) -> None:
    for bad in ("", "127.0.0.1:70000", ("127.0.0.1", True)):
        with pytest.raises((TypeError, ValueError)):
            bind_listen(bad)
    assert spy.sockets == []


def test_every_socket_is_exclusive_and_takeover_is_passed_through(
    listen: ty.Any, spy: types.SimpleNamespace
) -> None:
    listen("127.0.0.1:0", allow_address_takeover=True)
    ((_, kwargs),) = spy.calls
    assert kwargs["allow_address_takeover"] is True
    assert kwargs["reuse_address"] is False
    assert kwargs["connreset"] is False
    assert kwargs["kind"] == socket.SOCK_DGRAM


def test_the_interface_cache_is_dropped_before_the_lookup(
    listen: ty.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    cleared: "ty.List[bool]" = []
    real = _binding.clear_interface_cache
    monkeypatch.setattr(
        _binding, "clear_interface_cache", lambda: (cleared.append(True), real())[1]
    )
    listen("127.0.0.1:0")
    assert cleared == [True]


def test_a_listen_name_is_never_a_host_name() -> None:
    if any(a.name == "localhost" for a in netimps.get_interfaces()):
        pytest.skip("this host has an adapter named localhost")
    with pytest.raises(NetimpsValueError, match="host name is never resolved"):
        bind_listen("localhost:0")
