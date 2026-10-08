"""An endpoint knows the interfaces it serves, and says whether a datagram is one of theirs.

`recv`, `arecv` and `datagrams` never filter: the caller asks `admits`, so that it
can count and report what it drops.
"""

from __future__ import annotations

import socket
import typing as ty

import pytest

import netimps
from netimps import (
    Datagram,
    Interface,
    MACAddress,
    NetimpsValueError,
    UDPEndpoint,
    bind,
)

NOWHERE = ("192.0.2.1", 9)


def _made(index: "ty.Optional[int]") -> Datagram:
    return Datagram(b"x", NOWHERE, interface_index=0 if index is None else index)


def _endpoint(*interfaces: Interface) -> UDPEndpoint:
    return UDPEndpoint(bind("127.0.0.1", 0), interfaces=interfaces)


@pytest.fixture
def endpoints() -> "ty.Iterator[ty.List[UDPEndpoint]]":
    made: "ty.List[UDPEndpoint]" = []
    yield made
    for endpoint in made:
        endpoint.close()


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


# -- an endpoint with no interfaces ------------------------------------------------


def test_an_endpoint_with_no_interfaces_admits_everything(
    endpoints: "ty.List[UDPEndpoint]",
) -> None:
    endpoint = _endpoint()
    endpoints.append(endpoint)
    assert endpoint.interfaces == ()
    assert endpoint.admits(_made(None))
    assert endpoint.admits(_made(0))
    assert endpoint.admits(_made(3))


# -- a limited endpoint, on made datagrams -------------------------------------------


def test_a_limited_endpoint_admits_the_index_of_one_of_its_interfaces(
    endpoints: "ty.List[UDPEndpoint]",
) -> None:
    endpoint = _endpoint(Interface("a", 7), Interface("b", 9))
    endpoints.append(endpoint)
    assert [i.name for i in endpoint.interfaces] == ["a", "b"]
    assert endpoint.admits(_made(7))
    assert endpoint.admits(_made(9))
    assert not endpoint.admits(_made(8))


def test_a_limited_endpoint_does_not_admit_a_datagram_with_no_arrival_interface(
    endpoints: "ty.List[UDPEndpoint]",
) -> None:
    endpoint = _endpoint(Interface("a", 7))
    endpoints.append(endpoint)
    assert not endpoint.admits(_made(None))
    assert not endpoint.admits(_made(0))
    assert not endpoint.admits(Datagram(b"x", NOWHERE))


def test_interfaces_is_a_tuple_of_what_was_given_in_order(
    endpoints: "ty.List[UDPEndpoint]",
) -> None:
    first, second = Interface("a", 7), Interface("b", 9)
    for given in ([first, second], iter([first, second]), (first, second)):
        endpoint = UDPEndpoint(bind("127.0.0.1", 0), interfaces=given)
        endpoints.append(endpoint)
        assert endpoint.interfaces == (first, second)
        assert isinstance(endpoint.interfaces, tuple)


# -- a limited endpoint, on real datagrams ---------------------------------------------


def _wildcard(*interfaces: Interface) -> UDPEndpoint:
    endpoint = UDPEndpoint(bind("", 0), interfaces=interfaces)
    endpoint.socket.settimeout(5.0)
    if not endpoint.has_pktinfo:
        endpoint.close()
        pytest.skip("this host reports no arrival interface on an IPv4 socket")
    return endpoint


def _send_to_loopback(endpoint: UDPEndpoint) -> None:
    port = endpoint.socket.getsockname()[1]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.sendto(b"ping", ("127.0.0.1", port))
    finally:
        sender.close()


def test_a_wildcard_endpoint_limited_to_loopback_admits_loopback_traffic(
    endpoints: "ty.List[UDPEndpoint]",
) -> None:
    endpoint = _wildcard(_loopback())
    endpoints.append(endpoint)
    _send_to_loopback(endpoint)
    datagram = endpoint.recv()
    assert datagram.data == b"ping"
    assert datagram.interface_index == _loopback().index
    assert endpoint.admits(datagram)


def test_a_wildcard_endpoint_limited_to_another_adapter_does_not_admit_it_but_recv_returns_it(
    endpoints: "ty.List[UDPEndpoint]",
) -> None:
    endpoint = _wildcard(_another_adapter())
    endpoints.append(endpoint)
    _send_to_loopback(endpoint)
    datagram = endpoint.recv()
    assert datagram.data == b"ping"
    assert not endpoint.admits(datagram)


# -- construction ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        ["lo"],
        [MACAddress("aa:bb:cc:dd:ee:ff")],
        [None],
        [7],
        "lo",
        Interface("a", 7),
        7,
    ],
    ids=repr,
)
def test_an_item_that_is_not_an_interface_is_refused(bad: ty.Any) -> None:
    sock = bind("127.0.0.1", 0)
    try:
        with pytest.raises(TypeError, match="interfaces"):
            UDPEndpoint(sock, interfaces=bad)
    finally:
        sock.close()


@pytest.mark.parametrize("index", [0])
def test_an_interface_with_no_index_is_refused(index: int) -> None:
    sock = bind("127.0.0.1", 0)
    try:
        with pytest.raises(NetimpsValueError, match="index"):
            UDPEndpoint(sock, interfaces=[Interface("a", index)])
    finally:
        sock.close()


def test_a_refused_construction_leaves_the_socket_the_callers() -> None:
    sock = bind("127.0.0.1", 0)
    try:
        with pytest.raises(TypeError):
            UDPEndpoint(sock, interfaces=["lo"])
        assert sock.fileno() >= 0
    finally:
        sock.close()


def test_the_keyword_is_keyword_only() -> None:
    sock = bind("127.0.0.1", 0)
    try:
        with pytest.raises(TypeError):
            UDPEndpoint(sock, True, ())  # type: ignore[misc]
    finally:
        sock.close()


def test_the_repr_names_the_interfaces_of_a_limited_endpoint(
    endpoints: "ty.List[UDPEndpoint]",
) -> None:
    endpoint = _endpoint(Interface("eth9", 7))
    endpoints.append(endpoint)
    assert "eth9" in repr(endpoint)
    plain = _endpoint()
    endpoints.append(plain)
    assert "interfaces" not in repr(plain)
