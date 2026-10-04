"""``resolve_wire``: the DNS protocol over UDP/TCP to named servers, standard library only."""

from __future__ import annotations

import ipaddress as _ipaddress
import os as _os
import socket as _socket
import struct as _struct
import time as _time
from typing import Any, List, Literal, Optional, Tuple, Union, overload
from . import _dnswire
from .._exceptions import DNSDecodeError, ResolutionError, ResolutionTimeoutError
from .._ip import HostLike, IPv4Address, IPv6Address, _dst_argument
from ._common import _auto_rdtype, _budget, _nameservers, search_candidates


def _system_nameservers() -> "List[str]":
    """The nameservers of ``/etc/resolv.conf`` (POSIX); empty elsewhere."""
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            return [
                line.split()[1]
                for line in handle
                if line.split()[:1] == ["nameserver"] and len(line.split()) > 1
            ]
    except OSError:
        return []


def _servers(
    ns: "Optional[Union[str, List[str]]]", port: int
) -> "List[Tuple[str, int]]":
    """``(host, port)`` per nameserver (see :func:`_nameservers`). ``None``: the
    system's, from ``/etc/resolv.conf`` (POSIX only)."""
    entries = [ns] if isinstance(ns, str) else list(ns or [])
    if not entries:
        entries = _system_nameservers()
        if not entries:
            raise ResolutionError(
                "resolve_wire needs ns= here: no /etc/resolv.conf to take the system's from"
            )
    return _nameservers(entries, port)


def _source_for(
    source: "Optional[Union[str, List[str]]]", host: str
) -> "Optional[str]":
    """The source address of ``host``'s family, ``None`` for any; a source
    list without one for that family skips the server (``ValueError``)."""
    if not source:
        return None
    sources = [source] if isinstance(source, str) else list(source)
    family = _ipaddress.ip_address(host.split("%")[0]).version
    for address in sources:
        if _ipaddress.ip_address(address.split("%")[0]).version == family:
            return address
    raise ValueError("no source address for IPv%d nameserver %s" % (family, host))


def _exchange(
    server: "Tuple[str, int]",
    payload: bytes,
    timeout: float,
    tcp: bool,
    source: "Optional[str]",
) -> bytes:
    """One query and its reply, within ``timeout`` seconds in all.

    Over UDP a datagram that is not a reply to this query (another id, another
    question) is discarded and the wait goes on until the deadline; the buffer
    is what the query advertised, :data:`_dnswire.EDNS_PAYLOAD`.
    """
    host, port = server
    deadline = _time.monotonic() + timeout
    family = _socket.AF_INET6 if ":" in host else _socket.AF_INET
    sock = _socket.socket(family, _socket.SOCK_STREAM if tcp else _socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        if source:
            sock.bind((source, 0))
        sock.connect((host, port))
        if not tcp:
            sock.send(payload)
            while True:
                sock.settimeout(_remaining(deadline))
                data = sock.recv(_dnswire.EDNS_PAYLOAD)
                if _dnswire.is_reply_to(payload, data):
                    return data
        sock.settimeout(_remaining(deadline))
        sock.sendall(_struct.pack("!H", len(payload)) + payload)
        size = _struct.unpack("!H", _recv_exactly(sock, 2, deadline))[0]
        data = _recv_exactly(sock, size, deadline)
        if not _dnswire.is_reply_to(payload, data):
            raise DNSDecodeError("reply to another query")
        return data
    finally:
        sock.close()


def _remaining(deadline: float) -> float:
    """Seconds until ``deadline``, or ``socket.timeout`` once it has passed."""
    left = deadline - _time.monotonic()
    if left <= 0:
        raise _socket.timeout("timed out")
    return left


def _recv_exactly(sock: "_socket.socket", count: int, deadline: float) -> bytes:
    data = b""
    while len(data) < count:
        sock.settimeout(_remaining(deadline))
        piece = sock.recv(count - len(data))
        if not piece:
            raise OSError("connection closed after %d of %d bytes" % (len(data), count))
        data += piece
    return data


def _question(query: str, rdtype: "Optional[str]") -> "Tuple[str, str]":
    """``(name asked, rdtype)``: an address literal's PTR name for ``ptr``."""
    rdtype = (rdtype or _auto_rdtype(query)).lower()
    if rdtype not in _dnswire.RDTYPES:
        raise ResolutionError(
            "rdtype %r is not one the DNS wire backend reads (%s)"
            % (rdtype, ", ".join(sorted(_dnswire.RDTYPES)))
        )
    if rdtype == "ptr":
        try:
            return _dnswire.reverse_name(query), rdtype
        except ValueError:
            pass
    return query, rdtype


@overload
def resolve_wire(
    query: "HostLike",
    rdtype: "Literal['a', 'A']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[IPv4Address]": ...


@overload
def resolve_wire(
    query: "HostLike",
    rdtype: "Literal['aaaa', 'AAAA']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[IPv6Address]": ...


@overload
def resolve_wire(
    query: "HostLike",
    rdtype: "Literal['ptr', 'PTR']",
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[str]": ...


@overload
def resolve_wire(
    query: "HostLike",
    rdtype: Optional[str] = None,
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[Any]": ...


def resolve_wire(
    query: "HostLike",
    rdtype: Optional[str] = None,
    *,
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
    search: Union[bool, List[str]] = True,
    source: Optional[Union[str, List[str]]] = None,
) -> "List[Any]":
    """Resolve ``query`` by speaking DNS to ``ns`` directly -- no dnspython,
    no OS resolver. UDP, retried over TCP when the reply is truncated (or TCP
    throughout with ``tcp=True``); the nameservers in turn until one answers.

    ::

        resolve_wire("example.com", ns="1.1.1.1")
        resolve_wire("example.com", "aaaa", ns=["10.0.0.53:5353", "[fd00::53]"])
        resolve_wire("example.com", ns="10.0.0.53", source="10.0.0.7")

    :param ns: nameserver(s): ``host``, ``host:port``, ``[v6]:port``.
        ``None``: ``/etc/resolv.conf``'s (POSIX; elsewhere
        :class:`ResolutionError`).
    :param rdtype: ``a``, ``aaaa``, ``cname``, ``ptr``, ``mx``, ``txt``,
        ``ns``, ``srv``; ``None`` auto-selects as :func:`resolve` does.
        Another type is a :class:`ResolutionError` (the chain moves on).
    :param timeout: seconds for the whole resolution, every server included.
    :param port: the port of an ``ns`` entry that names none.
    :param source: the address the queries leave from -- one, or one per
        address family; a server whose family has none is skipped.
    :param search: a list of domains tries ``query`` under each, then as
        given; ``True``/``False`` ask for ``query`` as given (this backend
        reads no system search list).

    Contract as the other backends: native values, ``[]`` for NXDOMAIN or no
    record of the type, :class:`ResolutionError` when no server answered
    (:class:`ResolutionTimeoutError` when the deadline or a socket timeout
    was the reason). A reply the codec cannot read, or a name it cannot encode,
    is not raised as such: it counts as that server not answering, and the
    :class:`DNSDecodeError` is the ``__cause__`` of the final error.
    A CNAME chain inside the reply is followed.
    """
    query = _dst_argument(query)
    name, rdtype = _question(query, rdtype)
    servers = _servers(ns, port)
    names = search_candidates(name, search, wire=True)
    deadline = _time.monotonic() + (_budget(5.0 if timeout is None else timeout) or 0.0)
    last: Optional[Exception] = None
    answered = False
    for candidate in names:
        for index, server in enumerate(servers):
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                raise ResolutionTimeoutError(
                    "no answer within %ss (last: %s)" % (timeout, last)
                ) from last
            # Each server gets its share of what is left, so a dead first one
            # cannot use up the time the next would have answered in.
            remaining /= len(servers) - index
            try:
                from_ = _source_for(source, server[0])
                ident = int.from_bytes(_os.urandom(2), "big")
                payload = _dnswire.build_query(candidate, rdtype, ident)
                reply = _dnswire.parse_response(
                    _exchange(server, payload, remaining, tcp, from_), ident
                )
                if reply.truncated and not tcp:
                    reply = _dnswire.parse_response(
                        _exchange(
                            server,
                            payload,
                            max(deadline - _time.monotonic(), 0.01),
                            True,
                            from_,
                        ),
                        ident,
                    )
            except (OSError, ValueError) as exc:
                last = exc
                continue
            if reply.rcode == _dnswire.NXDOMAIN:
                answered = True
                break
            if reply.rcode != _dnswire.NOERROR:
                last = ResolutionError(
                    "%s:%d answered rcode %d" % (server[0], server[1], reply.rcode)
                )
                continue
            values = reply.records(candidate, rdtype)
            if values:
                return values
            answered = True
            break
    if answered:
        return []
    if isinstance(last, _socket.timeout):
        raise ResolutionTimeoutError(
            "no nameserver answered in time: %s" % (last,)
        ) from last
    raise ResolutionError("no nameserver answered: %s" % (last,)) from last
