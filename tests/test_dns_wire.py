"""The standard-library DNS client: the wire codec, :func:`resolve_wire`
against a fake nameserver on 127.0.0.1 (UDP and TCP on one port),
:func:`resolve_doh` against a fake RFC 8484 endpoint, and where both sit in
:func:`resolve`'s chain."""

import ipaddress
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import netimps
from fakedns import reply_for
from netimps import DNSDecodeError, _dns, _dnswire


def ns(server):
    return "127.0.0.1:%d" % server.port


# --------------------------------------------------------------------------- #
# The codec.
# --------------------------------------------------------------------------- #
def test_a_query_is_one_question_with_edns():
    data = _dnswire.build_query("example.com", "aaaa", 0x1234)
    ident, flags, qd, an, ns_, ar = struct.unpack("!HHHHHH", data[:12])
    assert (ident, flags, qd, an, ns_, ar) == (0x1234, 0x0100, 1, 0, 0, 1)
    assert data[12:25] == b"\x07example\x03com\x00"


def test_unknown_types_and_bad_names_are_refused():
    with pytest.raises(DNSDecodeError):
        _dnswire.build_query("example.com", "hinfo", 1)
    with pytest.raises(DNSDecodeError):
        _dnswire.encode_name("a..b")


def test_compressed_names_and_loops():
    reply = (
        struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        + _dnswire.encode_name("a.test")
        + b"\x00\x01\x00\x01"
    )
    reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
    parsed = _dnswire.parse_response(reply, 1)
    assert parsed.records("A.TEST.", "a") == [ipaddress.IPv4Address("1.2.3.4")]
    looping = reply[:12] + b"\xc0\x0c"
    with pytest.raises(DNSDecodeError):
        _dnswire.parse_response(looping + b"\x00\x01\x00\x01", 1)


def test_the_codec_agrees_with_dnspython():
    message = pytest.importorskip("dns.message")
    rrset = pytest.importorskip("dns.rrset")
    query = message.from_wire(_dnswire.build_query("example.com", "mx", 7))
    assert str(query.question[0].name) == "example.com." and query.id == 7
    response = message.make_response(query)
    response.answer.append(
        rrset.from_text("example.com.", 60, "IN", "MX", "10 mail.example.com.")
    )
    response.answer.append(
        rrset.from_text("example.com.", 60, "IN", "TXT", '"v=spf1" " -all"')
    )
    parsed = _dnswire.parse_response(response.to_wire(), 7)
    assert parsed.records("example.com", "mx") == ["10 mail.example.com"]
    assert parsed.records("example.com", "txt") == ["v=spf1 -all"]


# --------------------------------------------------------------------------- #
# resolve_wire against the fake nameserver.
# --------------------------------------------------------------------------- #
def test_records_come_back_native(server):
    assert netimps.resolve_wire("host.test", ns=ns(server)) == [
        ipaddress.IPv4Address("10.0.0.5")
    ]
    assert netimps.resolve_wire("host.test", "aaaa", ns=ns(server)) == [
        ipaddress.IPv6Address("fd00::5")
    ]
    assert netimps.resolve_wire("alias.test", ns=ns(server)) == [
        ipaddress.IPv4Address("10.0.0.5")
    ]
    assert netimps.resolve_wire("mail.test", "mx", ns=ns(server)) == ["10 mx.mail.test"]
    assert netimps.resolve_wire("note.test", "txt", ns=ns(server)) == ["hello world"]
    assert netimps.resolve_wire("10.0.0.5", ns=ns(server)) == ["host.test"]


def test_nxdomain_and_nodata_are_empty(server):
    assert netimps.resolve_wire("missing.test", ns=ns(server)) == []
    assert netimps.resolve_wire("host.test", "mx", ns=ns(server)) == []


def test_a_truncated_reply_is_asked_again_over_tcp(server):
    got = netimps.resolve_wire("big.test", ns=ns(server))
    assert len(got) == 200 and server.tcp_queries == 1


def test_tcp_throughout(server):
    assert netimps.resolve_wire("host.test", ns=ns(server), tcp=True) == [
        ipaddress.IPv4Address("10.0.0.5")
    ]
    assert server.tcp_queries == 1


def test_no_answer_is_a_resolution_error(server):
    with pytest.raises(netimps.ResolutionError):
        netimps.resolve_wire("silent.test", ns=ns(server), timeout=0.5)


def test_the_next_server_answers(server):
    dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dead.bind(("127.0.0.1", 0))
    try:
        got = netimps.resolve_wire(
            "host.test",
            ns=["127.0.0.1:%d" % dead.getsockname()[1], ns(server)],
            timeout=3,
        )
    finally:
        dead.close()
    assert got == [ipaddress.IPv4Address("10.0.0.5")]


def test_search_domains_are_tried_first(server):
    assert netimps.resolve_wire("host", ns=ns(server), search=["test"]) == [
        ipaddress.IPv4Address("10.0.0.5")
    ]


def test_the_source_address_is_used(server):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.2", 0))
    except OSError:
        pytest.skip("127.0.0.2 is not bindable here")
    finally:
        probe.close()
    netimps.resolve_wire("host.test", ns=ns(server), source=["::1", "127.0.0.2"])
    assert server.peers[-1][0] == "127.0.0.2"


def test_a_source_of_the_wrong_family_skips_the_server(server):
    with pytest.raises(netimps.ResolutionError, match="no source address for IPv4"):
        netimps.resolve_wire("host.test", ns=ns(server), source="::1", timeout=1)


@pytest.mark.parametrize(
    "entry,expected",
    [
        ("1.1.1.1", [("1.1.1.1", 53)]),
        ("1.1.1.1:5353", [("1.1.1.1", 5353)]),
        ("[::1]:5353", [("::1", 5353)]),
        ("fd00::53", [("fd00::53", 53)]),
    ],
)
def test_nameserver_entries(entry, expected):
    assert _dns._wire._servers(entry, 53) == expected


def test_a_nameserver_must_be_an_address():
    with pytest.raises(ValueError):
        _dns._wire._servers("dns.example", 53)


# --------------------------------------------------------------------------- #
# resolve(): where the wire backend sits.
# --------------------------------------------------------------------------- #
def test_resolve_uses_the_wire_backend_for_ns_without_dnspython(server, monkeypatch):
    for name in ("dns", "dns.resolver", "dns.name", "dns.exception"):
        monkeypatch.setitem(sys.modules, name, None)
    got = netimps.resolve("host.test", ns=ns(server), backends=["dnspython", "wire"])
    assert got == [ipaddress.IPv4Address("10.0.0.5")]


def test_source_excludes_the_backends_that_cannot_choose_it():
    with pytest.raises(ValueError, match="source="):
        netimps.resolve(
            "host.test", source="127.0.0.1", backends=["system", "nslookup"]
        )


def test_wire_is_skipped_without_ns_or_source(monkeypatch):
    """No nameserver was named, so nothing is sent: the OS resolver answers."""
    sent = []
    monkeypatch.setattr(_dns._wire, "_exchange", lambda *a, **k: sent.append(a) or b"")
    monkeypatch.setattr(
        _dns._wire._socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, 0, 0, "", ("1.2.3.4", 0))],
    )
    assert netimps.resolve("host.test", backends=["wire", "system"]) == [
        ipaddress.IPv4Address("1.2.3.4")
    ]
    assert sent == []


# --------------------------------------------------------------------------- #
# resolve_doh against a fake RFC 8484 endpoint.
# --------------------------------------------------------------------------- #
class _DoH(BaseHTTPRequestHandler):
    kind = "application/dns-message"
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _DoH.seen.append((self.headers["Content-Type"], self.headers["Accept"]))
        out = reply_for(body, tcp=True)
        self.send_response(200)
        self.send_header("Content-Type", _DoH.kind)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture()
def doh():
    _DoH.kind, _DoH.seen = "application/dns-message", []
    httpd = HTTPServer(("127.0.0.1", 0), _DoH)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d/dns-query" % httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def test_doh_answers(doh):
    assert netimps.resolve_doh("alias.test", doh, allow_http=True) == [
        ipaddress.IPv4Address("10.0.0.5")
    ]
    assert netimps.resolve_doh("missing.test", doh, allow_http=True) == []
    assert _DoH.seen[0] == ("application/dns-message", "application/dns-message")


def test_doh_wrong_content_type_is_an_error(doh):
    _DoH.kind = "text/html"
    with pytest.raises(netimps.ResolutionError, match="text/html"):
        netimps.resolve_doh("host.test", doh, allow_http=True)


def test_doh_through_the_callers_fetch(doh):
    calls = []

    def fetch(url, body, headers, timeout):
        calls.append(url)
        return reply_for(body, tcp=True)

    assert netimps.resolve_doh("host.test", "https://dns.example/q", fetch=fetch) == [
        ipaddress.IPv4Address("10.0.0.5")
    ]
    assert calls == ["https://dns.example/q"]


def test_doh_unreachable_is_an_error():
    with pytest.raises(netimps.ResolutionError):
        netimps.resolve_doh(
            "host.test", "http://127.0.0.1:1/dns-query", timeout=2, allow_http=True
        )


def test_dnspython_takes_the_source_too(server):
    pytest.importorskip("dns.resolver")
    got = netimps.resolve_dnspython(
        "host.test", ns="127.0.0.1", port=server.port, source="127.0.0.1", search=False
    )
    assert (
        got == [ipaddress.IPv4Address("10.0.0.5")]
        and server.peers[-1][0] == "127.0.0.1"
    )
