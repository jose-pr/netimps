"""The standard-library DNS client: the wire codec, :func:`resolve_wire`
against a fake nameserver on 127.0.0.1 (UDP and TCP on one port),
:func:`resolve_doh` against a fake RFC 8484 endpoint, and where both sit in
:func:`resolve`'s chain."""

import ipaddress
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import netimps
from netimps import DNSDecodeError, _dns, _dnswire

# --------------------------------------------------------------------------- #
# A fake nameserver: answers from ZONE by the question's name and type.
# --------------------------------------------------------------------------- #
ZONE = {
    ("host.test", 1): [("host.test", 1, bytes([10, 0, 0, 5]))],
    ("host.test", 28): [("host.test", 28, ipaddress.IPv6Address("fd00::5").packed)],
    ("alias.test", 1): [
        ("alias.test", 5, _dnswire.encode_name("host.test")),
        ("host.test", 1, bytes([10, 0, 0, 5])),
    ],
    ("mail.test", 15): [
        ("mail.test", 15, struct.pack("!H", 10) + _dnswire.encode_name("mx.mail.test"))
    ],
    ("note.test", 16): [("note.test", 16, b"\x05hello\x06 world")],
    ("5.0.0.10.in-addr.arpa", 12): [
        ("5.0.0.10.in-addr.arpa", 12, _dnswire.encode_name("host.test"))
    ],
    ("big.test", 1): [
        ("big.test", 1, bytes([10, 1, i // 256, i % 256])) for i in range(200)
    ],
}
NXDOMAIN_NAMES = {"missing.test"}


def reply_for(query, tcp=False):
    ident, _flags, qdcount = struct.unpack("!HHH", query[:6])
    name, end = _dnswire._read_name(query, 12)
    qtype = struct.unpack("!H", query[end : end + 2])[0]
    question = query[12 : end + 4]
    if name in NXDOMAIN_NAMES:
        return struct.pack("!HHHHHH", ident, 0x8183, 1, 0, 0, 0) + question
    records = ZONE.get((name, qtype), [])
    answers = b"".join(
        _dnswire.encode_name(owner)
        + struct.pack("!HHIH", rtype, 1, 60, len(data))
        + data
        for owner, rtype, data in records
    )
    truncated = not tcp and len(answers) > 512
    if truncated:
        return struct.pack("!HHHHHH", ident, 0x8380, 1, 0, 0, 0) + question
    return (
        struct.pack("!HHHHHH", ident, 0x8180, 1, len(records), 0, 0)
        + question
        + answers
    )


class FakeNameserver(object):
    def __init__(self, host="127.0.0.1"):
        # A port free for **both** UDP and TCP, because `resolve_wire` is given
        # one `ns=` address and reaches the same number by either transport.
        #
        # TCP is bound FIRST: it is the one more likely to collide, since a
        # recently closed connection leaves the number in `TIME_WAIT` while a UDP
        # port is free the moment it is closed. Asking TCP for an ephemeral port
        # and then matching UDP to it therefore succeeds far more often than the
        # other way round -- which is what the fixture used to do, and why four
        # tests skipped silently under full-suite port pressure.
        self.tcp = socket.socket()
        try:
            self.tcp.bind((host, 0))
            self.port = self.tcp.getsockname()[1]
            self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                self.udp.bind((host, self.port))
            except OSError:
                self.udp.close()
                raise
            self.tcp.listen(5)
        except OSError:
            self.tcp.close()
            raise
        self.peers = []
        self.tcp_queries = 0
        threading.Thread(target=self._serve_udp, daemon=True).start()
        threading.Thread(target=self._serve_tcp, daemon=True).start()

    def _serve_udp(self):
        while True:
            try:
                data, peer = self.udp.recvfrom(4096)
            except OSError:
                return
            self.peers.append(peer)
            if b"silent" in data:
                continue
            self.udp.sendto(reply_for(data), peer)

    def _serve_tcp(self):
        while True:
            try:
                conn, peer = self.tcp.accept()
            except OSError:
                return
            with conn:
                size = struct.unpack("!H", conn.recv(2))[0]
                data = b""
                while len(data) < size:
                    data += conn.recv(size - len(data))
                self.tcp_queries += 1
                out = reply_for(data, tcp=True)
                conn.sendall(struct.pack("!H", len(out)) + out)

    def close(self):
        self.udp.close()
        self.tcp.close()


#: Attempts at finding a port free on both transports. 5 was not enough: under a
#: full-suite run on Windows -- hundreds of sockets opened and closed, TCP numbers
#: sitting in TIME_WAIT -- it gave up and **four tests skipped silently**, while
#: the file passed 26/26 in isolation. A skip is not a pass, and these cover
#: `resolve_wire`'s TCP fallback, so losing them quietly is the worst case. 50
#: attempts cost milliseconds.
_PORT_ATTEMPTS = 50


@pytest.fixture()
def server():
    for _ in range(_PORT_ATTEMPTS):
        try:
            fake = FakeNameserver()
            break
        except OSError:
            continue
    else:  # pragma: no cover - a host with essentially no free ports
        pytest.skip(
            "no port free on both UDP and TCP after %d attempts" % (_PORT_ATTEMPTS,)
        )
    yield fake
    fake.close()


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
    assert _dns._servers(entry, 53) == expected


def test_a_nameserver_must_be_an_address():
    with pytest.raises(ValueError):
        _dns._servers("dns.example", 53)


# --------------------------------------------------------------------------- #
# resolve(): where the wire backend sits.
# --------------------------------------------------------------------------- #
def test_resolve_uses_the_wire_backend_for_ns_without_dnspython(server, monkeypatch):
    monkeypatch.setattr(
        _dns,
        "resolve_dnspython",
        lambda *a, **k: (_ for _ in ()).throw(netimps.ResolutionError("no")),
    )
    got = netimps.resolve("host.test", ns=ns(server), backends=["dnspython", "wire"])
    assert got == [ipaddress.IPv4Address("10.0.0.5")]


def test_source_excludes_the_backends_that_cannot_choose_it():
    with pytest.raises(ValueError, match="source="):
        netimps.resolve(
            "host.test", source="127.0.0.1", backends=["system", "nslookup"]
        )


def test_wire_is_skipped_without_ns_or_source(monkeypatch):
    called = []
    monkeypatch.setattr(_dns, "resolve_wire", lambda *a, **k: called.append(1) or [])
    monkeypatch.setattr(_dns, "resolve_system", lambda *a, **k: ["1.2.3.4"])
    assert netimps.resolve("host.test", backends=["wire", "system"]) == ["1.2.3.4"]
    assert called == []


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
    assert netimps.resolve_doh("alias.test", doh) == [ipaddress.IPv4Address("10.0.0.5")]
    assert netimps.resolve_doh("missing.test", doh) == []
    assert _DoH.seen[0] == ("application/dns-message", "application/dns-message")


def test_doh_wrong_content_type_is_an_error(doh):
    _DoH.kind = "text/html"
    with pytest.raises(netimps.ResolutionError, match="text/html"):
        netimps.resolve_doh("host.test", doh)


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
        netimps.resolve_doh("host.test", "http://127.0.0.1:1/dns-query", timeout=2)


def test_dnspython_takes_the_source_too(server):
    pytest.importorskip("dns.resolver")
    got = netimps.resolve_dnspython(
        "host.test", ns="127.0.0.1", port=server.port, source="127.0.0.1", search=False
    )
    assert (
        got == [ipaddress.IPv4Address("10.0.0.5")]
        and server.peers[-1][0] == "127.0.0.1"
    )
