"""A DNS reply is untrusted input, and an argument is not an option.

The wire codec and the two transports bound what they read and how long they
take; ``nslookup`` is never handed a value it would read as an option; a DoH
reply is size-limited, over https, not redirected, and its URL's query string
stays out of messages. Everything runs on loopback.
"""

import http.server
import ipaddress
import socket
import struct
import threading
import time

import pytest

import netimps
from fakedns import reply_for
from netimps import DNSDecodeError, ResolutionError, ResolutionTimeoutError
from netimps import _dns, _dnswire


def message(answers, ident=7, qname="host.test", qtype=1):
    """A reply with one question and the given raw answer records."""
    header = struct.pack("!HHHHHH", ident, 0x8180, 1, len(answers), 0, 0)
    question = _dnswire.encode_name(qname) + struct.pack("!HH", qtype, 1)
    return header + question + b"".join(answers)


def record(name, rtype, rdata):
    return name + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata


# --------------------------------------------------------------------------- #
# The codec                                                                   #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "rtype,rdata",
    [
        (15, b"\x00"),  # MX: a preference needs two bytes and a name
        (15, b"\x00\x0a"),  # ...and the name
        (33, b"\x00\x01\x00\x02\x00"),  # SRV: priority, weight, port, name
        (33, b""),
    ],
)
def test_a_short_mx_or_srv_record_is_a_decode_error(rtype, rdata):
    """Measured on ec35558: ``struct.error``, which no handler catches."""
    reply = message([record(b"\xc0\x0c", rtype, rdata)], qtype=rtype)
    with pytest.raises(DNSDecodeError):
        _dnswire.parse_response(reply, 7)


def test_a_short_record_is_a_resolution_error_through_doh():
    reply = message([record(b"\xc0\x0c", 15, b"\x00")], ident=0, qtype=15)
    with pytest.raises(ResolutionError) as caught:
        netimps.resolve_doh(
            "host.test",
            "https://dns.example/q",
            rdtype="mx",
            fetch=lambda *args: reply,
        )
    assert isinstance(caught.value.__cause__, DNSDecodeError)


def _chain(hops):
    """A name that follows ``hops`` compression pointers before it ends."""
    base = 12
    data = bytearray(
        struct.pack("!HHHHHH", 7, 0x8180, 0, 0, 0, 0) + b"\x00"
    )  # offset 12: the root
    previous = base
    for _ in range(hops):
        offset = len(data)
        data += struct.pack("!H", 0xC000 | previous)
        previous = offset
    return bytes(data), previous


def test_a_name_follows_at_most_32_pointers():
    ok, start = _chain(32)
    assert _dnswire.read_labels(ok, start)[0] == []
    too_long, start = _chain(33)
    with pytest.raises(DNSDecodeError, match="pointers"):
        _dnswire.read_labels(too_long, start)


def test_a_long_pointer_chain_walked_by_many_records_is_cheap():
    """Measured on ec35558: 9.64 s for one 65,000-byte reply."""
    base = (
        struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0)
        + _dnswire.encode_name("host.test")
        + struct.pack("!HH", 1, 1)
    )
    first_name = len(base) + len(b"\xc0\x0c") + 10
    hops = 7000
    chain = bytearray(b"\x00")
    for i in range(hops):
        target = first_name + (0 if i == 0 else 1 + 2 * (i - 1))
        chain += struct.pack("!H", 0xC000 | target)
    tail = first_name + 1 + 2 * (hops - 1)
    pointer = struct.pack("!H", 0xC000 | tail)
    records = [record(b"\xc0\x0c", 99, bytes(chain))]
    count = (65000 - len(base) - len(records[0])) // (len(pointer) + 10 + len(pointer))
    records += [record(pointer, 5, pointer) for _ in range(count)]
    blob = (
        struct.pack("!HHHHHH", 7, 0x8180, 1, len(records), 0, 0)
        + base[12:]
        + b"".join(records)
    )
    started = time.perf_counter()
    with pytest.raises(DNSDecodeError):
        _dnswire.parse_response(blob, 7)
    assert time.perf_counter() - started < 0.1


def test_bytes_outside_letters_digits_and_hyphen_are_escaped_in_a_name():
    """A PTR answer is attacker text and ends up on a terminal.

    Newline, escape, NUL and a dot inside a label were returned as they came.
    The underscore is kept: service labels (``_sip._tcp``) carry it.
    """
    nasty = b"a.b\n\x1b[31mX\x00 y"
    reply = message(
        [record(b"\xc0\x0c", 12, bytes([len(nasty)]) + nasty + b"\x00")],
        qname="9.0.0.127.in-addr.arpa",
        qtype=12,
    )
    [name] = _dnswire.parse_response(reply, 7).records("9.0.0.127.in-addr.arpa", "ptr")
    assert name == "a\\046b\\010\\027\\09131mX\\000\\032y"
    assert all(ch.isalnum() or ch in "-\\" for ch in name)


def test_ordinary_names_are_untouched():
    reply = message(
        [record(b"\xc0\x0c", 12, _dnswire.encode_name("_sip._tcp.Mail-1.example.com"))],
        qname="9.0.0.127.in-addr.arpa",
        qtype=12,
    )
    [name] = _dnswire.parse_response(reply, 7).records("9.0.0.127.in-addr.arpa", "ptr")
    assert name == "_sip._tcp.Mail-1.example.com"


# --------------------------------------------------------------------------- #
# UDP: which datagram counts as the answer                                    #
# --------------------------------------------------------------------------- #


class Decoys(object):
    """A UDP server that answers each query with forgeries and then the truth."""

    def __init__(self, replies):
        self.replies = replies
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                data, peer = self.sock.recvfrom(4096)
            except OSError:
                return
            for reply in self.replies(data):
                self.sock.sendto(reply, peer)

    def close(self):
        self.sock.close()


@pytest.fixture
def decoys():
    made = []

    def make(replies):
        made.append(Decoys(replies))
        return made[-1]

    yield make
    for each in made:
        each.close()


def test_a_datagram_with_the_wrong_id_or_question_is_discarded(decoys):
    def replies(query):
        wrong_id = bytearray(reply_for(query))
        wrong_id[0] ^= 0xFF
        ident = struct.unpack("!H", query[:2])[0]
        other = _dnswire.build_query("other.test", "a", ident)
        yield bytes(wrong_id)
        yield reply_for(other)
        yield reply_for(query)

    server = decoys(replies)
    got = netimps.resolve_wire(
        "host.test", ns="127.0.0.1:%d" % server.port, timeout=2, search=False
    )
    assert got == [ipaddress.IPv4Address("10.0.0.5")]


def test_a_reply_larger_than_the_advertised_payload_is_not_accepted(decoys):
    """The query advertises 1232 bytes; ``recv(65535)`` took anything."""
    text = b"".join(bytes([255]) + b"x" * 255 for _ in range(6))  # ~1536 bytes

    def replies(query):
        ident = struct.unpack("!H", query[:2])[0]
        yield message(
            [record(b"\xc0\x0c", 16, text)], ident=ident, qname="host.test", qtype=16
        )

    server = decoys(replies)
    assert len(next(replies(b"\x00\x01"))) > _dnswire.EDNS_PAYLOAD
    with pytest.raises(ResolutionError):
        netimps.resolve_wire(
            "host.test",
            "txt",
            ns="127.0.0.1:%d" % server.port,
            timeout=1,
            search=False,
        )


# --------------------------------------------------------------------------- #
# TCP: one deadline for the whole exchange                                    #
# --------------------------------------------------------------------------- #


def test_the_tcp_exchange_has_one_deadline_not_one_per_recv():
    """Measured on ec35558: 12.3 s for ``timeout=0.5`` against one byte per 0.3 s."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def drip():
        conn, _ = listener.accept()
        conn.recv(4096)
        try:
            for byte in struct.pack("!H", 40) + b"\0" * 40:
                conn.send(bytes([byte]))
                time.sleep(0.3)
        except OSError:
            pass
        conn.close()

    threading.Thread(target=drip, daemon=True).start()
    started = time.perf_counter()
    with pytest.raises(ResolutionTimeoutError):
        netimps.resolve_wire(
            "host.test",
            ns="127.0.0.1:%d" % listener.getsockname()[1],
            tcp=True,
            timeout=0.5,
            search=False,
        )
    listener.close()
    assert time.perf_counter() - started < 1.5


# --------------------------------------------------------------------------- #
# Nameserver entries                                                          #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "entry", ["127.0.0.1:70000", "127.0.0.1:0", "[::1]:65536", "127.0.0.1:-1"]
)
def test_a_nameserver_port_out_of_range_is_a_value_error_before_a_socket(
    entry, monkeypatch
):
    def no_socket(*args, **kwargs):
        raise AssertionError("a socket was created")

    monkeypatch.setattr(_dns._socket, "socket", no_socket)
    with pytest.raises(ValueError, match="port"):
        netimps.resolve_wire("host.test", ns=entry, timeout=0.3, search=False)


def test_a_default_port_out_of_range_is_a_value_error(monkeypatch):
    with pytest.raises(ValueError, match="port"):
        netimps.resolve_wire(
            "host.test", ns="127.0.0.1", port=70000, timeout=0.3, search=False
        )


# --------------------------------------------------------------------------- #
# nslookup arguments                                                          #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["-debug", "-", "--x"])
def test_ns_that_looks_like_an_option_is_refused_before_a_program_runs(
    fake_program, value
):
    """Measured on ec35558: argv ended in ``-debug``."""
    fake = fake_program("nslookup")
    with pytest.raises(ValueError, match="'-'"):
        netimps.resolve_nslookup("host.test", ns=value, search=False)
    with pytest.raises(ValueError, match="'-'"):
        netimps.resolve("host.test", ns=value, backends="nslookup", search=False)
    assert fake.calls == []


@pytest.mark.parametrize("domain", ["-debug", "a b", "a\nb"])
def test_a_search_domain_that_cannot_be_part_of_a_name_is_refused(fake_program, domain):
    fake = fake_program("nslookup")
    with pytest.raises(ValueError):
        netimps.resolve_nslookup("host", search=[domain])
    assert fake.calls == []


def test_a_nameserver_is_not_checked_when_it_is_absent(fake_program):
    fake = fake_program("nslookup", stdout=b"Name: x\nAddress: 192.0.2.1\n")
    assert netimps.resolve_nslookup("host.test", search=False) != []
    assert fake.argv[-1] == "host.test."


# --------------------------------------------------------------------------- #
# DNS over HTTPS                                                              #
# --------------------------------------------------------------------------- #


class _Endpoint(http.server.BaseHTTPRequestHandler):
    """Answers by path: ``/ok``, ``/big`` (8 MiB of padding), ``/redirect``,
    ``/second`` (counts hits) and ``/fail`` (HTTP 500)."""

    hits = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        query = self.rfile.read(length)
        type(self).hits.append(self.path)
        path = self.path.split("?")[0]
        if path == "/redirect":
            self.send_response(307)
            self.send_header("Location", "/second")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/fail":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = reply_for(query, tcp=True)
        if path == "/big":
            body += b"\0" * (8 * 1024 * 1024)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def endpoint():
    _Endpoint.hits = []
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Endpoint)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def test_a_plain_http_url_is_refused_unless_asked_for(endpoint):
    with pytest.raises(ValueError, match="allow_http"):
        netimps.resolve_doh("host.test", endpoint + "/ok", rdtype="a")
    assert _Endpoint.hits == [], "a request left before the URL was checked"
    got = netimps.resolve_doh(
        "host.test", endpoint + "/ok", rdtype="a", allow_http=True
    )
    assert got == [ipaddress.IPv4Address("10.0.0.5")]


def test_https_is_not_refused(endpoint):
    calls = []

    def fetch(url, body, headers, timeout):
        calls.append(url)
        return reply_for(body, tcp=True)

    assert netimps.resolve_doh(
        "host.test", "https://dns.example/q", rdtype="a", fetch=fetch
    ) == [ipaddress.IPv4Address("10.0.0.5")]
    assert calls == ["https://dns.example/q"]


def test_a_reply_body_over_64_kib_is_refused(endpoint):
    """Measured on ec35558: the parser was handed 8,388,660 bytes."""
    started = time.perf_counter()
    with pytest.raises(ResolutionError, match="larger"):
        netimps.resolve_doh(
            "host.test", endpoint + "/big", rdtype="a", allow_http=True, timeout=10
        )
    assert time.perf_counter() - started < 5


def test_a_redirect_is_not_followed(endpoint):
    with pytest.raises(ResolutionError, match="307"):
        netimps.resolve_doh(
            "host.test", endpoint + "/redirect", rdtype="a", allow_http=True
        )
    assert _Endpoint.hits == ["/redirect"], "the redirect target was requested"


def test_the_query_string_stays_out_of_messages(endpoint):
    """A token in the URL is a secret."""
    with pytest.raises(ResolutionError) as caught:
        netimps.resolve_doh(
            "host.test", endpoint + "/fail?token=SECRET", rdtype="a", allow_http=True
        )
    assert "SECRET" not in str(caught.value) and "/fail" in str(caught.value)
    refused = "http://127.0.0.1:1/dns-query?token=SECRET"
    with pytest.raises(ResolutionError) as caught:
        netimps.resolve_doh(
            "host.test", refused, rdtype="a", allow_http=True, timeout=2
        )
    assert "SECRET" not in str(caught.value)
    assert "127.0.0.1" in str(caught.value)


def test_a_shown_url_has_no_credentials_query_or_fragment():
    assert (
        _dns._shown_url("https://u:p@h.example:8443/dns?token=S#f")
        == "https://h.example:8443/dns"
    )
    assert _dns._shown_url("https://[::1]/q?a=b") == "https://[::1]/q"
