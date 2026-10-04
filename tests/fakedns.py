"""A fake nameserver on loopback, shared by the resolver tests.

It answers from :data:`ZONE` by the question's name and type over UDP and TCP
on one port, never answers a name containing ``silent``, and can be told to
drop one record type. Nothing here leaves the machine.
"""

import ipaddress
import socket
import struct
import threading

from netimps import _dnswire

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
#: Names answered with rcode SERVFAIL.
SERVFAIL_NAMES = {"broken.test"}


def reply_for(query, tcp=False):
    ident, _flags, qdcount = struct.unpack("!HHH", query[:6])
    name, end = _dnswire._read_name(query, 12)
    qtype = struct.unpack("!H", query[end : end + 2])[0]
    question = query[12 : end + 4]
    if name in NXDOMAIN_NAMES:
        return struct.pack("!HHHHHH", ident, 0x8183, 1, 0, 0, 0) + question
    if name in SERVFAIL_NAMES:
        return struct.pack("!HHHHHH", ident, 0x8182, 1, 0, 0, 0) + question
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
        #: Record types (numbers) the server never answers over UDP.
        self.drop_types = set()
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
            name, end = _dnswire._read_name(data, 12)
            if struct.unpack("!H", data[end : end + 2])[0] in self.drop_types:
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
