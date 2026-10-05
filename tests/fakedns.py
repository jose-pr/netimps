"""A fake nameserver on loopback, shared by the resolver tests.

It answers from :data:`ZONE` by the question's name and type over UDP and TCP
on one port, never answers a name containing ``silent``, and can be told to
drop one record type. Nothing here leaves the machine.
"""

import ipaddress
import socket
import struct
import threading

from netimps._dns import _dnswire
from netimps._fqdn import _wire as _namewire

ZONE = {
    ("host.test", 1): [("host.test", 1, bytes([10, 0, 0, 5]))],
    ("host.test", 28): [("host.test", 28, ipaddress.IPv6Address("fd00::5").packed)],
    ("alias.test", 1): [
        ("alias.test", 5, _namewire.encode_name("host.test")),
        ("host.test", 1, bytes([10, 0, 0, 5])),
    ],
    ("mail.test", 15): [
        ("mail.test", 15, struct.pack("!H", 10) + _namewire.encode_name("mx.mail.test"))
    ],
    ("note.test", 16): [("note.test", 16, b"\x05hello\x06 world")],
    ("5.0.0.10.in-addr.arpa", 12): [
        ("5.0.0.10.in-addr.arpa", 12, _namewire.encode_name("host.test"))
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
        _namewire.encode_name(owner)
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
        # UDP is bound FIRST, to an ephemeral port, and TCP is then asked for
        # that number. The other order walks a TCP counter that Windows hands
        # out almost sequentially into the 100 to 200 port blocks it reserves
        # for UDP only, where every pair fails until the counter leaves them.
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp.bind((host, 0))
            self.port = self.udp.getsockname()[1]
            self.tcp = socket.socket()
            try:
                self.tcp.bind((host, self.port))
                self.tcp.listen(5)
            except OSError:
                self.tcp.close()
                raise
        except OSError:
            self.udp.close()
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


#: Attempts at finding a number free on both transports. Each one binds a fresh
#: ephemeral UDP port, so a refusal says nothing about the next attempt.
_PORT_ATTEMPTS = 50


class PortPairUnavailable(OSError):
    """No number could be bound on both UDP and TCP; says which and why."""


def make_nameserver(host="127.0.0.1"):
    """A :class:`FakeNameserver`, retrying until a UDP and TCP pair binds.

    Raises :class:`PortPairUnavailable` naming every port that was refused and
    the error, so a skip or a failure says what the host did rather than that
    something was busy.
    """
    refused = []
    for _ in range(_PORT_ATTEMPTS):
        try:
            return FakeNameserver(host)
        except OSError as exc:
            refused.append(exc)
    raise PortPairUnavailable(
        "no port free on both UDP and TCP after %d attempts; last refusals: %s"
        % (_PORT_ATTEMPTS, "; ".join(str(exc) for exc in refused[-3:]))
    )
