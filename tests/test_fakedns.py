"""The fake nameserver's port-pair search reports what the host refused.

A search that gives up quietly turns three tests into skips that come and go
with the host's port reservations (Windows keeps UDP-only blocks of 100 to 200
ports), and nothing says why.
"""

import pytest

import fakedns


def test_a_refused_pair_is_retried_on_a_fresh_port(monkeypatch):
    real_init = fakedns.FakeNameserver.__init__
    attempts = []

    def refuse_twice(self, host="127.0.0.1"):
        attempts.append(host)
        if len(attempts) <= 2:
            raise OSError(10013, "refused")
        real_init(self, host)

    monkeypatch.setattr(fakedns.FakeNameserver, "__init__", refuse_twice)
    fake = fakedns.make_nameserver()
    try:
        assert len(attempts) == 3
        assert fake.port > 0
    finally:
        fake.close()


def test_giving_up_names_the_error_the_host_gave(monkeypatch):
    def always_refuse(self, host="127.0.0.1"):
        raise OSError(10013, "an attempt to access a socket was forbidden")

    monkeypatch.setattr(fakedns.FakeNameserver, "__init__", always_refuse)
    with pytest.raises(fakedns.PortPairUnavailable, match="forbidden") as caught:
        fakedns.make_nameserver()
    assert "after %d attempts" % fakedns._PORT_ATTEMPTS in str(caught.value)


def test_the_pair_shares_one_number_on_both_transports():
    fake = fakedns.make_nameserver()
    try:
        assert fake.udp.getsockname()[1] == fake.tcp.getsockname()[1] == fake.port
    finally:
        fake.close()
