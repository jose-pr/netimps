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

    def refuse_twice(self, host="127.0.0.1", port=0):
        attempts.append(port)
        if len(attempts) <= 2:
            raise OSError(10013, "refused")
        real_init(self, host, port)

    monkeypatch.setattr(fakedns.FakeNameserver, "__init__", refuse_twice)
    fake = fakedns.make_nameserver()
    try:
        # At least three: the pair asked for after the two refusals is a real
        # one, and the host may refuse that too before one binds.
        assert len(attempts) >= 3
        assert fake.port > 0
    finally:
        fake.close()


def test_giving_up_names_the_error_the_host_gave(monkeypatch):
    def always_refuse(self, host="127.0.0.1", port=0):
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


def test_after_the_os_choices_a_number_of_the_dynamic_range_is_named(monkeypatch):
    """A counter that walks into a one-transport block stays inside it, so once
    the OS's own picks have failed the search names numbers itself."""
    asked = []

    def refuse(self, host="127.0.0.1", port=0):
        asked.append(port)
        raise OSError(10013, "refused")

    monkeypatch.setattr(fakedns.FakeNameserver, "__init__", refuse)
    with pytest.raises(fakedns.PortPairUnavailable, match="port [0-9]+: "):
        fakedns.make_nameserver()
    assert asked[: fakedns._OS_CHOSEN_ATTEMPTS] == [0] * fakedns._OS_CHOSEN_ATTEMPTS
    assert all(49152 <= port <= 65535 for port in asked[fakedns._OS_CHOSEN_ATTEMPTS :])
