"""Tests for the duho-backed CLI.

Skipped wholesale when the ``cli`` extra is absent, since duho is optional --
importing netimps itself must never require it.
"""

import json

import pytest

pytest.importorskip("duho", reason="the cli extra is not installed")

import netimps
from netimps.cli import Netimps, run


def _run(capsys, *argv):
    """Run the CLI and return (exit_code, stdout)."""
    code = run(list(argv))
    return code, capsys.readouterr().out


# --------------------------------------------------------------------------- #
# wiring                                                                       #
# --------------------------------------------------------------------------- #


def test_every_subcommand_is_registered():
    names = {c._parsername_ for c in Netimps._subcommands_}
    assert names == {
        "interfaces",
        "ping",
        "resolve",
        "check",
        "route",
        "mtu",
        "scan",
        "addr",
        "source",
        "port",
        "split",
    }


def test_duho_is_optional():
    """The library must import without the cli extra.

    duho is a CLI-only dependency; a consumer using netimps as a library
    should never be forced to install it.
    """
    import subprocess
    import sys

    script = (
        "import sys, importlib.abc\n"
        "class B(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'duho' or name.startswith('duho.'):\n"
        "            raise ImportError('blocked')\n"
        "        return None\n"
        "sys.meta_path.insert(0, B())\n"
        "import netimps\n"
        "print(len(netimps.__all__))\n"
    )
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert int(out.stdout.strip()) == len(netimps.__all__)


# --------------------------------------------------------------------------- #
# commands that need no network                                                #
# --------------------------------------------------------------------------- #


def test_interfaces_lists_something(capsys):
    code, out = _run(capsys, "interfaces")
    assert code in (None, 0)
    assert out.strip()


def test_interfaces_json_shape(capsys):
    _, out = _run(capsys, "interfaces", "--json")
    payload = json.loads(out)
    assert isinstance(payload, list) and payload
    entry = payload[0]
    assert {"name", "index", "mac", "mtu", "is_loopback", "addresses"} <= set(entry)


def test_interfaces_unknown_name_is_an_error(capsys):
    code, out = _run(capsys, "interfaces", "no-such-nic")
    assert code == 1
    assert "no interface named" in out


def test_addr_classifies_an_address(capsys):
    _, out = _run(capsys, "addr", "127.0.0.1", "--json")
    payload = json.loads(out)
    assert payload["kind"] == "address"
    assert payload["is_loopback"] is True
    assert payload["version"] == 4


def test_addr_classifies_a_mac(capsys):
    _, out = _run(capsys, "addr", "00:00:5e:00:53:01", "--json")
    payload = json.loads(out)
    assert payload["kind"] == "mac"
    assert payload["oui"] == "00:00:5e"
    assert payload["is_multicast"] is False


def test_addr_classifies_a_network(capsys):
    _, out = _run(capsys, "addr", "10.0.0.0/24", "--json")
    payload = json.loads(out)
    assert payload["kind"] == "network"
    assert payload["num_addresses"] == 256


def test_addr_rejects_nonsense(capsys):
    code, out = _run(capsys, "addr", "definitely not an address")
    assert code == 2
    assert "error:" in out


def test_port_scheme_to_number(capsys):
    _, out = _run(capsys, "port", "https", "--json")
    assert json.loads(out)["port"] == 443


def test_port_number_to_scheme(capsys):
    _, out = _run(capsys, "port", "443", "--json")
    assert json.loads(out)["scheme"] == "https"


def test_port_with_no_argument_gives_a_free_one(capsys):
    _, out = _run(capsys, "port", "--json")
    assert 1 <= json.loads(out)["free_port"] <= 65535


def test_port_unknown_scheme_exits_nonzero(capsys):
    code, _ = _run(capsys, "port", "definitely-not-a-scheme")
    assert code == 1


@pytest.mark.parametrize(
    "value, host, port",
    [
        ("[::1]:8080", "::1", 8080),
        ("::1", "::1", None),  # the case hand-rolled splitters get wrong
        ("example.com:443", "example.com", 443),
        ("10.0.0.5", "10.0.0.5", None),
    ],
)
def test_split_handles_ipv6(capsys, value, host, port):
    _, out = _run(capsys, "split", value, "--json")
    payload = json.loads(out)
    assert payload["host"] == host
    assert payload["port"] == port


def test_split_rejects_a_bad_port(capsys):
    code, out = _run(capsys, "split", "host:not-a-port")
    assert code == 2
    assert "error:" in out


# --------------------------------------------------------------------------- #
# commands that touch loopback only                                            #
# --------------------------------------------------------------------------- #


def test_check_reports_a_closed_port(capsys):
    port = netimps.get_free_port()
    code, out = _run(capsys, "check", "127.0.0.1", str(port), "-t", "1")
    assert code == 1
    assert "closed" in out


def test_check_accepts_a_scheme_name(capsys):
    """The port argument takes a scheme, not just a number."""
    code, out = _run(capsys, "check", "127.0.0.1", "https", "-t", "0.5", "--json")
    assert json.loads(out)["port"] == 443


def test_check_rejects_an_unknown_scheme(capsys):
    code, out = _run(capsys, "check", "127.0.0.1", "not-a-scheme")
    assert code == 2
    assert "error:" in out


def test_source_for_loopback(capsys):
    _, out = _run(capsys, "source", "127.0.0.1", "--json")
    assert json.loads(out)["src"].startswith("127.")


def test_route_to_loopback_is_on_link(capsys):
    _, out = _run(capsys, "route", "127.0.0.1", "--json")
    payload = json.loads(out)
    assert payload["on_link"] is True
    assert payload["gateway"] is None


def test_ping_loopback(capsys):
    code, out = _run(capsys, "ping", "127.0.0.1", "-t", "2", "--json")
    assert code == 0
    assert json.loads(out)["ok"] is True


def test_ping_exit_code_mirrors_reachability(capsys):
    """Exit status follows ping(8): non-zero when it did not answer."""
    code, _ = _run(capsys, "ping", "192.0.2.99", "-t", "1")
    assert code == 1


def test_scan_finds_a_listener(capsys):
    import socket

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        _, out = _run(capsys, "scan", "127.0.0.1", "-p", str(port), "-t", "1", "--json")
        assert json.loads(out)["ports"] == [port]
    finally:
        server.close()


def test_scan_refuses_a_huge_network(capsys):
    code, out = _run(capsys, "scan", "10.0.0.0/8", "-p", "80")
    assert code == 2
    assert "error:" in out
