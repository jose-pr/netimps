"""Tests for the duho-backed CLI.

Tests that actually drive a command are skipped when the ``cli`` extra is
absent (the skip lives in ``_run``, so it cannot swallow the whole module).
The entry-point tests are *not* skipped: the case worth testing is precisely
the one where duho is missing, and a module-level ``importorskip`` would have
skipped the file before reaching it.
"""

import importlib.util
import json
import subprocess
import sys

import pytest

import netimps
from netimps import cli
from netimps.cli import Netimps, run

_HAS_DUHO = importlib.util.find_spec("duho") is not None

#: Blocks duho the way a missing extra does. ``find_spec``, not the legacy
#: ``find_module``: that hook was removed in 3.12, so a finder defining only
#: it is ignored and the import quietly succeeds.
_BLOCK_DUHO = (
    "import sys, importlib.abc\n"
    "class B(importlib.abc.MetaPathFinder):\n"
    "    def find_spec(self, name, path=None, target=None):\n"
    "        if name == 'duho' or name.startswith('duho.'):\n"
    "            raise ImportError('blocked')\n"
    "        return None\n"
    "sys.meta_path.insert(0, B())\n"
)


def _run(capsys, *argv):
    """Run the CLI and return (exit_code, stdout, stderr)."""
    if not _HAS_DUHO:
        pytest.skip("the cli extra is not installed")
    code = run(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


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
    script = _BLOCK_DUHO + "import netimps\nprint(len(netimps.__all__))\n"
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert int(out.stdout.strip()) == len(netimps.__all__)


def test_run_without_the_cli_extra_names_it(monkeypatch):
    """The console script is installed by a bare ``pip install netimps``.

    duho lives in the ``cli`` extra, so the one thing that user must be told
    is the name of the extra -- not an ImportError traceback from an import
    they never wrote. Blocked in-process here, so the assertion is on the
    exception ``run`` raises rather than on a subprocess's output.
    """

    class _Blocked:
        def find_spec(self, name, path=None, target=None):
            if name == "duho" or name.startswith("duho."):
                raise ImportError("blocked")
            return None

    # An already-imported module is found in sys.modules without ever
    # consulting meta_path, so the finder alone would block nothing.
    for name in [n for n in sys.modules if n == "duho" or n.startswith("duho.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(sys, "meta_path", [_Blocked()] + list(sys.meta_path))

    with pytest.raises(SystemExit) as caught:
        run(["ping", "127.0.0.1"])
    assert "netimps[cli]" in str(caught.value)


def test_the_module_imports_and_exits_cleanly_without_duho():
    """End to end: what the installed console script actually does.

    The console script starts with ``from netimps.cli import run``, so the
    module has to import with duho absent -- a test that only calls ``run``
    in a process where duho was already imported cannot show that.
    """
    script = (
        _BLOCK_DUHO + "from netimps.cli import run\n"
        "raise SystemExit(run(['ping', '127.0.0.1']))\n"
    )
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert out.returncode == 1
    assert "netimps[cli]" in out.stderr
    assert "Traceback" not in out.stderr


# --------------------------------------------------------------------------- #
# commands that need no network                                                #
# --------------------------------------------------------------------------- #


def test_interfaces_lists_something(capsys):
    code, out, _ = _run(capsys, "interfaces")
    assert code in (None, 0)
    assert out.strip()


def test_interfaces_json_shape(capsys):
    _, out, _ = _run(capsys, "interfaces", "--json")
    payload = json.loads(out)
    assert isinstance(payload, list) and payload
    entry = payload[0]
    assert {"name", "index", "mac", "mtu", "is_loopback", "addresses"} <= set(entry)


def test_interfaces_unknown_name_is_an_error(capsys):
    code, out, err = _run(capsys, "interfaces", "no-such-nic")
    assert code == 1
    assert "no interface named" in err
    assert out == ""


def test_addr_classifies_an_address(capsys):
    _, out, _ = _run(capsys, "addr", "127.0.0.1", "--json")
    payload = json.loads(out)
    assert payload["kind"] == "address"
    assert payload["is_loopback"] is True
    assert payload["version"] == 4


def test_addr_classifies_a_mac(capsys):
    _, out, _ = _run(capsys, "addr", "00:00:5e:00:53:01", "--json")
    payload = json.loads(out)
    assert payload["kind"] == "mac"
    assert payload["oui"] == "00:00:5e"
    assert payload["is_multicast"] is False


def test_addr_classifies_a_network(capsys):
    _, out, _ = _run(capsys, "addr", "10.0.0.0/24", "--json")
    payload = json.loads(out)
    assert payload["kind"] == "network"
    assert payload["num_addresses"] == 256


def test_addr_rejects_nonsense(capsys, no_such_host):
    code, _, err = _run(capsys, "addr", "definitely not an address")
    assert code == 2
    assert "error:" in err


def test_port_scheme_to_number(capsys):
    _, out, _ = _run(capsys, "port", "https", "--json")
    assert json.loads(out)["port"] == 443


def test_port_number_to_scheme(capsys):
    _, out, _ = _run(capsys, "port", "443", "--json")
    assert json.loads(out)["scheme"] == "https"


def test_port_with_no_argument_gives_a_free_one(capsys):
    _, out, _ = _run(capsys, "port", "--json")
    assert 1 <= json.loads(out)["free_port"] <= 65535


def test_port_unknown_scheme_exits_nonzero(capsys):
    code, _, _ = _run(capsys, "port", "definitely-not-a-scheme")
    assert code == 1


def test_unknown_scheme_exit_codes_differ_by_command(capsys):
    """Measured, and deliberate -- the two commands ask different questions.

    ``port`` looked the token up and the answer is "no mapping", which is exit
    1 the way an empty ``resolve`` is. ``check`` was left with no port to
    connect to and tested nothing, which is a caller error: exit 2.
    """
    assert _run(capsys, "port", "not-a-scheme")[0] == 1
    assert _run(capsys, "check", "127.0.0.1", "not-a-scheme")[0] == 2


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
    _, out, _ = _run(capsys, "split", value, "--json")
    payload = json.loads(out)
    assert payload["host"] == host
    assert payload["port"] == port


def test_split_rejects_a_bad_port(capsys):
    code, _, err = _run(capsys, "split", "host:not-a-port")
    assert code == 2
    assert "error:" in err


# --------------------------------------------------------------------------- #
# argument handling and error routing                                          #
# --------------------------------------------------------------------------- #


def test_ping_without_a_host_is_a_usage_error(capsys):
    """Not "'' did not answer": a missing argument is not an unreachable host."""
    if not _HAS_DUHO:
        pytest.skip("the cli extra is not installed")
    with pytest.raises(SystemExit) as caught:
        run(["ping"])
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "dst" in captured.err
    assert captured.out == ""


def test_ping_tcp_without_a_port_is_a_usage_error(capsys):
    """The library is right to raise; the CLI must not show the traceback."""
    code, out, err = _run(capsys, "ping", "127.0.0.1", "-m", "tcp")
    assert code == 2
    assert "error:" in err and "port" in err
    assert out == ""


def test_json_errors_keep_stdout_parseable(capsys):
    """A script pipes stdout into a parser; prose there is the failure mode."""
    code, out, err = _run(capsys, "ping", "127.0.0.1", "-m", "tcp", "--json")
    assert code == 2
    assert out == ""
    assert "error:" in err


# --------------------------------------------------------------------------- #
# commands that touch loopback only                                            #
# --------------------------------------------------------------------------- #


def test_check_reports_a_closed_port(capsys):
    port = netimps.get_free_port()
    code, out, _ = _run(capsys, "check", "127.0.0.1", str(port), "-t", "1")
    assert code == 1
    assert "closed" in out


def test_check_accepts_a_scheme_name(capsys):
    """The port argument takes a scheme, not just a number."""
    code, out, _ = _run(capsys, "check", "127.0.0.1", "https", "-t", "0.5", "--json")
    assert json.loads(out)["port"] == 443


def test_check_rejects_an_unknown_scheme(capsys):
    code, out, err = _run(capsys, "check", "127.0.0.1", "not-a-scheme")
    assert code == 2
    assert "error:" in err
    assert out == ""


def test_source_for_loopback(capsys):
    _, out, _ = _run(capsys, "source", "127.0.0.1", "--json")
    assert json.loads(out)["src"].startswith("127.")


def test_route_to_loopback_is_never_via_a_router(capsys):
    """Loopback needs no gateway on any platform.

    ``Route.on_link`` is a tri-state: True where the platform's next-hop
    lookup ran and found no gateway, None where it could not be attempted
    at all (POSIX reads /proc/net/route, which omits loopback entirely).
    Both are honest answers here; ``False`` -- "reached through a router"
    -- is the only one that would be wrong, so that is what this pins.
    Rewritten from an ``is True`` assertion, which pinned the old
    two-state contract.
    """
    _, out, _ = _run(capsys, "route", "127.0.0.1", "--json")
    payload = json.loads(out)
    assert payload["on_link"] is not False
    assert payload["gateway"] is None


def test_ping_loopback(capsys):
    code, out, _ = _run(capsys, "ping", "127.0.0.1", "-t", "2", "--json")
    assert code == 0
    assert json.loads(out)["ok"] is True


def test_ping_exit_code_mirrors_reachability(capsys):
    """Exit status follows ping(8): non-zero when it did not answer."""
    code, _, _ = _run(capsys, "ping", "192.0.2.99", "-t", "1")
    assert code == 1


def test_scan_finds_a_listener(capsys):
    import socket

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        _, out, _ = _run(
            capsys, "scan", "127.0.0.1", "-p", str(port), "-t", "1", "--json"
        )
        assert json.loads(out)["ports"] == [port]
    finally:
        server.close()


def test_scan_refuses_a_huge_network(capsys):
    code, _, err = _run(capsys, "scan", "10.0.0.0/8", "-p", "80")
    assert code == 2
    assert "error:" in err


# --------------------------------------------------------------------------- #
# rendering contracts                                                          #
# --------------------------------------------------------------------------- #


class _FakeRoute:
    """The five attributes the ``route`` command reads off a :class:`Route`.

    A stand-in rather than a real ``Route``, because ``on_link`` is a derived
    property there: the point of these tests is what the CLI *prints* for each
    of its three values, which a real lookup cannot be made to produce on
    demand.
    """

    def __init__(self, gateway=None, on_link=None):
        self.dst = "192.0.2.1"
        self.src = "192.0.2.10"
        self.gateway = gateway
        self.interface_index = 0
        self.on_link = on_link


@pytest.mark.parametrize(
    "gateway, on_link, expect_text",
    [
        # None is "the next-hop lookup never ran", not "no router needed".
        (None, None, "on-link  unknown"),
        (None, True, "gateway  (on-link, no router)"),
        ("192.0.2.254", False, "gateway  192.0.2.254"),
    ],
)
def test_route_renders_the_on_link_tri_state(
    capsys, monkeypatch, gateway, on_link, expect_text
):
    """An undetermined route must not be printed as an on-link one.

    ``--json`` carries the value itself (``null`` / ``true`` / ``false``), and
    the text form has to keep the same three cases apart -- claiming
    "on-link, no router" for a lookup that was never attempted states as fact
    the one thing that was not established.
    """
    monkeypatch.setattr(cli, "get_route", lambda dst: _FakeRoute(gateway, on_link))

    _, out, _ = _run(capsys, "route", "192.0.2.1", "--json")
    payload = json.loads(out)
    assert payload["on_link"] is on_link
    assert payload["gateway"] == gateway

    _, text, _ = _run(capsys, "route", "192.0.2.1")
    assert expect_text in text
    if on_link is not True:
        assert "on-link, no router" not in text


def test_route_hops_line_is_added_not_sliced_in(capsys, monkeypatch):
    """``--hops`` appends a line; without it nothing extra is printed."""
    monkeypatch.setattr(cli, "get_route", lambda dst: _FakeRoute(None, True))
    monkeypatch.setattr(cli, "hop_count", lambda dst: 3)

    _, plain, _ = _run(capsys, "route", "192.0.2.1")
    assert "hops" not in plain

    _, with_hops, _ = _run(capsys, "route", "192.0.2.1", "--hops")
    assert "hops     3" in with_hops
    assert "None" not in with_hops


@pytest.mark.parametrize("command", ["ping", "mtu"])
def test_method_choices_are_enforced(capsys, command):
    """Guards the ``_ty.Annotated[str, Choice(...)]`` spelling of the field.

    duho's ``Arg`` *is* ``typing.Annotated``, but it is bound as a variable
    and so unusable in type position for a checker. The fields spell
    ``Annotated`` directly instead -- which is only equivalent if duho still
    sees the ``Choice`` metadata, i.e. if argparse still rejects a value that
    is not one of the three.
    """
    if not _HAS_DUHO:
        pytest.skip("the cli extra is not installed")
    with pytest.raises(SystemExit) as caught:
        run([command, "127.0.0.1", "-m", "carrier-pigeon"])
    assert caught.value.code == 2
    assert "carrier-pigeon" in capsys.readouterr().err
