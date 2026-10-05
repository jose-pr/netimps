"""The command line, driven through the real parser.

Every test builds its command from an argument vector with ``duho.parse`` and
calls it, so the fields, the aliases and the exit status are the ones a user
gets; none calls a function underneath. The tests that run a command are
skipped when the ``cli`` extra is absent (the skip lives in ``_command``, so it
cannot swallow the module). The entry-point tests are *not* skipped: the case
worth testing is precisely the one where duho is missing.

Statuses, as ``grep``: 0 found or yes, 1 nothing found or the answer was no,
2 an error. ``route``, ``addr`` and ``split`` always answer or fail, so they
have no "no" case; ``interfaces`` and ``route`` take no argument that can be
wrong, so their bad-input case is a usage error from the parser.
"""

import importlib.util
import json
import socket
import subprocess
import sys

import pytest

import netimps
from netimps import IPv4Address
from netimps.cli import Netimps, main
from netimps.cli import mtu as _mtu_cli
from netimps.cli import resolve as _resolve_cli
from netimps.cli import route as _route_cli
from netimps.cli import source as _source_cli

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


def _command(*argv):
    """The command the real parser builds from ``argv``."""
    if not _HAS_DUHO:
        pytest.skip("the cli extra is not installed")
    import duho

    return duho.parse(Netimps, list(argv))


def _run(capsys, *argv):
    """Parse ``argv``, call the command, and return (status, stdout, stderr)."""
    status = _command(*argv)()
    captured = capsys.readouterr()
    return status, captured.out, captured.err


@pytest.fixture
def listener():
    """A real listening socket on loopback, yielding its port."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    yield server.getsockname()[1]
    server.close()


@pytest.fixture
def two_records(monkeypatch):
    monkeypatch.setattr(
        _resolve_cli, "resolve", lambda *a, **k: [IPv4Address("192.0.2.1")]
    )


@pytest.fixture
def no_records(monkeypatch):
    monkeypatch.setattr(_resolve_cli, "resolve", lambda *a, **k: [])


@pytest.fixture
def mtu_answer(monkeypatch):
    monkeypatch.setattr(_mtu_cli, "discover_mtu", lambda *a, **k: 1500)


@pytest.fixture
def mtu_none(monkeypatch):
    monkeypatch.setattr(_mtu_cli, "discover_mtu", lambda *a, **k: None)


@pytest.fixture
def no_source(monkeypatch):
    monkeypatch.setattr(_source_cli, "get_source_ip", lambda dst: None)


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


@pytest.mark.parametrize(
    "alias, name",
    [
        ("ifaces", "Interfaces"),
        ("if", "Interfaces"),
        ("dns", "Resolve"),
        ("tcp", "Check"),
        ("parse", "Addr"),
        ("src", "Source"),
    ],
)
def test_an_alias_builds_the_same_command(alias, name):
    argv = [alias] + ([] if name == "Interfaces" else ["127.0.0.1"])
    argv += ["https"] if name == "Check" else []
    assert type(_command(*argv)).__name__ == name


def test_main_returns_an_int(capsys):
    """The entry point never returns ``None``: ``SystemExit(main())`` is the
    whole of ``__main__``."""
    if not _HAS_DUHO:
        pytest.skip("the cli extra is not installed")
    status = main(["port", "https"])
    assert status == 0 and type(status) is int
    assert capsys.readouterr().out.strip() == "443"


def test_duho_is_optional():
    """The library must import without the cli extra, and so must the
    package: a caller using netimps as a library should never need duho."""
    script = _BLOCK_DUHO + "import netimps, netimps.cli\nprint(len(netimps.__all__))\n"
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert int(out.stdout.strip()) == len(netimps.__all__)


def test_main_without_the_cli_extra_names_it(monkeypatch):
    """The console script is installed by a bare ``pip install netimps``.

    duho lives in the ``cli`` extra, so the one thing that user must be told
    is the name of the extra, not an ImportError traceback from an import
    they never wrote.
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
        main(["ping", "127.0.0.1"])
    assert "netimps[cli]" in str(caught.value)


def test_the_module_exits_cleanly_without_duho():
    """End to end: what the installed console script actually does."""
    script = (
        _BLOCK_DUHO + "from netimps.cli import main\n"
        "raise SystemExit(main(['ping', '127.0.0.1']))\n"
    )
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert out.returncode == 1
    assert "netimps[cli]" in out.stderr
    assert "Traceback" not in out.stderr


# --------------------------------------------------------------------------- #
# exit status: success (0), "no" (1), bad input (2), one case each             #
# --------------------------------------------------------------------------- #


def test_interfaces_status_found(capsys):
    status, out, _ = _run(capsys, "interfaces")
    assert status == 0 and out.strip()


def test_interfaces_status_no(capsys):
    status, out, err = _run(capsys, "interfaces", "no-such-nic")
    assert status == 1
    assert "no interface named" in err
    assert out == ""


def test_interfaces_bad_input_is_a_usage_error():
    with pytest.raises(SystemExit) as caught:
        _command("interfaces", "--no-such-flag")
    assert caught.value.code == 2


def test_ping_status_found(capsys):
    assert _run(capsys, "ping", "127.0.0.1", "-t", "2")[0] == 0


def test_ping_status_no(capsys, fake_program):
    """Follows ping(8): non-zero when it did not answer."""
    fake_program("ping", returncode=1)
    assert _run(capsys, "ping", "192.0.2.99", "-t", "1")[0] == 1


def test_ping_status_bad_input(capsys):
    """The library is right to raise; the command shows no traceback."""
    status, out, err = _run(capsys, "ping", "127.0.0.1", "-m", "tcp")
    assert status == 2
    assert "error:" in err and "port" in err
    assert out == ""


def test_ping_without_a_host_is_a_usage_error(capsys):
    """Not "'' did not answer": a missing argument is not an unreachable host."""
    with pytest.raises(SystemExit) as caught:
        _command("ping")
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "dst" in captured.err
    assert captured.out == ""


def test_resolve_status_found(capsys, two_records):
    status, out, _ = _run(capsys, "resolve", "example.com")
    assert status == 0 and out.strip() == "192.0.2.1"


def test_resolve_status_no(capsys, no_records):
    status, out, _ = _run(capsys, "resolve", "example.com")
    assert status == 1 and out == ""


def test_resolve_status_bad_input(capsys, no_such_host):
    status, _, err = _run(capsys, "resolve", "example.com", "-n", "bad ns!")
    assert status == 2 and "error:" in err


def test_check_status_found(capsys, listener):
    status, out, _ = _run(capsys, "check", "127.0.0.1", str(listener))
    assert status == 0 and "open" in out


def test_check_status_no(capsys):
    port = netimps.get_free_port()
    status, out, _ = _run(capsys, "check", "127.0.0.1", str(port), "-t", "1")
    assert status == 1 and "closed" in out


def test_check_status_bad_input(capsys):
    status, out, err = _run(capsys, "check", "127.0.0.1", "not-a-scheme")
    assert status == 2 and "error:" in err and out == ""


def test_check_accepts_a_scheme_name(capsys):
    _, out, _ = _run(capsys, "check", "127.0.0.1", "https", "-t", "0.5", "--json")
    assert json.loads(out)["port"] == 443


def test_route_status_found(capsys):
    status, out, _ = _run(capsys, "route", "127.0.0.1")
    assert status == 0 and "dst" in out


def test_route_bad_input_is_a_usage_error():
    with pytest.raises(SystemExit) as caught:
        _command("route", "--no-such-flag")
    assert caught.value.code == 2


def test_mtu_status_found(capsys, mtu_answer):
    status, out, _ = _run(capsys, "mtu", "192.0.2.1")
    assert status == 0 and "MTU 1500" in out


def test_mtu_status_no(capsys, mtu_none):
    status, out, _ = _run(capsys, "mtu", "192.0.2.1")
    assert status == 1 and "no answer" in out


def test_mtu_status_bad_input(capsys):
    status, _, err = _run(capsys, "mtu", "127.0.0.1", "-p", "99999")
    assert status == 2 and "error:" in err


def test_scan_status_found(capsys, listener):
    status, out, _ = _run(capsys, "scan", "127.0.0.1", "-p", str(listener), "-t", "1")
    assert status == 0 and "/tcp open" in out


def test_scan_status_no(capsys):
    port = netimps.get_free_port()
    status, out, _ = _run(capsys, "scan", "127.0.0.1", "-p", str(port), "-t", "1")
    assert status == 1 and "no open ports found" in out


def test_scan_of_a_network_with_nothing_open_is_status_1(capsys):
    port = netimps.get_free_port()
    status, out, _ = _run(capsys, "scan", "127.0.0.0/30", "-p", str(port), "-t", "0.5")
    assert status == 1 and "no hosts responded" in out


def test_scan_status_bad_input(capsys):
    status, _, err = _run(capsys, "scan", "10.0.0.0/8", "-p", "80")
    assert status == 2 and "error:" in err


def test_scan_takes_a_comma_list(capsys, listener):
    other = netimps.get_free_port()
    _, out, _ = _run(
        capsys, "scan", "127.0.0.1", "-p", "%d,%d" % (other, listener), "-t", "1"
    )
    assert "%d/tcp open" % listener in out
    assert "%d/tcp open" % other not in out


def test_scan_rejects_an_empty_port_item(capsys):
    status, _, err = _run(capsys, "scan", "127.0.0.1", "-p", "22,,80")
    assert status == 2 and "error:" in err


@pytest.mark.parametrize(
    "value, kind",
    [
        ("127.0.0.1", "address"),
        ("00:00:5e:00:53:01", "mac"),
        ("10.0.0.0/24", "network"),
        ("10.0.0.5/24", "network"),
    ],
)
def test_addr_status_found(capsys, value, kind):
    status, out, _ = _run(capsys, "addr", value, "--json")
    assert status == 0
    assert json.loads(out)["kind"] == kind


def test_addr_status_bad_input(capsys, no_such_host):
    status, _, err = _run(capsys, "addr", "definitely not an address")
    assert status == 2 and "error:" in err


def test_addr_details(capsys):
    payload = json.loads(_run(capsys, "addr", "127.0.0.1", "--json")[1])
    assert payload["is_loopback"] is True and payload["version"] == 4
    payload = json.loads(_run(capsys, "addr", "00:00:5e:00:53:01", "--json")[1])
    assert payload["oui"] == "00:00:5e" and payload["is_multicast"] is False
    payload = json.loads(_run(capsys, "addr", "10.0.0.0/24", "--json")[1])
    assert payload["num_addresses"] == 256


def test_source_status_found(capsys):
    status, out, _ = _run(capsys, "source", "127.0.0.1")
    assert status == 0 and out.strip().startswith("127.")


def test_source_status_no(capsys, no_source):
    status, out, err = _run(capsys, "source", "192.0.2.1")
    assert status == 1 and out == "" and "no route to" in err


def test_source_bad_input_is_a_usage_error():
    with pytest.raises(SystemExit) as caught:
        _command("source", "127.0.0.1", "extra")
    assert caught.value.code == 2


def test_port_status_found(capsys):
    status, out, _ = _run(capsys, "port", "https")
    assert status == 0 and out.strip() == "443"
    assert _run(capsys, "port", "443")[1].strip() == "https"
    free = int(_run(capsys, "port")[1])
    assert 1 <= free <= 65535


def _port_without_a_service():
    """A port number the services database has no name for, asked of the
    platform: macOS names 9999 (``distinct``) where Linux and Windows do not."""
    import socket

    for port in range(65000, 60000, -1):
        try:
            socket.getservbyport(port)
        except OSError:
            if netimps.get_default_scheme(port) is None:
                return str(port)
    pytest.skip("every port from 60001 to 65000 has a service name here")


def test_port_status_no(capsys):
    assert _run(capsys, "port", "definitely-not-a-scheme")[0] == 1
    assert _run(capsys, "port", _port_without_a_service())[0] == 1


def test_port_status_bad_input(capsys):
    status, _, err = _run(capsys, "port", "99999")
    assert status == 2 and "out of range" in err


def test_unknown_scheme_statuses_differ_by_command(capsys):
    """The two commands ask different questions. ``port`` looked the token up
    and the answer is "no mapping" (1); ``check`` was left with no port to
    connect to and tested nothing, which is an error (2)."""
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
def test_split_status_found(capsys, value, host, port):
    status, out, _ = _run(capsys, "split", value, "--json")
    payload = json.loads(out)
    assert status == 0
    assert payload == {"host": host, "port": port}


def test_split_status_bad_input(capsys):
    status, _, err = _run(capsys, "split", "host:not-a-port")
    assert status == 2 and "error:" in err


# --------------------------------------------------------------------------- #
# -q: no result line, the status alone; --json unaffected                      #
# --------------------------------------------------------------------------- #


def _quiet_cases():
    """(argv, status): a success or a "no" for every command that has one."""
    return [
        (["interfaces"], 0),
        (["interfaces", "no-such-nic"], 1),
        (["ping", "127.0.0.1", "-t", "2"], 0),
        (["ping", "192.0.2.99", "-t", "1"], 1),
        (["route", "127.0.0.1"], 0),
        (["addr", "127.0.0.1"], 0),
        (["split", "[::1]:80"], 0),
        (["port", "https"], 0),
        (["port", "not-a-scheme"], 1),
        (["source", "127.0.0.1"], 0),
        (["check", "127.0.0.1", "%PORT%", "-t", "1"], 1),
        (["scan", "127.0.0.1", "-p", "%PORT%", "-t", "1"], 1),
    ]


@pytest.mark.parametrize("argv, status", _quiet_cases())
def test_q_prints_nothing_and_keeps_the_status(capsys, fake_program, argv, status):
    if argv[:2] == ["ping", "192.0.2.99"]:
        fake_program("ping", returncode=1)  # no host answers; send nothing
    port = str(netimps.get_free_port())
    argv = [a.replace("%PORT%", port) for a in argv]
    loud = _run(capsys, *argv)
    quiet = _run(capsys, *argv, "-q")
    assert loud[0] == quiet[0] == status
    assert quiet[1] == ""
    assert quiet[2] == ""


def test_q_on_the_fixture_backed_commands(capsys, two_records, mtu_answer):
    assert _run(capsys, "resolve", "example.com", "-q")[:2] == (0, "")
    assert _run(capsys, "mtu", "192.0.2.1", "-q")[:2] == (0, "")


def test_q_with_no_answer_on_the_fixture_backed_commands(capsys, no_records, mtu_none):
    assert _run(capsys, "resolve", "example.com", "-q")[:2] == (1, "")
    assert _run(capsys, "mtu", "192.0.2.1", "-q")[:2] == (1, "")


def test_q_keeps_a_listener_silent_and_found(capsys, listener):
    assert _run(capsys, "check", "127.0.0.1", str(listener), "-q")[:2] == (0, "")
    assert _run(capsys, "scan", "127.0.0.1", "-p", str(listener), "-q")[:2] == (0, "")


def test_q_still_reports_an_error_on_stderr(capsys):
    status, out, err = _run(capsys, "split", "host:not-a-port", "-q")
    assert status == 2 and out == "" and "error:" in err


def test_q_does_not_touch_json(capsys):
    plain = _run(capsys, "port", "https", "--json")
    quiet = _run(capsys, "port", "https", "--json", "-q")
    assert plain == quiet
    assert json.loads(quiet[1])["port"] == 443


def test_v_still_prints_the_result_line(capsys):
    status, out, _ = _run(capsys, "port", "https", "-v")
    assert status == 0 and out.strip() == "443"


# --------------------------------------------------------------------------- #
# --json: the shapes are a contract                                            #
# --------------------------------------------------------------------------- #


def test_interfaces_json_shape(capsys):
    _, out, _ = _run(capsys, "interfaces", "--json")
    payload = json.loads(out)
    assert isinstance(payload, list) and payload
    assert set(payload[0]) == {
        "name",
        "index",
        "mac",
        "mtu",
        "is_loopback",
        "addresses",
        "is_up",
        "raw",
    }


def test_interfaces_json_with_raw_is_serialisable(capsys):
    _, out, _ = _run(capsys, "interfaces", "--json", "--raw")
    assert all("raw" in entry for entry in json.loads(out))


def test_interfaces_text_marks_a_down_interface(capsys):
    _, out, _ = _run(capsys, "interfaces")
    down = [i for i in netimps.get_interfaces() if i.is_up is False]
    assert out.count("[down]") == len(down)


def test_ping_json_shape(capsys):
    _, out, _ = _run(capsys, "ping", "127.0.0.1", "-t", "2", "--json")
    payload = json.loads(out)
    assert set(payload) == {"ok", "host", "rtt_ms", "ttl", "attempts", "method"}
    assert payload["ok"] is True


def test_resolve_json_shape(capsys, two_records):
    assert json.loads(_run(capsys, "resolve", "example.com", "--json")[1]) == [
        "192.0.2.1"
    ]


def test_check_json_shape(capsys, listener):
    payload = json.loads(_run(capsys, "check", "127.0.0.1", str(listener), "--json")[1])
    assert payload == {"ok": True, "host": "127.0.0.1", "port": listener}


def test_route_json_shape(capsys):
    payload = json.loads(_run(capsys, "route", "127.0.0.1", "--json")[1])
    assert set(payload) == {"dst", "src", "gateway", "interface_index", "on_link"}
    assert payload["on_link"] is not False
    assert payload["gateway"] is None


def test_mtu_json_shape(capsys, mtu_answer):
    payload = json.loads(_run(capsys, "mtu", "192.0.2.1", "--json")[1])
    assert payload == {"dst": "192.0.2.1", "mtu": 1500, "method": "icmp"}


def test_scan_json_shapes(capsys, listener):
    host = json.loads(
        _run(capsys, "scan", "127.0.0.1", "-p", str(listener), "-t", "1", "--json")[1]
    )
    assert host == {"host": "127.0.0.1", "ports": [listener]}
    net = json.loads(
        _run(capsys, "scan", "127.0.0.1/32", "-p", str(listener), "-t", "1", "--json")[
            1
        ]
    )
    assert net == [{"host": "127.0.0.1", "ports": [listener]}]


def test_source_json_shape(capsys):
    payload = json.loads(_run(capsys, "source", "127.0.0.1", "--json")[1])
    assert set(payload) == {"dst", "src"} and payload["src"].startswith("127.")


def test_port_json_shapes(capsys):
    assert json.loads(_run(capsys, "port", "https", "--json")[1]) == {
        "scheme": "https",
        "port": 443,
    }
    assert json.loads(_run(capsys, "port", "443", "--json")[1]) == {
        "port": 443,
        "scheme": "https",
    }
    assert set(json.loads(_run(capsys, "port", "--json")[1])) == {"free_port"}


def test_json_errors_keep_stdout_parseable(capsys):
    """A script pipes stdout into a parser; prose there is the failure mode."""
    status, out, err = _run(capsys, "ping", "127.0.0.1", "-m", "tcp", "--json")
    assert status == 2
    assert out == ""
    assert "error:" in err


# --------------------------------------------------------------------------- #
# rendering contracts                                                          #
# --------------------------------------------------------------------------- #


class _FakeRoute:
    """The five attributes the ``route`` command reads off a :class:`Route`.

    A stand-in rather than a real ``Route``, because ``on_link`` is a derived
    property there: the point of these tests is what the command *prints* for
    each of its three values, which a real lookup cannot be made to produce on
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
    the text form has to keep the same three cases apart.
    """
    monkeypatch.setattr(
        _route_cli, "get_route", lambda dst: _FakeRoute(gateway, on_link)
    )

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
    monkeypatch.setattr(_route_cli, "get_route", lambda dst: _FakeRoute(None, True))
    monkeypatch.setattr(_route_cli, "count_hops", lambda dst: 3)

    _, plain, _ = _run(capsys, "route", "192.0.2.1")
    assert "hops" not in plain

    _, with_hops, _ = _run(capsys, "route", "192.0.2.1", "--hops")
    assert "hops     3" in with_hops
    assert "None" not in with_hops


@pytest.mark.parametrize("command", ["ping", "mtu"])
def test_method_choices_are_enforced(capsys, command):
    """Guards the ``_ty.Annotated[str, Choice(...)]`` spelling of the field:
    duho must still see the ``Choice`` metadata, i.e. argparse still rejects a
    value that is not one of the three."""
    with pytest.raises(SystemExit) as caught:
        _command(command, "127.0.0.1", "-m", "carrier-pigeon")
    assert caught.value.code == 2
    assert "carrier-pigeon" in capsys.readouterr().err
