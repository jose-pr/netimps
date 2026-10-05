"""The README's examples run.

The Python example of "Quick start" is executed statement by statement in one
namespace, and each command line of "Command line" is built through the real
parser and, where it can answer offline, called. A renamed function, a dropped
flag or a changed result shape fails here and not in a reader's terminal.

Nothing leaves the host: the network guard applies. A statement that needs the
network or a fixed port is not executed and is named in :data:`_NOT_RUN` with
its reason; it is still compiled, and a command line is still parsed. A
statement whose only offline obstacle is a fixed port or a number is run with
that number substituted. An entry that no longer matches a README line fails,
so the tables cannot go stale.
"""

import ast
import importlib.util
import pathlib
import re
import shlex
import socket

import pytest

import netimps

README = pathlib.Path(__file__).resolve().parent.parent / "README.md"
_TEXT = README.read_text(encoding="utf-8")
_HAS_DUHO = importlib.util.find_spec("duho") is not None


def _section(heading):
    start = _TEXT.index("\n## %s\n" % heading)
    end = _TEXT.find("\n## ", start + 1)
    return _TEXT[start : end if end != -1 else None]


def _blocks(section, language):
    return re.findall(r"```%s\n(.*?)```" % language, section, re.DOTALL)


#: Python statements that are compiled but not executed, by their first line.
#: The value is the reason and, optionally, the source of a stand-in run in its
#: place so that later statements find the name they use.
_NOT_RUN = {
    'netimps.wait_for_port("localhost", 5432, deadline=60)': (
        "waits up to a minute for a service that is not there; wait_for_port is "
        "tested against a real listener in test_sockets",
        None,
    ),
    'netimps.resolve("example.com")[0].is_global': (
        "needs a name server; resolution is tested against the fake name server "
        "in test_dns_wire",
        None,
    ),
    'netimps.resolve("example.com", "txt")': (
        "needs a name server; resolution is tested against the fake name server "
        "in test_dns_wire",
        None,
    ),
    'result = netimps.ping("8.8.8.8")': (
        "sends ICMP to a public host; ping is tested against the real binary on "
        "loopback in the integration smoke tests",
        'result = netimps.PingResult(True, "8.8.8.8", rtt=0.009, ttl=119)',
    ),
    'netimps.ping("8.8.8.8", method="tcp", port=53)': (
        "connects to a public host",
        None,
    ),
    'netimps.discover_mtu("8.8.8.8")': (
        "probes a public host; discover_mtu is tested on loopback",
        None,
    ),
    'netimps.discover_mtu("10.0.0.5", method="udp", port=9999)': (
        "probes a private address that is not this host's",
        None,
    ),
    'netimps.get_tcp_mss("example.com", 443)': (
        "connects to a public host",
        None,
    ),
    'netimps.scan_ports("192.168.1.1", ["ssh", "https"])': (
        "scans a private address that is not this host's; scanning is tested on "
        "loopback",
        None,
    ),
    'sock = netimps.multicast_socket("224.0.0.251", 5353)': (
        "joins a group on a fixed port that a resident mDNS responder holds on "
        "many hosts, and a group join needs a multicast route that several CI "
        "runners lack; multicast sockets are tested on free ports with that "
        "allowance in test_scan",
        "sock = None",
    ),
    'netimps.retry(lambda: netimps.tcp_check("example.com", 443), attempts=3)': (
        "retries a connection to a public host",
        None,
    ),
}

#: Statements run with a number replaced, by first line: (old, new source).
_SUBSTITUTED = {
    'server = netimps.bind("", 6767, broadcast=True)': (
        "6767",
        "0",
        "a fixed port is another process's on some hosts; port 0 reads one back",
    ),
}


def _python_statements():
    code = _blocks(_section("Quick start"), "python")[0]
    tree = ast.parse(code)
    lines = code.split("\n")
    out = []
    for node in tree.body:
        first = ast.get_source_segment(code, node).split("\n")[0].strip()
        out.append((first, "\n".join(lines[node.lineno - 1 : node.end_lineno]), node))
    return out


def test_the_quick_start_example_runs(no_such_host, allow_off_host_destination):
    """Every statement runs or is named in `_NOT_RUN`; both tables are current.

    `no_such_host` makes a name fail to resolve, so `tcp_check("example.com")`
    answers `False` without a lookup; `allow_off_host_destination` lets
    `get_source_ip("8.8.8.8")` connect a UDP socket, which sends nothing.
    """
    statements = _python_statements()
    firsts = [first for first, _source, _node in statements]
    for table in (_NOT_RUN, _SUBSTITUTED):
        stale = [key for key in table if key not in firsts]
        assert not stale, "README lines these entries name are gone: %r" % (stale,)

    namespace = {"__name__": "readme_example"}
    opened = []
    try:
        for first, source, node in statements:
            if first in _NOT_RUN:
                compile(ast.Module([node], []), "README.md", "exec")
                stand_in = _NOT_RUN[first][1]
                if stand_in:
                    exec(stand_in, namespace)
                continue
            if first in _SUBSTITUTED:
                old, new, _why = _SUBSTITUTED[first]
                assert old in source
                source = source.replace(old, new)
            exec(compile(source, "README.md", "exec"), namespace)
            for value in namespace.values():
                if isinstance(value, socket.socket) and value not in opened:
                    opened.append(value)
        assert namespace["mac"].format("-", upper=True) == "AA-BB-CC-DD-EE-FF"
        assert namespace["server"].getsockname()[1] > 0
    finally:
        for sock in opened:
            sock.close()


#: Command words whose README lines are parsed but not called, with the reason.
_COMMANDS_NOT_RUN = {
    "ping": "sends to a public host",
    "resolve": "needs a name server; resolution is tested against the fake name server",
    "mtu": "probes a public host",
    "scan": "connects to addresses that are not this host's",
}


def _command_lines():
    lines = []
    for block in _blocks(_section("Command line"), "bash"):
        for line in block.split("\n"):
            if line.startswith("netimps "):
                tokens = shlex.split(line, comments=True)
                for operator in ("&&", "||"):
                    if operator in tokens:
                        tokens = tokens[: tokens.index(operator)]
                lines.append(tokens[1:])
    return lines


def test_the_command_table_is_current():
    words = {tokens[0] for tokens in _command_lines()}
    stale = [word for word in _COMMANDS_NOT_RUN if word not in words]
    assert not stale, "README has no command line for %r" % (stale,)


@pytest.mark.parametrize("argv", _command_lines(), ids=" ".join)
def test_each_readme_command_line_parses_and_the_offline_ones_answer(
    argv, capsys, no_such_host
):
    """The line is built through the real parser. Called, it answers with a
    status of 0 (yes) or 1 (no), never 2 (an error): `check example.com` under
    `no_such_host` is a clean "no"."""
    if not _HAS_DUHO:
        pytest.skip("the cli extra is not installed")
    import duho

    from netimps.cli import Netimps

    command = duho.parse(Netimps, argv)
    if argv[0] in _COMMANDS_NOT_RUN:
        return
    status = command()
    capsys.readouterr()
    assert status in (0, 1), (argv, status)
