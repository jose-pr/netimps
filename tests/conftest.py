"""Suite-wide guards.

The repo's ``AGENTS.md`` has always said "tests must never hit the network".
That was aspirational: a review on 2026-09-20 measured eleven off-host
lookups, including three for the developer's own hostname. None of them
changed an assertion *on that machine* -- but simulating a wildcard resolver
(the kind many ISP and corporate networks run, which answers every name)
turned the suite red, because several tests assert that a name does **not**
resolve.

So the invariant is enforced here rather than trusted. Any test that reaches
the resolver for a non-local name now fails loudly, at the point of the call,
naming itself -- instead of passing until it meets an unusual network.

A test that genuinely needs a resolution result fakes it, as the DNS tests
already do. A test that needs the guard lifted asks for the ``allow_resolver``
fixture, which documents itself in the test body.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import urllib.parse
import urllib.request

import pytest

from netimps import _proc

#: Directories holding a fake program from :func:`fake_program`. A fake called
#: ``nslookup`` is a local script that sends nothing, so the guard that refuses
#: a real ``nslookup`` to an off-host name must not refuse it.
_FAKE_DIRECTORIES = set()

#: Names answered from the host's own configuration rather than a name server.
_LOCAL_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "", "0.0.0.0", "::", "::1"}
)


def _is_local(host: object) -> bool:
    """True when resolving ``host`` cannot reach a name server.

    Two cases, and the second is easy to get wrong. ``localhost`` and friends
    come out of the hosts file. And an **address literal is not a lookup at
    all** -- ``getaddrinfo("1.1.1.1", ...)`` parses four numbers and returns;
    no packet leaves the machine, and no resolver has an opinion about it. A
    guard that blocks those is not enforcing "never hit the network", it is
    blocking arithmetic, and it would push tests into mocking things that were
    never remote.

    Everything else is a question for somebody else's machine.
    """
    if host is None:
        return True
    text = str(host)
    if text in _LOCAL_NAMES:
        return True
    try:
        ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    return True


def _stays_on_host(host: object) -> bool:
    """True when traffic addressed to ``host`` cannot leave this machine.

    Not the same question as :func:`_is_local`. An address literal needs no
    *lookup*, but a packet sent to ``192.0.2.53`` still goes out, so only a
    loopback or unspecified address, or a name the hosts file answers, counts.
    """
    if host is None:
        return True
    text = str(host).split("%")[0]
    if text in _LOCAL_NAMES:
        return True
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


def _local_for(function: str, host: object) -> bool:
    """Whether ``socket.<function>(host)`` can be answered without a name server.

    A reverse lookup of an address *is* a query -- the PTR record lives on
    somebody else's server -- so unlike the forward lookups it is local only
    for a loopback address.
    """
    return _stays_on_host(host) if function == "gethostbyaddr" else _is_local(host)


class ResolverEscape(AssertionError):
    """A test asked the resolver about a name it does not own.

    Raised instead of returning an answer, because a silent answer is exactly
    what makes this class of flake invisible: the test passes here and fails on
    a network whose resolver has a different opinion.
    """


#: Ports a DNS query goes to: plain DNS, and DNS over TLS.
_DNS_PORTS = frozenset({53, 853})


def _install_query_guards(monkeypatch, refuse) -> None:
    """Refuse an off-host DNS query made without the OS resolver.

    ``getaddrinfo`` and its siblings are only one road to a name server.
    ``resolve_wire`` and ``dnspython`` open their own sockets, ``resolve_doh``
    goes through ``urllib`` and ``resolve_nslookup`` runs a program, so each is
    patched where it leaves the process.

    Two rules. An off-host DNS port may not be connected or sent to at all.
    A loopback DNS port may be connected to -- a port scan of loopback does
    that and sends nothing -- but nothing may be *sent* to it:
    ``127.0.0.53:53`` is systemd-resolved's stub and ``127.0.0.1:53`` a local
    dnsmasq, and both forward a query off the host. The fake servers the DNS
    tests talk to listen on loopback at an ephemeral port, which neither rule
    touches.

    ``refuse(what)`` records the escape and raises :class:`ResolverEscape`.
    The record matters because ``resolve_dnspython`` turns any exception into a
    ``ValueError``, which a caller then reads as a bad query -- the raise alone
    would let the escape pass as an ordinary failure.
    """

    def check_destination(method, address):
        if (
            isinstance(address, tuple)
            and len(address) >= 2
            and address[1] in _DNS_PORTS
            and (method == "sendto" or not _stays_on_host(address[0]))
        ):
            refuse("socket.%s(%r)" % (method, address))

    for method in ("connect", "connect_ex", "sendto"):
        real_method = getattr(socket.socket, method)

        def wrapper(self, *args, _real=real_method, _name=method, **kwargs):
            check_destination(_name, args[-1] if args else None)
            return _real(self, *args, **kwargs)

        monkeypatch.setattr(socket.socket, method, wrapper)

    for method in ("send", "sendall"):
        real_method = getattr(socket.socket, method)

        def payload_wrapper(self, *args, _real=real_method, _name=method, **kwargs):
            try:
                peer = self.getpeername()
            except OSError:
                peer = None
            if isinstance(peer, tuple) and len(peer) >= 2 and peer[1] in _DNS_PORTS:
                refuse("socket.%s() to %r" % (_name, peer))
            return _real(self, *args, **kwargs)

        monkeypatch.setattr(socket.socket, method, payload_wrapper)

    try:
        from dns import resolver as dns_resolver
    except ImportError:  # dnspython is an optional extra
        dns_resolver = None
    if dns_resolver is not None:
        for method in ("resolve", "resolve_address"):
            real_resolve = getattr(dns_resolver.Resolver, method)

            def resolve_wrapper(self, query, *args, _real=real_resolve, **kwargs):
                servers = [
                    str(getattr(server, "address", server))
                    for server in (self.nameservers or [])
                ]
                ports = getattr(self, "nameserver_ports", None) or {}
                default_port = getattr(self, "port", 53)
                on_host = servers and all(
                    _stays_on_host(server)
                    and ports.get(server, default_port) not in _DNS_PORTS
                    for server in servers
                )
                if not on_host:
                    refuse(
                        "dns.resolver.Resolver.resolve(%r, nameservers=%r)"
                        % (query, servers)
                    )
                return _real(self, query, *args, **kwargs)

            monkeypatch.setattr(dns_resolver.Resolver, method, resolve_wrapper)

    real_urlopen = urllib.request.urlopen

    def urlopen(url, *args, **kwargs):
        target = getattr(url, "full_url", url)
        if not _stays_on_host(urllib.parse.urlsplit(target).hostname):
            refuse("urllib.request.urlopen(%r)" % (target,))
        return real_urlopen(url, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)

    real_popen_init = subprocess.Popen.__init__

    def popen_init(self, args, *rest, **kwargs):
        argv = list(args) if isinstance(args, (list, tuple)) else [args]
        program = os.path.basename(str(argv[0])).lower()
        is_fake = os.path.normcase(os.path.dirname(str(argv[0]))) in _FAKE_DIRECTORIES
        if (
            program.startswith("nslookup")
            and not is_fake
            and not all(
                _stays_on_host(arg)
                for arg in map(str, argv[1:])
                if not arg.startswith("-")
            )
        ):
            refuse("subprocess.Popen(%r)" % (argv,))
        real_popen_init(self, args, *rest, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "__init__", popen_init)


@pytest.fixture(autouse=True)
def _no_off_host_resolution(request, monkeypatch):
    """Fail any off-host name resolution for the duration of each test.

    Yields the list of escapes seen. A test that fails to stop one -- because
    the code under test swallowed the exception -- still fails at teardown.
    """
    escapes = []
    names = set(request.fixturenames)
    # Both opt-outs step aside explicitly rather than relying on which fixture
    # happens to patch last.
    if "allow_resolver" in names:
        yield escapes
        return

    test_id = request.node.nodeid

    def refuse(what):
        message = (
            "%s called %s; tests must never hit the network. Fake the lookup, "
            "or request the `allow_resolver` fixture and say in the test why "
            "the real resolver is needed." % (test_id, what)
        )
        escapes.append(message)
        raise ResolverEscape(message)

    _install_query_guards(monkeypatch, refuse)
    if "no_such_host" in names:
        # `no_such_host` replaces the three lookups with deterministic misses.
        yield escapes
        if escapes:
            pytest.fail("; ".join(escapes), pytrace=False)
        return

    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname = socket.gethostbyname
    real_gethostbyaddr = socket.gethostbyaddr

    def guard(name, real, host, *args, **kwargs):
        if not _local_for(name, host):
            refuse("socket.%s(%r)" % (name, host))
        return real(host, *args, **kwargs)

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *a, **k: guard("getaddrinfo", real_getaddrinfo, host, *a, **k),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda host, *a, **k: guard("gethostbyname", real_gethostbyname, host, *a, **k),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda host, *a, **k: guard("gethostbyaddr", real_gethostbyaddr, host, *a, **k),
    )
    yield escapes
    if escapes:
        pytest.fail("; ".join(escapes), pytrace=False)


@pytest.fixture
def resolver_escapes(_no_off_host_resolution):
    """The escapes the network guard has recorded in this test.

    For a test of the guard itself, which provokes one on purpose and must
    clear it so the teardown check does not fail the test as well.
    """
    return _no_off_host_resolution


@pytest.fixture
def allow_resolver():
    """Opt out of :func:`_no_off_host_resolution` for one test.

    Requesting it is the documentation: it marks the test as one that depends
    on the host's resolver, so the next person reading a failure knows the
    network is a suspect.
    """
    return True


@pytest.fixture
def no_such_host(monkeypatch):
    """Make every off-host name fail to resolve, deterministically.

    A surprising number of tests here mean "given a name that does not
    resolve..." and get it by picking something in ``.invalid`` and trusting
    the resolver to say NXDOMAIN. That works until it meets a resolver that
    answers everything -- the wildcard/NXDOMAIN-hijacking kind many ISP and
    corporate networks run -- and then the assertion inverts. It is not a
    hypothetical: simulating one turned ``test_addr_rejects_nonsense`` red,
    because the CLI decided a nonsense string was a hostname.

    Requesting this fixture says "the name not resolving is the precondition",
    and makes it true regardless of whose network the tests run on.
    """
    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname = socket.gethostbyname
    real_gethostbyaddr = socket.gethostbyaddr

    def fail(name, real, host, *args, **kwargs):
        if _local_for(name, host):
            return real(host, *args, **kwargs)
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *a, **k: fail("getaddrinfo", real_getaddrinfo, host, *a, **k),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda host, *a, **k: fail("gethostbyname", real_gethostbyname, host, *a, **k),
    )
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda host, *a, **k: fail("gethostbyaddr", real_gethostbyaddr, host, *a, **k),
    )
    return True


# --------------------------------------------------------------------------- #
# Fake programs                                                                #
# --------------------------------------------------------------------------- #

#: The script every fake runs. ``{config}`` is a Python literal; the call log is
#: one JSON ``[arguments, stdin length]`` per line, which is how a test reads back what the
#: library actually passed.
_FAKE_SCRIPT = """\
import json, os, subprocess, sys, time

CONFIG = {config!r}
LOG = {log!r}
HANG_PIDS = {pids!r}

try:
    with open(LOG, encoding="utf-8") as handle:
        index = sum(1 for _ in handle)
except OSError:
    index = 0
STDIN = sys.stdin.read()
with open(LOG, "a", encoding="utf-8") as handle:
    handle.write(json.dumps([sys.argv[1:], len(STDIN)]) + "\\n")


def pick(key):
    value = CONFIG[key]
    if isinstance(value, list):
        return value[min(index, len(value) - 1)]
    return value


if CONFIG["hang"]:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(600)"]
    )
    with open(HANG_PIDS, "w") as handle:
        handle.write(json.dumps([os.getpid(), child.pid]))
    time.sleep(600)

sys.stdout.buffer.write(pick("stdout"))
sys.stdout.buffer.flush()
sys.stderr.buffer.write(pick("stderr"))
sys.stderr.buffer.flush()
sys.exit(pick("returncode"))
"""


class FakeProgram:
    """A program on ``PATH`` that records its arguments and prints what it was told."""

    def __init__(self, directory, name):
        self.directory = directory
        self.name = name
        self.log = directory / (name + ".calls")
        self.pids = directory / (name + ".pids")

    @property
    def calls(self):
        """Every argument list the fake was run with, oldest first."""
        if not self.log.exists():
            return []
        lines = self.log.read_text(encoding="utf-8").splitlines()
        return [json.loads(line)[0] for line in lines]

    @property
    def stdin_lengths(self):
        """How many characters of standard input each run could read."""
        if not self.log.exists():
            return []
        lines = self.log.read_text(encoding="utf-8").splitlines()
        return [json.loads(line)[1] for line in lines]

    @property
    def argv(self):
        """The arguments of the most recent run (the program itself is not in it)."""
        calls = self.calls
        assert calls, "%s was never run" % (self.name,)
        return calls[-1]

    @property
    def hung_pids(self):
        """Process ids of a ``hang=True`` fake and of the child it started."""
        return json.loads(self.pids.read_text()) if self.pids.exists() else []


def _as_bytes(value):
    if isinstance(value, (list, tuple)):
        return [_as_bytes(item) for item in value]
    if isinstance(value, str):
        return value.encode(_proc._ENCODING)
    return value


@pytest.fixture
def fake_program(tmp_path, monkeypatch):
    """Put a fake program first on ``PATH`` and return a handle to it.

    ``fake_program("ping", stdout=..., returncode=...)`` writes an executable
    named ``ping`` that prints ``stdout`` (``str``, encoded the way the runner
    decodes, or raw ``bytes``) and ``stderr``, exits with ``returncode``, or
    with ``hang=True`` starts a child and sleeps. Each of the three may be a
    list: one entry per run, the last one repeating. The library runs the real
    spawn, decode and timeout path against it; nothing is patched.

    POSIX: a script with a ``#!`` line naming the running interpreter, mode
    0o755. Windows: a ``.exe`` launcher built by ``distlib``, because a ``.cmd``
    shim is refused by the runner and would not be what the library runs.
    """
    directory = tmp_path / "fake-bin"
    directory.mkdir()
    sources = tmp_path / "fake-src"
    sources.mkdir()
    _FAKE_DIRECTORIES.add(os.path.normcase(str(directory)))
    monkeypatch.setenv("PATH", str(directory) + os.pathsep + os.environ.get("PATH", ""))
    _proc.clear_cache()

    def make(name, stdout="", stderr="", returncode=0, hang=False):
        fake = FakeProgram(directory, name)
        # Making the same fake again starts it afresh.
        for leftover in (fake.log, fake.pids):
            if leftover.exists():
                leftover.unlink()
        script = _FAKE_SCRIPT.format(
            config={
                "stdout": _as_bytes(stdout),
                "stderr": _as_bytes(stderr),
                "returncode": returncode,
                "hang": hang,
            },
            log=str(fake.log),
            pids=str(fake.pids),
        )
        if sys.platform == "win32":
            distlib_scripts = pytest.importorskip("distlib.scripts")
            source = sources / (name + ".py")
            source.write_bytes(("#!python\n" + script).encode("utf-8"))
            maker = distlib_scripts.ScriptMaker(
                str(sources), str(directory), add_launchers=True
            )
            maker.clobber = True
            maker.make(source.name)
        else:
            target = directory / name
            target.write_bytes(("#!" + sys.executable + "\n" + script).encode("utf-8"))
            target.chmod(0o755)
        _proc.clear_cache()
        return fake

    yield make
    _FAKE_DIRECTORIES.discard(os.path.normcase(str(directory)))
    _proc.clear_cache()
