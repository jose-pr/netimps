"""Suite-wide guards.

Tests never reach the network, and this module enforces it. Any test that
reaches the resolver for a non-local name, connects or sends to an address that
is not this host, or runs a real ``nslookup`` or probe program against anything
else fails loudly, at the point of the call, naming itself. A suite that merely
trusted its tests passes until it meets an unusual network: one whose resolver
answers every name turns red wherever a test asserts that a name does *not*
resolve.

A test that needs a resolution result fakes it, as the DNS tests do. A test
that needs the guard lifted asks for ``allow_resolver``, or, for the destination
rule alone, ``allow_off_host_destination``; either documents itself in the
test's signature.
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

from fakedns import PortPairUnavailable, make_nameserver

# Private: the runner every platform binary goes through.
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


def _is_own_address(host: object) -> bool:
    """True when ``host`` is an address configured on this machine.

    Asked of the platform, not of the library: a UDP socket can be bound to an
    address only if some interface of this host holds it. Traffic to such an
    address is delivered locally, so a test that binds a listener on an
    interface address and connects to it sends nothing off the host.
    """
    text = str(host)
    try:
        address = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    probe = socket.socket(family, socket.SOCK_DGRAM)
    try:
        probe.bind((text, 0))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _destination_allowed(host: object) -> bool:
    """True when a packet or connection addressed to ``host`` stays on this host.

    A loopback or unspecified address, a name the hosts file answers, or an
    address one of this machine's own interfaces holds. Any other name would be
    resolved in C where no Python hook sees it, and any other address is
    somebody else's machine, on whatever port.
    """
    return _stays_on_host(host) or _is_own_address(host)


def _local_for(function: str, host: object, *args: object) -> bool:
    """Whether ``socket.<function>(host, ...)`` can be answered without a name server.

    A reverse lookup of an address *is* a query -- the PTR record lives on
    somebody else's server -- so unlike the forward lookups it is local only
    for a loopback address. ``getnameinfo`` asks nobody when its flags say the
    host is to stay numeric.
    """
    if function == "getnameinfo":
        flags = args[0] if args else 0
        if isinstance(flags, int) and flags & socket.NI_NUMERICHOST:
            return True
        return _stays_on_host(host)
    return _stays_on_host(host) if function == "gethostbyaddr" else _is_local(host)


#: The lookups that reach the C resolver. ``getnameinfo`` takes a socket
#: address, whose first item is the host.
_LOOKUPS = (
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
    "getnameinfo",
)


def _lookup_host(name: str, first: object) -> object:
    if name == "getnameinfo" and isinstance(first, tuple) and first:
        return first[0]
    return first


def _patch_lookups(monkeypatch, on_non_local) -> None:
    """Wrap every lookup in :data:`_LOOKUPS`; ``on_non_local(name, real, host,
    *args, **kwargs)`` answers a call whose host needs a name server."""
    for name in _LOOKUPS:
        real = getattr(socket, name)

        def wrapper(first, *args, _name=name, _real=real, **kwargs):
            host = _lookup_host(_name, first)
            if _local_for(_name, host, *args):
                return _real(first, *args, **kwargs)
            return on_non_local(_name, host)

        monkeypatch.setattr(socket, name, wrapper)


class ResolverEscape(AssertionError):
    """A test asked the resolver about a name it does not own.

    Raised instead of returning an answer, because a silent answer is exactly
    what makes this class of flake invisible: the test passes here and fails on
    a network whose resolver has a different opinion.
    """


#: Programs that resolve their destination themselves and send to it.
_PROBE_PROGRAMS = frozenset(
    {"ping", "ping6", "traceroute", "traceroute6", "tracert", "pathping"}
)

#: Ports a DNS query goes to: plain DNS, and DNS over TLS.
_DNS_PORTS = frozenset({53, 853})


def _install_query_guards(monkeypatch, refuse, off_host_destinations=False) -> None:
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

    def check_destination(sock, method, address):
        if sock.family not in (socket.AF_INET, socket.AF_INET6):
            return
        if not (isinstance(address, tuple) and len(address) >= 2):
            return
        host, port = address[0], address[1]
        if not (off_host_destinations or _destination_allowed(host)):
            refuse("socket.%s(%r)" % (method, address))
        # Connecting to a loopback DNS port sends nothing; sending to one is a
        # query that a stub listening there forwards off the host.
        if method == "sendto" and port in _DNS_PORTS:
            refuse("socket.%s(%r)" % (method, address))

    # `sendmsg` is not hooked: the library installs its own on Windows and a
    # test asserts that nothing displaces it.
    for method in ("connect", "connect_ex", "sendto"):
        real_method = getattr(socket.socket, method, None)
        if real_method is None:
            continue

        def wrapper(self, *args, _real=real_method, _name=method, **kwargs):
            check_destination(self, _name, args[-1] if args else None)
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

    real_open = urllib.request.OpenerDirector.open

    def opener_open(self, fullurl, *args, **kwargs):
        target = getattr(fullurl, "full_url", fullurl)
        if not _stays_on_host(urllib.parse.urlsplit(target).hostname):
            refuse("urllib.request.OpenerDirector.open(%r)" % (target,))
        return real_open(self, fullurl, *args, **kwargs)

    # `urlopen` and any opener built with `build_opener` both end here.
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", opener_open)

    real_popen_init = subprocess.Popen.__init__

    def popen_init(self, args, *rest, **kwargs):
        argv = list(args) if isinstance(args, (list, tuple)) else [args]
        program = os.path.basename(str(argv[0])).lower()
        if program.endswith(".exe"):
            program = program[:-4]
        is_fake = os.path.normcase(os.path.dirname(str(argv[0]))) in _FAKE_DIRECTORIES
        if not is_fake and program == "nslookup":
            # With no server argument nslookup asks the configured resolver
            # whatever it was asked about, and a loopback server on the DNS
            # port may be a forwarder. Only a server that stays on this host
            # and a `-port=` outside the DNS ports is a query that stays here.
            operands = [a for a in map(str, argv[1:]) if not a.startswith("-")]
            ports = [a[6:] for a in map(str, argv[1:]) if a.startswith("-port=")]
            server = operands[1] if len(operands) > 1 else None
            if not (
                server is not None
                and _stays_on_host(server)
                and ports
                and ports[-1].isdigit()
                and int(ports[-1]) not in _DNS_PORTS
            ):
                refuse("subprocess.Popen(%r)" % (argv,))
        elif not is_fake and program in _PROBE_PROGRAMS:
            # They resolve a name themselves, in C, and the destination is
            # the last argument on every grammar the library emits.
            if len(argv) < 2 or not _destination_allowed(argv[-1]):
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

    off_host_destinations = "allow_off_host_destination" in names

    def refuse(what):
        message = (
            "%s called %s; tests must never hit the network. Fake the lookup, "
            "or request the `allow_resolver` fixture and say in the test why "
            "the real resolver is needed." % (test_id, what)
        )
        escapes.append(message)
        raise ResolverEscape(message)

    _install_query_guards(monkeypatch, refuse, off_host_destinations)
    if "no_such_host" in names:
        # `no_such_host` replaces the lookups with deterministic misses.
        yield escapes
        if escapes:
            pytest.fail("; ".join(escapes), pytrace=False)
        return

    _patch_lookups(
        monkeypatch, lambda name, host: refuse("socket.%s(%r)" % (name, host))
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
def allow_off_host_destination():
    """Let one test address a destination that is not this host.

    For a test whose subject needs one: a UDP ``connect`` to a public address
    to learn the route (sends nothing), a multicast group the test has joined,
    the limited broadcast. Requesting it is the documentation, and the test says
    in its docstring why. It lifts the destination rule only: lookups, DNS
    ports and programs stay guarded.
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

    def fail(name, host):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    _patch_lookups(monkeypatch, fail)
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


# --------------------------------------------------------------------------- #
# A fake nameserver                                                            #
# --------------------------------------------------------------------------- #


@pytest.fixture()
def server():
    try:
        fake = make_nameserver()
    except PortPairUnavailable as exc:  # pragma: no cover - a host with no free pair
        pytest.skip(str(exc))
    yield fake
    fake.close()
