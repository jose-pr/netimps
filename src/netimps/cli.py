"""Command-line interface, built on the duho declarative CLI framework.

Exposes the library's diagnostic surface as subcommands, so the same answers
are available from a shell -- or to an agent -- without writing Python::

    netimps interfaces
    netimps ping 8.8.8.8 --method tcp --port 443
    netimps resolve example.com aaaa
    netimps mtu 8.8.8.8
    netimps scan 192.0.2.1 --ports common

Every command takes ``--json`` for machine-readable output, because the whole
point of a library like this is being scripted against -- so the payload is
the only thing on stdout, and every diagnostic goes to stderr.

Installed by the ``cli`` extra: ``pip install netimps[cli]``. Importing this
module does *not* require it: the console script is installed either way, and
:func:`run` is what reports the missing extra.
"""

from __future__ import annotations

import json as _json
import sys as _sys
import typing as _ty

if _ty.TYPE_CHECKING:
    from duho import AUTO, Args, Choice, Cmd, LoggingArgs
else:
    try:
        from duho import AUTO, Args, Choice, Cmd, LoggingArgs
    except ImportError:
        # `pip install netimps` installs the `netimps` console script whether
        # or not the `cli` extra was asked for, and a console script imports
        # this module before it can call anything -- so importing it must not
        # raise. The stand-ins exist only so the command classes below can
        # still be *defined*; `run()` refuses before it ever uses one.
        AUTO = Choice = None

        class _Unavailable:
            """Stand-in for a duho base when the ``cli`` extra is absent."""

        class Args(_Unavailable):
            pass

        class Cmd(_Unavailable):
            pass

        class LoggingArgs(_Unavailable):
            pass


# duho's ``Arg`` *is* ``typing.Annotated`` -- but duho binds it as a plain
# variable (``Arg = _ty.Annotated``), and a variable is not usable in type
# position, so a type checker rejects every field annotated through it. The
# annotated fields below therefore spell ``_ty.Annotated[...]`` directly:
# identical at runtime (duho reads ``__metadata__``, which is what
# ``Annotated`` produces), and it type-checks.
#
# The ``"int | None"`` return annotations below are PEP 604 written inside
# strings, which the 3.9 floor cannot evaluate -- and never has to.
# ``from __future__ import annotations`` leaves every annotation unevaluated,
# and duho's only runtime introspection is ``typing.get_type_hints(cls)`` in
# ``_introspect.get_clsargs``, which reads CLASS-level fields and never a
# method signature. Measured on 3.9.13: the whole parser tree builds and
# commands run. The class-level fields are the ones that must stay
# ``_ty.Optional[...]`` -- and they are.

from ._dns import ResolutionError
from . import (
    IPNetwork,
    MACAddress,
    discover_mtu,
    get_default_port,
    get_default_scheme,
    get_free_port,
    get_interfaces,
    get_ip,
    get_pmtu,
    get_route,
    get_source_ip,
    get_tcp_mss,
    hop_count,
    is_link_scoped,
    normalize_host,
    parse,
    ping,
    resolve,
    scan_hosts,
    scan_ports,
    tcp_check,
    try_parse,
    wait_for_port,
)

__all__ = ["run"]

#: What a user who ran the console script without the extra needs to be told.
_NEEDS_EXTRA = "netimps: the CLI needs the 'cli' extra -- pip install 'netimps[cli]'"


def _error(text: str) -> None:
    """Print a diagnostic on stderr, keeping stdout for the answer alone.

    Errors used to go to stdout, which made ``--json`` unparseable exactly
    where a script needs it most: prose landed in the pipe instead of (or
    ahead of) the payload. Anything that is not the answer belongs on stderr.
    """
    print(text, file=_sys.stderr)


def _as_int(text: str) -> "int | None":
    """``int(text)``, or ``None`` when it is not a number.

    The conversion *is* the test: ``str.isdigit()`` answers a different
    question -- it is true for ``'\N{SUPERSCRIPT TWO}'`` and other Unicode
    digits that ``int()`` then rejects, turning a mistyped port into a
    traceback instead of a usage error.
    """
    try:
        return int(text)
    except ValueError:
        return None


def _emit(payload, as_json: bool, plain=None) -> None:
    """Print ``payload`` as JSON, or ``plain`` (or the payload) as text.

    Centralised so every command honours ``--json`` identically -- the thing a
    caller scripting against this needs to be able to rely on.
    """
    if as_json:
        print(_json.dumps(payload, indent=2, default=str))
    elif plain is not None:
        print(plain)
    elif isinstance(payload, list):
        for item in payload:
            print(item)
    else:
        print(payload)


class _Base(LoggingArgs, Cmd):
    """Shared options. ``--json`` on every command, without repeating it."""

    _logger_name_ = "netimps"

    json_out: bool = False
    "Emit JSON instead of human-readable text"
    ("--json",)


class Interfaces(_Base):
    """List network interfaces with their addresses, MACs and MTU."""

    _parsername_ = "interfaces"
    _parseraliases_ = ["ifaces", "if"]

    name: _ty.Optional[str] = None
    "Only show this interface"
    ("name",)

    raw: bool = False
    "Include the platform-specific raw data (not portable)"
    ("--raw",)

    def __call__(self) -> "int | None":
        found = get_interfaces(raw=self.raw)
        if self.name:
            found = [i for i in found if i.name == self.name]
            if not found:
                _error("no interface named %r" % self.name)
                return 1

        if self.json_out:
            _emit(
                [
                    {
                        "name": i.name,
                        "index": i.index,
                        "mac": None if i.mac is None else str(i.mac),
                        "mtu": i.mtu,
                        "is_loopback": i.is_loopback,
                        "addresses": [str(a) for a in i.ips],
                        "raw": i.raw,
                    }
                    for i in found
                ],
                True,
            )
            return None

        for iface in found:
            flags = " [loopback]" if iface.is_loopback else ""
            print("%s%s" % (iface.name, flags))
            print("  index %s   mac %s   mtu %s" % (iface.index, iface.mac, iface.mtu))
            for address in iface.ips:
                print("  %s" % address)
        return None


class Ping(_Base):
    """Check whether a host answers, by ICMP, TCP or UDP."""

    _parsername_ = "ping"

    # No default: a missing host must be argparse's "required argument"
    # message, not a ping of the empty string reported as unreachable.
    dst: str
    "Host to ping"
    ("dst",)

    method: _ty.Annotated[str, Choice("icmp", "tcp", "udp")] = "icmp"
    "Probe type; tcp/udp reach hosts that drop ICMP echo"
    ("--method", "-m")

    port: _ty.Optional[int] = None
    "Port for --method tcp/udp"
    ("--port", "-p")

    count: int = 1
    "Attempts before giving up"
    ("--count", "-c")

    timeout: float = 1.0
    "Seconds to wait per attempt"
    ("--timeout", "-t")

    size: _ty.Optional[int] = None
    "ICMP payload bytes (the wire packet is larger by the headers)"
    ("--size", "-s")

    source: _ty.Optional[str] = None
    "Send from this interface, address or MAC"
    ("--source", "-S")

    def __call__(self) -> "int | None":
        result = ping(
            self.dst,
            tries=self.count,
            timeout=self.timeout,
            method=self.method,
            port=self.port,
            size=self.size,
            src=self.source,
        )
        _emit(
            {
                "ok": result.ok,
                "host": result.host,
                "rtt_ms": result.rtt_ms,
                "ttl": result.ttl,
                "attempts": result.attempts,
                "method": self.method,
            },
            self.json_out,
            plain=(
                "%s is up (%s, %.2f ms%s)"
                % (
                    self.dst,
                    self.method,
                    result.rtt_ms if result.rtt_ms is not None else float("nan"),
                    "" if result.ttl is None else ", ttl %d" % result.ttl,
                )
                if result.ok
                else "%s did not answer (%s)" % (self.dst, self.method)
            ),
        )
        # Exit status mirrors ping(8): 0 when it answered.
        return 0 if result.ok else 1


class Resolve(_Base):
    """Resolve a name via DNS."""

    _parsername_ = "resolve"
    _parseraliases_ = ["dns"]

    query: str
    "Name to look up"
    ("query",)

    rdtype: _ty.Optional[str] = None
    "Record type (a, aaaa, mx, txt, ns, ptr, ...); auto-detects ptr for an address query"
    ("rdtype",)

    nameserver: _ty.Optional[str] = None
    "Query this nameserver instead of the system resolver"
    ("--nameserver", "-n")

    timeout: float = 5.0
    "Seconds for the whole resolution, retries included"
    ("--timeout", "-t")

    tcp: bool = False
    "Query over TCP rather than UDP"
    ("--tcp",)

    def __call__(self) -> "int | None":
        try:
            records = resolve(
                self.query,
                self.rdtype,
                ns=self.nameserver,
                timeout=self.timeout,
                tcp=self.tcp,
            )
        except (ValueError, ResolutionError) as exc:
            # ValueError: caller error (bad query/rdtype). ResolutionError:
            # every applicable backend failed to even attempt the query
            # (e.g. a non-address rdtype with dnspython not installed) --
            # neither is a DNS answer, so both are reported the same way.
            _error("error: %s" % exc)
            return 2
        _emit([str(r) for r in records], self.json_out)
        # Empty is a real answer (NXDOMAIN / no records), not an error.
        return 0 if records else 1


class Check(_Base):
    """Test whether a TCP port accepts a connection."""

    _parsername_ = "check"
    _parseraliases_ = ["tcp"]

    dst: str
    "Host to connect to"
    ("dst",)

    port: str
    "Port number or scheme name (https, ssh, ...)"
    ("port",)

    timeout: float = 3.0
    "Connect timeout in seconds"
    ("--timeout", "-t")

    wait: _ty.Optional[float] = None
    "Poll until it answers, up to this many seconds"
    ("--wait", "-w")

    def __call__(self) -> "int | None":
        number = _as_int(self.port)
        port = number if number is not None else get_default_port(self.port)
        if port is None:
            # A port the command cannot derive is a caller error (exit 2), not
            # a closed port (exit 1): nothing was tested.
            _error("error: unknown port or scheme %r" % self.port)
            return 2

        if self.wait is not None:
            ok = wait_for_port(self.dst, port, timeout=self.wait)
        else:
            ok = tcp_check(self.dst, port, timeout=self.timeout)

        _emit(
            {"ok": ok, "host": self.dst, "port": port},
            self.json_out,
            plain="%s:%d is %s" % (self.dst, port, "open" if ok else "closed"),
        )
        return 0 if ok else 1


class Route(_Base):
    """Show how traffic reaches a destination."""

    _parsername_ = "route"

    dst: str = "8.8.8.8"
    "Destination to route toward"
    ("dst",)

    hops: bool = False
    "Also count the hops (slower; may need privileges)"
    ("--hops",)

    def __call__(self) -> "int | None":
        found = get_route(self.dst)
        payload: _ty.Dict[str, _ty.Any] = {
            "dst": str(found.dst),
            "src": None if found.src is None else str(found.src),
            "gateway": None if found.gateway is None else str(found.gateway),
            "interface_index": found.interface_index,
            "on_link": found.on_link,
        }
        if self.hops:
            payload["hops"] = hop_count(self.dst)

        # ``on_link`` is a tri-state: True (no router needed), False (via the
        # gateway), or None when this platform could not be asked. Rendering
        # None as "on-link" would state as fact the one thing the lookup
        # failed to establish, so the two stay distinguishable in text
        # ("unknown") exactly as they are in JSON (``null``).
        if found.gateway is not None:
            gateway_text = str(found.gateway)
        elif found.on_link:
            gateway_text = "(on-link, no router)"
        else:
            gateway_text = "(unknown)"

        lines = [
            "dst      %s" % payload["dst"],
            "src      %s" % payload["src"],
            "gateway  %s" % gateway_text,
            "on-link  %s" % ("unknown" if found.on_link is None else found.on_link),
        ]
        if self.hops:
            lines.append("hops     %s" % payload["hops"])

        _emit(
            payload,
            self.json_out,
            plain="\n".join(lines),
        )
        return None


class Mtu(_Base):
    """Measure the path MTU to a destination."""

    _parsername_ = "mtu"

    dst: str
    "Destination to measure toward"
    ("dst",)

    method: _ty.Annotated[str, Choice("icmp", "udp", "tcp")] = "icmp"
    "How to probe; tcp derives from the negotiated MSS"
    ("--method", "-m")

    port: int = 80
    "Port for --method udp/tcp"
    ("--port", "-p")

    timeout: float = 1.0
    "Seconds per probe"
    ("--timeout", "-t")

    cached: bool = False
    "Only report the kernel's cached answer; do not probe"
    ("--cached",)

    def __call__(self) -> "int | None":
        if self.cached:
            value = get_pmtu(self.dst, self.port)
        else:
            value = discover_mtu(
                self.dst,
                timeout=self.timeout,
                port=self.port,
                method=self.method,
            )
        payload = {
            "dst": self.dst,
            "mtu": value,
            "method": "cached" if self.cached else self.method,
        }
        if self.method == "tcp" and not self.cached:
            payload["mss"] = get_tcp_mss(self.dst, self.port)

        _emit(
            payload,
            self.json_out,
            plain=(
                "%s: MTU %d bytes (%s)" % (self.dst, value, payload["method"])
                if value is not None
                else "%s: no answer -- the destination may filter probes" % self.dst
            ),
        )
        return 0 if value is not None else 1


class Scan(_Base):
    """Scan a host's ports, or a network for responsive hosts."""

    _parsername_ = "scan"

    target: str
    "Host to scan, or a network in CIDR form"
    ("target",)

    ports: str = "common"
    "Ports: a range name (common/well-known/all), scheme, or comma list"
    ("--ports", "-p")

    timeout: float = 1.0
    "Per-connection timeout"
    ("--timeout", "-t")

    workers: int = 100
    "Concurrent connections"
    ("--workers", "-w")

    def __call__(self) -> "int | None":
        spec: _ty.Any = self.ports
        if "," in self.ports:
            spec = [p.strip() for p in self.ports.split(",") if p.strip()]

        network = try_parse(self.target, IPNetwork)
        # A bare address parses as a /32, which is a host scan, not a sweep.
        is_network = network is not None and "/" in self.target

        # The two branches answer different questions and so emit different
        # shapes: a list of hosts for a sweep, one host for a port scan.
        # Declared up front, because inferring the type from whichever
        # branch comes first makes the other one a type error.
        payload: _ty.Any
        plain: str

        try:
            if is_network:
                found = scan_hosts(
                    self.target,
                    ports=spec,
                    timeout=self.timeout,
                    workers=self.workers,
                )
                payload = [{"host": str(addr), "ports": ports} for addr, ports in found]
                plain = (
                    "\n".join(
                        "%-16s %s" % (h["host"], " ".join(map(str, h["ports"])))
                        for h in payload
                    )
                    or "no hosts responded"
                )
            else:
                open_ports = scan_ports(
                    self.target,
                    ports=spec,
                    timeout=self.timeout,
                    workers=self.workers,
                )
                payload = {"host": self.target, "ports": open_ports}
                plain = (
                    "\n".join(
                        "%d/tcp open  %s" % (p, get_default_scheme(p) or "")
                        for p in open_ports
                    )
                    or "no open ports found"
                )
        except ValueError as exc:
            _error("error: %s" % exc)
            return 2

        _emit(payload, self.json_out, plain=plain)
        return None


class Addr(_Base):
    """Inspect an address, a hostname or a MAC."""

    _parsername_ = "addr"
    _parseraliases_ = ["parse"]

    value: str
    "Address, hostname, network or MAC to inspect"
    ("value",)

    def __call__(self) -> "int | None":
        mac = try_parse(self.value, MACAddress)
        if mac is not None:
            _emit(
                {
                    "kind": "mac",
                    "value": str(mac),
                    "oui": mac.oui.hex(":"),
                    "is_multicast": mac.is_multicast,
                    "is_local": mac.is_local,
                },
                self.json_out,
                plain="\n".join(
                    [
                        "mac          %s" % mac,
                        "oui          %s" % mac.oui.hex(":"),
                        "multicast    %s" % mac.is_multicast,
                        "administered %s"
                        % ("locally" if mac.is_local else "universally"),
                    ]
                ),
            )
            return None

        network = try_parse(self.value, IPNetwork)
        if network is not None and "/" in self.value:
            _emit(
                {
                    "kind": "network",
                    "value": str(network),
                    "network_address": str(network.network_address),
                    "netmask": str(network.netmask),
                    "num_addresses": network.num_addresses,
                    "version": network.version,
                },
                self.json_out,
                plain="\n".join(
                    [
                        "network   %s" % network,
                        "netmask   %s" % network.netmask,
                        "addresses %d" % network.num_addresses,
                    ]
                ),
            )
            return None

        address = get_ip(self.value)
        if address is None:
            _error(
                "error: %r is not an address, network, MAC or resolvable name"
                % self.value
            )
            return 2

        _emit(
            {
                "kind": "address",
                "value": str(address),
                "version": address.version,
                "is_private": address.is_private,
                "is_global": address.is_global,
                "is_loopback": address.is_loopback,
                "is_multicast": address.is_multicast,
                "is_link_scoped": is_link_scoped(address),
                "reverse_pointer": address.reverse_pointer,
            },
            self.json_out,
            plain="\n".join(
                [
                    "address     %s (IPv%d)" % (address, address.version),
                    "private     %s" % address.is_private,
                    "global      %s" % address.is_global,
                    "loopback    %s" % address.is_loopback,
                    "multicast   %s" % address.is_multicast,
                    "link-scoped %s" % is_link_scoped(address),
                ]
            ),
        )
        return None


class Source(_Base):
    """Show which local address is used to reach a destination."""

    _parsername_ = "source"
    _parseraliases_ = ["src"]

    dst: str = "8.8.8.8"
    "Destination to route toward"
    ("dst",)

    def __call__(self) -> "int | None":
        address = get_source_ip(self.dst)
        if address is None:
            _error("no route to %s" % self.dst)
            return 1
        _emit({"dst": self.dst, "src": str(address)}, self.json_out, plain=str(address))
        return None


class Port(_Base):
    """Look up a scheme's port, a port's scheme, or a free local port."""

    _parsername_ = "port"

    value: _ty.Optional[str] = None
    "Scheme name or port number; omit to get a free local port"
    ("value",)

    def __call__(self) -> "int | None":
        if self.value is None:
            # Named apart from the lookup below: this branch answers a
            # different question and always has a port, where
            # ``get_default_port`` may have none.
            free = get_free_port()
            _emit({"free_port": free}, self.json_out, plain=str(free))
            return None

        number = _as_int(self.value)
        if number is not None:
            scheme = get_default_scheme(number)
            _emit(
                {"port": number, "scheme": scheme},
                self.json_out,
                plain=scheme or "unknown",
            )
            # No registered mapping is an answer ("none"), the way an empty
            # `resolve` is -- exit 1, not the caller error `check` reports when
            # an unknown scheme leaves it with no port to connect to.
            return 0 if scheme else 1

        port = get_default_port(self.value)
        _emit(
            {"scheme": self.value, "port": port},
            self.json_out,
            plain=str(port) if port else "unknown",
        )
        return 0 if port else 1


class Split(_Base):
    """Split a host:port string, handling IPv6 brackets correctly."""

    _parsername_ = "split"

    value: str
    "The host:port string, e.g. '[::1]:8080'"
    ("value",)

    default_port: _ty.Optional[int] = None
    "Port to assume when the string has none"
    ("--default-port", "-d")

    def __call__(self) -> "int | None":
        try:
            host, port = normalize_host(self.value, self.default_port)
        except ValueError as exc:
            _error("error: %s" % exc)
            return 2
        _emit(
            {"host": host, "port": port},
            self.json_out,
            plain="%s\t%s" % (host, "" if port is None else port),
        )
        return None


class Netimps(Args):
    """Network utilities: interfaces, reachability, routing, MTU, DNS, scanning."""

    _parsername_ = "netimps"
    _version_ = AUTO
    _distribution_ = "netimps"
    _subcommands_ = [
        Interfaces,
        Ping,
        Resolve,
        Check,
        Route,
        Mtu,
        Scan,
        Addr,
        Source,
        Port,
        Split,
    ]


def run(argv: "_ty.Sequence[str] | None" = None) -> "int | None":
    """Console-script entry point.

    ``duho`` is imported here, not at module scope, because the console script
    is installed by a plain ``pip install netimps`` while duho lives in the
    ``cli`` extra: without the extra the command must say so in one line, not
    die in an ``ImportError`` traceback from an import the user never wrote.

    A ``ValueError`` out of the library is a caller error -- a port that is not
    a port, a ``--method`` that needs an argument it was not given -- so it
    becomes a usage error on stderr with exit 2, never a traceback.
    """
    try:
        from duho import main
    except ImportError as exc:
        raise SystemExit(_NEEDS_EXTRA) from exc

    try:
        return main(Netimps, argv)
    except ValueError as exc:
        _error("error: %s" % exc)
        return 2
