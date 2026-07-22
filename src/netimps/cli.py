"""Command-line interface, built on the duho declarative CLI framework.

Exposes the library's diagnostic surface as subcommands, so the same answers
are available from a shell -- or to an agent -- without writing Python::

    netimps interfaces
    netimps ping 8.8.8.8 --method tcp --port 443
    netimps resolve example.com aaaa
    netimps mtu 8.8.8.8
    netimps scan 192.0.2.1 --ports common

Every command takes ``--json`` for machine-readable output, because the whole
point of a library like this is being scripted against.

Installed by the ``cli`` extra: ``pip install netimps[cli]``.
"""

from __future__ import annotations

import json as _json
import typing as _ty

from duho import AUTO, Arg, Args, Choice, Cmd, LoggingArgs, main

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
                print("no interface named %r" % self.name)
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

    dst: str = ""
    "Host to ping"
    ("dst",)

    method: "Arg[str, Choice('icmp', 'tcp', 'udp')]" = "icmp"
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

    query: str = ""
    "Name to look up"
    ("query",)

    rdtype: str = "a"
    "Record type (a, aaaa, mx, txt, ns, ...)"
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
        except ValueError as exc:
            print("error: %s" % exc)
            return 2
        _emit([str(r) for r in records], self.json_out)
        # Empty is a real answer (NXDOMAIN / no records), not an error.
        return 0 if records else 1


class Check(_Base):
    """Test whether a TCP port accepts a connection."""

    _parsername_ = "check"
    _parseraliases_ = ["tcp"]

    dst: str = ""
    "Host to connect to"
    ("dst",)

    port: str = ""
    "Port number or scheme name (https, ssh, ...)"
    ("port",)

    timeout: float = 3.0
    "Connect timeout in seconds"
    ("--timeout", "-t")

    wait: _ty.Optional[float] = None
    "Poll until it answers, up to this many seconds"
    ("--wait", "-w")

    def __call__(self) -> "int | None":
        port = self.port if self.port.isdigit() else get_default_port(self.port)
        if port is None:
            print("error: unknown port or scheme %r" % self.port)
            return 2
        port = int(port)

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
        payload = {
            "dst": str(found.dst),
            "src": None if found.src is None else str(found.src),
            "gateway": None if found.gateway is None else str(found.gateway),
            "interface_index": found.interface_index,
            "on_link": found.on_link,
        }
        if self.hops:
            payload["hops"] = hop_count(self.dst)

        _emit(
            payload,
            self.json_out,
            plain="\n".join(
                [
                    "dst      %s" % payload["dst"],
                    "src      %s" % payload["src"],
                    "gateway  %s" % (payload["gateway"] or "(on-link, no router)"),
                    "hops     %s" % payload["hops"] if self.hops else None,
                ][: 4 if self.hops else 3]
            ),
        )
        return None


class Mtu(_Base):
    """Measure the path MTU to a destination."""

    _parsername_ = "mtu"

    dst: str = ""
    "Destination to measure toward"
    ("dst",)

    method: "Arg[str, Choice('icmp', 'udp', 'tcp')]" = "icmp"
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

    target: str = ""
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
            print("error: %s" % exc)
            return 2

        _emit(payload, self.json_out, plain=plain)
        return None


class Addr(_Base):
    """Inspect an address, a hostname or a MAC."""

    _parsername_ = "addr"
    _parseraliases_ = ["parse"]

    value: str = ""
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
            print(
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
            print("no route to %s" % self.dst)
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
            port = get_free_port()
            _emit({"free_port": port}, self.json_out, plain=str(port))
            return None

        if self.value.isdigit():
            scheme = get_default_scheme(int(self.value))
            _emit(
                {"port": int(self.value), "scheme": scheme},
                self.json_out,
                plain=scheme or "unknown",
            )
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

    value: str = ""
    "The host:port string, e.g. '[::1]:8080'"
    ("value",)

    default_port: _ty.Optional[int] = None
    "Port to assume when the string has none"
    ("--default-port", "-d")

    def __call__(self) -> "int | None":
        try:
            host, port = normalize_host(self.value, self.default_port)
        except ValueError as exc:
            print("error: %s" % exc)
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
    """Console-script entry point."""
    return main(Netimps, argv)
