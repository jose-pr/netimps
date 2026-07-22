# netimps

[![Version](https://img.shields.io/pypi/v/netimps.svg)](https://pypi.org/project/netimps/)
[![Python versions](https://img.shields.io/pypi/pyversions/netimps.svg)](https://pypi.org/project/netimps/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/netimps/test.yml)](https://github.com/jose-pr/netimps/actions/workflows/test.yml)

**The network utilities every tool ends up rewriting** — interface discovery,
"which is my IP", reachability checks, CIDR maths, host:port parsing, DNS,
ping, scanning and multicast — as one typed, flat-import library.

Built on the standard library: the only runtime dependency is `dnspython`, and
only `resolve()` uses it. Interface enumeration, routing and multicast are
`ctypes` bindings to the platform's own APIs, so there is nothing to compile
and no wheel to miss for your platform.

## Features

- **Interface discovery, no dependencies** — `get_interfaces()` gives adapter
  names, MACs, MTU and **real prefix lengths** on Linux, macOS/BSD and Windows,
  via `getifaddrs(3)` / `GetAdaptersAddresses`. No `ifaddr` required.
- **One parsing entry point** — `parse(value, type)` with non-raising
  `try_parse` and boolean `is_valid` siblings, all typed so a checker narrows
  the result.
- **`MACAddress`** — colon/hyphen/dot/bare plus `int`/`bytes`, hashable and
  ordered, with `.oui`, `.is_multicast`, `.is_local` and case-selectable
  rendering.
- **The socket helpers everyone rewrites** — `get_source_ip`, `free_port`,
  `tcp_check`, `wait_for_port`.
- **Routing and MTU** — `get_route` (first hop, unprivileged), `hop_count`
  (raw sockets *or* traceroute fallback), `discover_mtu` / `get_pmtu`, `Interface.mtu`.
- **CIDR set maths** — `collapse` and `subtract`, the latter missing from
  `ipaddress` entirely.
- **`normalize_host`** — `host:port` splitting that gets IPv6 brackets right.
- **Scanning** — concurrent `scan_ports` / `scan_hosts`.
- **Socket setup** — `bind()` with the options named, `UdpEndpoint` for UDP
  servers that need to know which interface a datagram arrived on, and
  `retry()` for the backoff loop everyone writes without jitter.
- **Multicast** — `multicast_socket` handling the join dance whose failure
  modes are otherwise silent.
- **DNS and ping** — `resolve()` returning native types; `ping()` returning
  round-trip time and TTL, not just a boolean.

## Installation

```bash
pip install netimps
```

Requires Python 3.9+.

## Quick start

```python
import netimps
from netimps import IPAddress, IPNetwork, MACAddress, parse

# Interfaces: names, MACs, MTU and real prefixes on every OS
for iface in netimps.get_interfaces():
    print(iface.name, iface.mac, iface.mtu, [str(ip) for ip in iface.ips])
    # 'Wi-Fi'  00:00:5e:00:53:01  1500  ['192.0.2.10/24', 'fe80::.../64']

# Types annotate; parse builds
def route(dst: IPAddress, via: IPNetwork) -> None: ...

parse("10.0.0.5")                        # IPv4Address('10.0.0.5')
parse("10.0.0.5/24", IPNetwork)          # IPv4Network('10.0.0.0/24')
netimps.try_parse("nope", IPAddress)     # None
netimps.is_valid("::1", IPAddress)       # True

# Which of my addresses actually reaches that host?
netimps.get_source_ip("8.8.8.8")         # IPv4Address('192.0.2.10')
netimps.get_route("8.8.8.8").gateway     # IPv4Address('192.0.2.1')

# Honest reachability, and waiting for a service
netimps.tcp_check("example.com", 443)              # True
netimps.wait_for_port("localhost", 5432, timeout=60)

# CIDR set maths
netimps.subtract(["10.0.0.0/24"], ["10.0.0.64/26"])
# [IPv4Network('10.0.0.0/26'), IPv4Network('10.0.0.128/25')]

# host:port, including the IPv6 case people get wrong
netimps.normalize_host("[::1]:8080")     # ('::1', 8080)
netimps.normalize_host("::1")            # ('::1', None)  -- not port 1

# MAC addresses
mac = MACAddress("AA-BB-CC-DD-EE-FF")
mac.as_str("-", upper=True)              # 'AA-BB-CC-DD-EE-FF'
mac.is_local, mac.oui.hex()              # (True, 'aabbcc') -- AA has the U/L bit

# DNS returns native types
netimps.resolve("example.com")[0].is_global   # an IPv4Address, not a str
netimps.resolve("example.com", "txt")         # ['v=spf1 -all']  -- unquoted

# ping carries the details
result = netimps.ping("8.8.8.8")
result.ok, result.rtt_ms, result.ttl     # (True, 9.0, 119)

# Scanning and multicast
netimps.scan_ports("192.168.1.1", ["ssh", "https"])   # [22, 443]
sock = netimps.multicast_socket("224.0.0.251", 5353)  # mDNS listener

# Server-side: bind with the options named, and know where packets came from
server = netimps.bind("", 6767, broadcast=True)
endpoint = netimps.UdpEndpoint(server)

# Retry with backoff and jitter
netimps.retry(lambda: netimps.tcp_check("example.com", 443), attempts=3)
```

## API overview

| Name | Purpose |
| --- | --- |
| `IPAddress`, `IPInterface`, `IPNetwork` | v4/v6 **union aliases** for annotations |
| `IPAddressLike`, `IPNetworkLike`, `MACLike` | accepted-input unions |
| `IPv4Address`, `IPv4Interface`, ... | stdlib concrete-type re-exports |
| `parse`, `try_parse`, `is_valid` | build a type from a value (raising / `None` / `bool`) |
| `MACAddress` | parse / classify / render MAC addresses |
| `get_interfaces`, `Interface`, `iter_addresses` | native cross-platform NIC discovery |
| `get_ip`, `is_link_scoped` | address resolution and scope classification |
| `collapse`, `subtract` | CIDR set maths |
| `normalize_host` | `host:port` splitting, IPv6-aware |
| `get_default_port`, `get_default_scheme`, `register_port` | scheme ↔ port registry |
| `resolve` | DNS lookup → native records (`[]` on failure) |
| `ping`, `PingResult` | reachability with RTT and TTL |
| `bind`, `bind_error_hint`, `interface_for` | socket creation and diagnosis |
| `get_source_ip`, `free_port`, `tcp_check`, `wait_for_port` | socket helpers |
| `UdpEndpoint`, `Datagram` | UDP receive with arrival interface (`IP_PKTINFO`) |
| `Host` | hostname-or-address value type |
| `retry`, `backoff_delays` | bounded retry with exponential backoff |
| `APIPA`, `LOOPBACK_V4`, `LOOPBACK_V6`, `LINK_LOCAL_V6` | named networks |
| `get_route`, `Route`, `hop_count` | routing and distance |
| `discover_mtu`, `get_pmtu` | path MTU: measured, or the kernel's cached guess |
| `scan_ports`, `scan_hosts`, `PORT_RANGES` | concurrent scanning |
| `multicast_socket`, `join_group`, `leave_group`, `is_multicast` | multicast |
| `HOST_DN` | `platform.node()`, captured at import time |

Full per-export reference, with contracts and gotchas, lives in
[`src/netimps/AGENTS.md`](src/netimps/AGENTS.md).

## Design notes

A few behaviours are deliberate and worth knowing:

- **`Interface.is_loopback` is computed from addresses, not names** — `lo`,
  `lo0` and `Loopback Pseudo-Interface 1` share no spelling.
- **Concrete types are strict about family.** `parse("::1", IPAddress)` works;
  `parse("::1", IPv4Address)` raises rather than quietly returning v6.
- **Networks parse non-strict by default**, so `10.0.0.5/24` normalises instead
  of raising. Pass `strict=True` for stdlib behaviour.
- **`resolve` raises on a malformed query** rather than returning `[]` — a
  typo'd record type should not look like "no such record".
- **`ping(ttl=...)` behaves the same on every OS.** Windows `ping` exits `0`
  for "TTL expired in transit", so the reply address is verified instead of
  trusting the exit code.
- **`hop_count` works unprivileged**, falling back to the system traceroute
  when a raw socket is unavailable.
- **`discover_mtu` measures; `get_pmtu` only reports what the kernel cached.**
  The latter is usually `None`, and always `None` on Windows. On one real host
  the local link was 9000 and the true path MTU 1500 — only probing found it.

## Development

```bash
python -m venv .venv/dev
.venv/dev/Scripts/pip install -e ".[dev]"   # POSIX: .venv/dev/bin/pip
.venv/dev/Scripts/pytest -q
.venv/dev/Scripts/black src/ tests/
```

Tested on Python 3.9 (the floor) and 3.14.

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pushing a tag matching `v*` triggers the release
workflow: test gate → build → publish → docs deploy.

## License

MIT — see [LICENSE](LICENSE).
