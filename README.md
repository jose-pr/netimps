# netimps

[![Version](https://img.shields.io/pypi/v/netimps.svg)](https://pypi.org/project/netimps/)
[![Python versions](https://img.shields.io/pypi/pyversions/netimps.svg)](https://pypi.org/project/netimps/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/netimps/test.yml)](https://github.com/jose-pr/netimps/actions/workflows/test.yml)

A **small, self-contained network-utilities library** — a thin, typed layer over
the standard library's `ipaddress` plus a handful of host helpers (DNS lookup,
ping, interface discovery). One flat import surface, and the only runtime
dependency is `dnspython`, used solely by `resolve`.

## Features

- **Interface discovery with no dependencies** — `get_interfaces()` returns
  adapter names, MACs and **real prefix lengths** on Linux, macOS/BSD and
  Windows, via `ctypes` bindings to `getifaddrs(3)` and
  `GetAdaptersAddresses`. No `ifaddr` required.
- **Types *and* factories** — `IPAddress`/`IPInterface`/`IPNetwork` are the
  v4/v6 unions you annotate with; `IPAddr()`/`IPIface()`/`IPNet()` are the
  factories that build values.
- **`MACAddress`** — parses colon/hyphen/dot/bare forms plus `int`/`bytes`,
  hashable and ordered, with `.oui`, `.is_multicast`, `.is_local` and
  case-selectable rendering.
- **Generic parsing** — `try_parse(value, parser)` returns the value or `None`;
  `is_valid(value, parser)` returns a bool. Both work with any factory.
- **DNS** — `resolve()` with a clean list-of-strings contract, a real
  timeout, and no swallowing of caller errors.
- **`ping`** — cross-platform reachability with timeout and family selection.

## Installation

```bash
pip install netimps
```

## Quick start

```python
import netimps

# Interfaces: names, MACs and real prefixes on every OS
for iface in netimps.get_interfaces():
    print(iface.name, iface.mac, [str(ip) for ip in iface.ips])
    # 'Wi-Fi'  00:00:5e:00:53:01  ['fe80::cc6a:7d4f:5095:72bf/64', '192.0.2.10/24']

# Types annotate; factories build
def route(dst: netimps.IPAddress, via: netimps.IPNetwork) -> None: ...

iface = netimps.IPIface("10.0.0.5/24")
iface.network.network_address.exploded              # '10.0.0.0'
netimps.IPAddr("10.0.0.5") in netimps.IPNet("10.0.0.0/24")   # True

# MAC addresses
mac = netimps.MACAddress("AA-BB-CC-DD-EE-FF")
mac.as_str("-")                             # 'aa-bb-cc-dd-ee-ff'
mac.as_str("-", upper=True)                 # 'AA-BB-CC-DD-EE-FF'
mac.is_universal, mac.oui.hex()             # (True, 'aabbcc')

# Parsing without exceptions
netimps.try_parse("not-an-ip", netimps.IPAddr)   # None
netimps.is_valid("10.0.0.5", netimps.IPAddr)     # True

# DNS + reachability
netimps.resolve("example.com", "aaaa")      # ['2606:2800::1']  (or [] on failure)
netimps.ping("127.0.0.1", timeout=2.0)      # True / False
```

## API overview

| Name | Purpose |
| --- | --- |
| `IPAddress`, `IPInterface`, `IPNetwork` | v4/v6 **union aliases** for annotations |
| `IPAddr`, `IPIface`, `IPNet` | **factories** (non-strict networks) |
| `IPAddressLike`, `IPNetworkLike`, `MACLike` | accepted-input unions |
| `IPv4Address`, `IPv4Interface`, ... | stdlib concrete-type re-exports |
| `MACAddress` | parse / classify / render MAC addresses |
| `try_parse`, `is_valid` | generic non-raising parse / check |
| `is_valid_ip`, `is_valid_network`, `is_valid_mac` | named shorthands |
| `get_interfaces`, `Interface` | native cross-platform NIC discovery |
| `resolve` | DNS lookup → list of string records (`[]` on failure) |
| `ping` | reachability → `bool` |
| `get_ip`, `is_link_scoped` | address helpers |
| `get_default_port`, `port_scheme`, `register_port` | scheme ↔ port registry |

Full per-export reference, with contracts and gotchas, lives in
[`src/netimps/AGENTS.md`](src/netimps/AGENTS.md).

## Development

```bash
python -m venv .venv/dev
.venv/dev/Scripts/pip install -e ".[dev]"   # POSIX: .venv/dev/bin/pip
.venv/dev/Scripts/pytest -q
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pushing a tag matching `v*` triggers the release
workflow: test gate → build → publish → docs deploy.

## License

MIT — see [LICENSE](LICENSE).
