# netutils

[![Version](https://img.shields.io/pypi/v/netutils.svg)](https://pypi.org/project/netutils/)
[![Python versions](https://img.shields.io/pypi/pyversions/netutils.svg)](https://pypi.org/project/netutils/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/jose-pr/netutils/test.yml)](https://github.com/jose-pr/netutils/actions/workflows/test.yml)

A **small, self-contained network-utilities library** — a thin, typed layer over
the standard library's `ipaddress` plus a handful of host helpers (DNS lookup,
ping, local NIC discovery). One flat import surface, minimal dependencies, and
behaviour that stays faithful to the stdlib.

## Features

- **IP types** — `IPAddress`, `IPInterface`, `IPNetwork` factories over
  `ipaddress`, plus the concrete `IPv4Address`/`IPv4Interface`/... re-exports.
  `.exploded`, `.network_address`, `.netmask` and `addr in network` all work.
- **`MACAddress`** — parses colon/hyphen/dot/bare forms, normalises to
  lowercase, renders with any separator via `.as_str(sep)`, and is hashable so
  it works as a dict key.
- **Tolerant parsers** — `parse_ip` / `parse_network` coerce str/int/None,
  mapping empty input to `None`; `is_valid_ip` never raises.
- **`nslookup`** — DNS resolution with a clean list-of-strings contract.
- **`ping`** — cross-platform single-echo reachability check.
- **NIC discovery** — `active_nic_addresses()` everywhere; `get_ip_address` /
  `nic_info` on POSIX.

## Installation

```bash
pip install netutils
```

## Quick start

```python
import netutils

# IP / network types
iface = netutils.IPInterface("10.0.0.5/24")
iface.network.network_address.exploded      # '10.0.0.0'
netutils.IPAddress("10.0.0.5") in netutils.IPNetwork("10.0.0.0/24")  # True

# MAC addresses
mac = netutils.MACAddress("AA-BB-CC-DD-EE-FF")
mac.as_str("-")                             # 'aa-bb-cc-dd-ee-ff'
mac == "aabb.ccdd.eeff"                     # True

# Tolerant parsing
netutils.parse_ip("")                       # None
netutils.is_valid_ip("not-an-ip")           # False

# DNS + reachability
netutils.nslookup("example.com")            # ['93.184.216.34']  (or [] on failure)
netutils.ping("127.0.0.1")                  # True / False
```

## API overview

| Name | Purpose |
| --- | --- |
| `IPAddress`, `IPInterface`, `IPNetwork` | `ipaddress` factories (non-strict networks) |
| `IPv4Address`, `IPv4Interface`, ... | stdlib concrete-type re-exports |
| `MACAddress` | parse / normalise / render MAC addresses |
| `parse_ip`, `parse_network` | tolerant coercion (empty → `None`) |
| `is_valid_ip` | non-raising validity check |
| `nslookup` | DNS lookup → list of string records (`[]` on failure) |
| `ping` | single-echo reachability → `bool` |
| `active_nic_addresses`, `get_ip_address`, `nic_info` | local NIC discovery |

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
