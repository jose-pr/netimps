# netimps

A **small, self-contained network-utilities library** — a thin, typed layer over
the standard library's `ipaddress` plus a handful of host helpers (DNS lookup,
ping, local NIC discovery). One flat import surface, minimal dependencies, and
behaviour that stays faithful to the stdlib.

```python
import netimps

iface = netimps.IPInterface("10.0.0.5/24")
iface.network.network_address.exploded      # '10.0.0.0'

mac = netimps.MACAddress("AA-BB-CC-DD-EE-FF")
mac.as_str("-")                             # 'aa-bb-cc-dd-ee-ff'

netimps.nslookup("example.com")            # ['93.184.216.34']  (or [] on failure)
netimps.ping("127.0.0.1")                  # True / False
```

- **IP types** — `IPAddress`, `IPInterface`, `IPNetwork` factories over
  `ipaddress` (non-strict networks), plus the concrete `IPv4Address`/
  `IPv4Interface`/`IPv4Network`/`IPv6...` stdlib re-exports so callers can
  annotate with them directly.
- **`MACAddress`** — parses colon/hyphen/dot/bare textual forms (and `int`/
  `bytes`), normalises to lowercase, renders with any separator via
  `.as_str(sep)`, and is hashable (usable as a dict key or set member).
- **Tolerant parsers** — `parse_ip` / `parse_network` coerce `str`/`int`/`None`,
  mapping `None`/empty string to `None` instead of raising; `is_valid_ip`
  never raises.
- **`nslookup`** — DNS resolution (via `dnspython`) with a clean
  list-of-strings contract: `[]` on any failure, never `None`.
- **`ping`** — cross-platform single-echo reachability check (shells out to
  the platform `ping` binary).
- **NIC discovery** — `active_nic_addresses()` works everywhere;
  `get_ip_address` / `nic_info` are POSIX-only (`fcntl`-based).

## Install

```bash
pip install netimps
```

Requires Python 3.9+. Runtime dependency: `dnspython` (used only inside
`nslookup`).

## Code layout

```
src/netimps/
├── __init__.py   # the entire public API (see src/netimps/AGENTS.md for the header)
└── py.typed      # PEP 561 marker — the package ships inline type hints
```

The library is intentionally a single flat module — no subpackages, no
plugin system. Everything importable from `netimps` is declared in
`__all__` at the top of `__init__.py`.

## Entry points

See **`src/netimps/AGENTS.md`** for the header-file-style public API (every
export with its signature, arguments, return contract, and gotchas). Quick
map:

| Name | Purpose |
| --- | --- |
| `IPAddress`, `IPInterface`, `IPNetwork` | `ipaddress` factories (non-strict networks) |
| `IPv4Address`, `IPv4Interface`, `IPv4Network`, `IPv6Address`, `IPv6Interface`, `IPv6Network` | stdlib concrete-type re-exports |
| `MACAddress` | parse / normalise / render MAC addresses |
| `parse_ip`, `parse_network` | tolerant coercion (empty → `None`) |
| `is_valid_ip` | non-raising validity check |
| `nslookup` | DNS lookup → list of string records (`[]` on failure) |
| `ping` | single-echo reachability → `bool` |
| `active_nic_addresses`, `get_ip_address`, `nic_info` | local NIC discovery |
| `HOST_DN` | `platform.node()` of the running host, captured at import time |

## Develop

```bash
python -m venv .venv/dev
.venv/dev/Scripts/pip install -e ".[dev]"   # POSIX: .venv/dev/bin/pip
.venv/dev/Scripts/pytest -q                 # POSIX: .venv/dev/bin/pytest -q
```

Tests live in `tests/` (`test_ip.py`, `test_mac.py`, `test_net.py`) and run
via `pytest -q` from a checkout; `pyproject.toml` puts `src/` on the path.

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pushing a tag matching `v*` triggers the
release workflow: test gate → build → publish (PyPI) → docs deploy. Package
builds locally with `hatchling`.

## License

MIT — see [LICENSE](LICENSE).
