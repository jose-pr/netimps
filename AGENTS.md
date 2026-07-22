# netimps

A **small, self-contained network-utilities library** — a thin, typed layer over
the standard library's `ipaddress`, native cross-platform interface discovery,
and a handful of host helpers (DNS lookup, ping). One flat import surface, one
runtime dependency (`dnspython`, used only by `resolve`), and behaviour that
stays faithful to the stdlib.

```python
import netimps

for iface in netimps.get_interfaces():
    print(iface.name, iface.mac, [str(ip) for ip in iface.ips])

netimps.IPIface("10.0.0.5/24").network.network_address.exploded   # '10.0.0.0'
netimps.MACAddress("AA-BB-CC-DD-EE-FF").as_str("-")               # 'aa-bb-cc-dd-ee-ff'
netimps.resolve("example.com")             # ['93.184.216.34']  (or [] on failure)
netimps.ping("127.0.0.1")                  # True / False
```

- **Interface discovery, no dependencies** — `get_interfaces()` gives adapter
  names, MACs and *real* prefix lengths on Linux, macOS/BSD and Windows, via
  `ctypes` bindings to `getifaddrs(3)` / `GetAdaptersAddresses`. Results are
  normalised across platforms; the native leftovers are opt-in via `raw=True`.
- **Types vs factories** — `IPAddress`/`IPInterface`/`IPNetwork` are the v4/v6
  **union aliases** for annotations; `IPAddr()`/`IPIface()`/`IPNet()` are the
  **factories** (non-strict networks). Plus the concrete stdlib re-exports.
- **`MACAddress`** — parses colon/hyphen/dot/bare forms (and `int`/`bytes`),
  hashable and ordered, with `.packed`, `.oui`, `.is_multicast`, `.is_local`
  and `.as_str(sep, upper=)`.
- **Generic parsing** — `try_parse(value, parser)` → value or `None`;
  `is_valid(value, parser)` → bool. Both work with any factory; named
  shorthands `is_valid_ip` / `is_valid_network` / `is_valid_mac`.
- **DNS** — `resolve()` via `dnspython`: `[]` on any genuine lookup failure,
  never `None`, with a real total-resolution timeout.
- **`ping`** — cross-platform reachability with timeout, retry and family
  selection (shells out to the platform `ping` binary).

## Install

```bash
pip install netimps
```

Requires Python 3.9+. Runtime dependency: `dnspython` (used only inside
`resolve`).

## Code layout

```
src/netimps/
├── __init__.py   # the public surface: type aliases, parse/try_parse/is_valid
├── _mac.py       # private: MACAddress value type
├── _scheme.py    # private: scheme <-> port registry
├── _ifaddrs.py   # private: ctypes getifaddrs/GetAdaptersAddresses bindings
├── _sockets.py   # private: source IP, free port, tcp/wait, route, hops, MTU
├── _dns.py       # private: resolve() over dnspython
├── _ping.py      # private: ping() over the platform binary
└── py.typed      # PEP 561 marker — the package ships inline type hints
```

**The import surface is still flat** — everything is re-exported from
`netimps`, and the `_`-prefixed modules are implementation detail. Do not
import them directly from outside the package.

`__init__` imports the submodules **last**, because several of them call back
into it (`parse`, `try_parse`, `MACAddress`); those back-references are
function-local imports for the same reason. Everything importable from
`netimps` is declared in `__all__` at the top of `__init__.py`.

## Entry points

See **`src/netimps/AGENTS.md`** for the header-file-style public API (every
export with its signature, arguments, return contract, and gotchas). Quick
map:

| Name | Purpose |
| --- | --- |
| `IPAddress`, `IPInterface`, `IPNetwork` | v4/v6 **union aliases** for annotations |
| `IPAddr`, `IPIface`, `IPNet` | **factories** (non-strict networks) |
| `IPAddressLike`, `IPNetworkLike`, `MACLike` | accepted-input unions |
| `IPv4Address`, `IPv4Interface`, `IPv4Network`, `IPv6Address`, `IPv6Interface`, `IPv6Network` | stdlib concrete-type re-exports |
| `MACAddress` | parse / classify / render MAC addresses |
| `try_parse`, `is_valid` | generic non-raising parse / check |
| `is_valid_ip`, `is_valid_network`, `is_valid_mac` | named shorthands |
| `get_interfaces`, `Interface` | native cross-platform NIC discovery |
| `resolve` | DNS lookup → list of string records (`[]` on failure) |
| `ping` | reachability → `bool` |
| `get_ip`, `is_link_scoped` | address helpers |
| `get_default_port`, `get_default_scheme`, `register_port` | scheme ↔ port registry |
| `HOST_DN` | `platform.node()` of the running host, captured at import time |

## Working here

- **Don't collapse the per-platform `sockaddr` layouts** in `_ifaddrs.py`.
  macOS/BSD have a leading `sa_len` byte Linux lacks; using the Linux layout on
  BSD decodes `AF_INET` as `512` and *silently* drops every address instead of
  raising — a Linux-only CI stays green while Mac users lose data.
- **`is_loopback` is derived from addresses, never names** (`lo` / `lo0` /
  `Loopback Pseudo-Interface 1` share no spelling).
- The ctypes paths can't be asserted against fixed values, so
  `tests/test_interfaces.py` checks invariants plus the pure helpers and the
  fallback, which *are* exactly testable.
- Tests must never hit the network — `tests/test_net.py` fakes `dns.resolver`
  and `subprocess.run` throughout.

## Develop

```bash
python -m venv .venv/dev
.venv/dev/Scripts/pip install -e ".[dev]"   # POSIX: .venv/dev/bin/pip
.venv/dev/Scripts/pytest -q                 # POSIX: .venv/dev/bin/pytest -q
```

Tests live in `tests/` (`test_ip.py`, `test_mac.py`, `test_net.py`,
`test_interfaces.py`) and run via `pytest -q` from a checkout;
`pyproject.toml` puts `src/` on the path. Run against **3.9 and 3.14** — 3.9 is
the floor, so no unquoted `X | Y` unions at runtime.

Code is formatted with **black** (`target-version = py39`, configured in
`pyproject.toml`; installed by the `dev` extra):

```bash
.venv/dev/Scripts/black src/ tests/          # format
.venv/dev/Scripts/black --check src/ tests/  # verify, for CI
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pushing a tag matching `v*` triggers the
release workflow: test gate → build → publish (PyPI) → docs deploy. Package
builds locally with `hatchling`.

## License

MIT — see [LICENSE](LICENSE).
