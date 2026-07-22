# netimps

A **small, self-contained network-utilities library** — a thin, typed layer over
the standard library's `ipaddress`, native cross-platform interface discovery,
and a handful of host helpers (DNS lookup, ping). One flat import surface, one
runtime dependency (`dnspython`, used only by `resolve`), and behaviour that
stays faithful to the stdlib.

```python
import netimps
from netimps import IPNetwork, MACAddress, parse

for iface in netimps.get_interfaces():
    print(iface.name, iface.mac, iface.mtu, [str(ip) for ip in iface.ips])

parse("10.0.0.5/24", IPNetwork)            # IPv4Network('10.0.0.0/24')
netimps.get_source_ip("8.8.8.8")           # the address that actually reaches it
netimps.tcp_check("example.com", 443)      # True
netimps.resolve("example.com")             # [IPv4Address(...)]  ([] on failure)
netimps.ping("8.8.8.8").rtt_ms             # 9.0
```

- **Interface discovery, no dependencies** — `get_interfaces()` gives adapter
  names, MACs, MTU and *real* prefix lengths on Linux, macOS/BSD and Windows,
  via `ctypes` bindings to `getifaddrs(3)` / `GetAdaptersAddresses`. Results are
  normalised across platforms; native leftovers are opt-in via `raw=True`.
- **One parsing entry point** — `parse(value, type)`, plus non-raising
  `try_parse` and boolean `is_valid`. `IPAddress`/`IPInterface`/`IPNetwork` are
  the v4/v6 unions you annotate with *and* the types you parse into.
- **`MACAddress`** — colon/hyphen/dot/bare plus `int`/`bytes`, hashable and
  ordered, with `.packed`, `.oui`, `.is_multicast`, `.is_local`,
  `.as_str(sep, upper=)` and `is_valid`/`try_parse` classmethods.
- **Socket helpers** — `get_source_ip`, `free_port`, `tcp_check`,
  `wait_for_port`: the four every network tool rewrites.
- **Routing and MTU** — `get_route` (first hop, unprivileged), `hop_count`
  (raw sockets or traceroute fallback), `discover_mtu` / `get_pmtu`, `Interface.mtu`.
- **CIDR maths and host parsing** — `collapse`, `subtract` (absent from
  `ipaddress`), and `normalize_host` with correct IPv6 bracket handling.
- **Scanning** — concurrent `scan_ports` / `scan_hosts`, ports addressable by
  scheme name.
- **Multicast** — `multicast_socket`, `join_group`, `leave_group`, wrapping the
  setup whose failure modes are silent.
- **DNS and ping** — `resolve()` returning native types; `ping()` returning a
  `PingResult` with RTT and TTL that stays truthy.

## Install

```bash
pip install netimps
```

Requires Python 3.9+. Runtime dependency: `dnspython` (used only inside
`resolve`).

> **This file is development documentation** — layout, testing, CI, release.
> It is deliberately **not shipped** in the wheel. The library-usage reference
> is `src/netimps/AGENTS.md`, which *is* shipped and must stay self-contained
> (no repo-relative links, since an installed consumer has no repo).

## Code layout

```
src/netimps/
├── __init__.py   # the public surface: generic parse/try_parse/is_valid
├── _ip.py        # private: IP type aliases, builder tables, IP helpers
├── _mac.py       # private: MACAddress value type
├── _scheme.py    # private: scheme <-> port registry
├── _scan.py      # private: concurrent port/host scanning
├── _multicast.py # private: group membership and socket setup
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
| `IPAddressLike`, `IPNetworkLike`, `MACLike` | accepted-input unions |
| `IPv4Address`, `IPv4Interface`, `IPv4Network`, `IPv6Address`, `IPv6Interface`, `IPv6Network` | stdlib concrete-type re-exports |
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
  and `subprocess.run` throughout. `test_scan.py` and `test_sockets.py` use
  loopback only.
- **`_ip` is imported *before* the definitions** in `__init__`, unlike the other
  submodules which are imported last. `parse()` uses `IPAddress` as a default
  argument, and defaults evaluate at definition time.
- **Windows `ping` exits 0 for "TTL expired in transit."** Anything inferring
  success from the exit code alone is wrong; match the reply address instead,
  never the localised prose.
- **Check for silent platform gaps before adding a socket option.** `IP_MTU`,
  `IP_MTU_DISCOVER`, `IP_DONTFRAG` and `SO_REUSEPORT` do not exist on Windows;
  binding a multicast socket to the group address fails there too.
- **Windows exposes no cached path MTU.** Already investigated, so do not
  re-derive it: `MIB_IPFORWARDROW.dwForwardMtu` reads 0 (unsupported), and
  `MIB_IPFORWARD_ROW2` has no MTU field. `Interface.mtu` is the link MTU;
  `discover_mtu` probing is the only way to get a path MTU there.
- **`GetBestRoute`, not `GetIpForwardTable`.** It asks Windows which route it
  would pick, so the kernel does longest-prefix matching. The POSIX side has no
  equivalent and must parse `/proc/net/route` by hand — which is where the
  loopback bug came from, since that file omits loopback entirely.
- Run `black src/ tests/` before committing; CI uses `--check`.

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
