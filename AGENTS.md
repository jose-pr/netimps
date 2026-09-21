# netimps

A **small, self-contained network-utilities library** — a thin, typed layer over
the standard library's `ipaddress`, native cross-platform interface discovery,
and a handful of host helpers (DNS lookup, ping). One flat import surface, no
hard runtime dependencies (`resolve()` chains `dnspython`/OS-resolver/
`nslookup` backends, using whichever is available -- `dnspython` is optional,
via the `dns` extra), and behaviour that stays faithful to the stdlib.

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
- **Socket helpers** — `get_source_ip`, `get_free_port`, `tcp_check`,
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
pip install netimps          # no hard dependencies
pip install netimps[dns]     # plus dnspython, for resolve()'s fullest backend
```

Requires Python 3.9+. No hard runtime dependencies.

> **This file is development documentation** — layout, testing, CI, release.
> It is deliberately **not shipped** in the wheel. The library-usage reference
> is `src/netimps/AGENTS.md`, which *is* shipped and must stay self-contained
> (no repo-relative links, since an installed consumer has no repo).

## Code layout

```
src/netimps/
├── __init__.py    # the public surface: generic parse/try_parse/is_valid
├── _ip.py         # private: IP type aliases, builder tables, IP helpers
├── _mac.py        # private: MACAddress value type
├── _scheme.py     # private: scheme <-> port registry, shared port coercion
├── cli.py         # public: duho-backed CLI (needs the `cli` extra)
├── __main__.py    # `python -m netimps`
├── _scan.py       # private: concurrent port/host scanning
├── _multicast.py  # private: group membership and socket setup
├── _ifaddrs.py    # private: ctypes getifaddrs/GetAdaptersAddresses bindings
├── _sockets.py    # private: source IP, free port, tcp/wait, route, hops, MTU
├── _dns.py        # private: resolve() chaining dnspython/system/nslookup backends
├── _ping.py       # private: ping() over the platform binary
├── _retry.py      # private: bounded retry with exponential backoff
├── _udp.py        # private: UDP receive with arrival interface (pktinfo)
├── _iface_spec.py # private: shared InterfaceSpec coercion (MAC/name/Interface -> address)
└── py.typed       # PEP 561 marker — the package ships inline type hints
```

Beside the package: `tests/` (see **Develop**), `docs/` + `mkdocs.yml` for the
published site, `benchmarks/` (run on demand, never in CI) and `examples/`
(two runnable scripts; local and read-only).

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
| `IPAddressLike`, `IPInterfaceLike`, `IPNetworkLike`, `MACLike` | accepted-input unions |
| `AddressLike` | accepted-input union for a single destination (hostname, address, or interface object) |
| `IPv4Address`, `IPv4Interface`, `IPv4Network`, `IPv6Address`, `IPv6Interface`, `IPv6Network` | stdlib concrete-type re-exports |
| `parse`, `try_parse`, `is_valid` | build a type from a value (raising / `None` / `bool`) |
| `MACAddress` | parse / classify / render MAC addresses |
| `get_interfaces`, `Interface`, `iter_addresses` | native cross-platform NIC discovery |
| `get_ip`, `is_link_scoped` | address resolution and scope classification |
| `collapse`, `subtract` | CIDR set maths |
| `normalize_host` | `host:port` splitting, IPv6-aware |
| `get_default_port`, `get_default_scheme`, `register_port` | scheme ↔ port registry |
| `resolve`, `resolve_dnspython`, `resolve_system`, `resolve_nslookup` | DNS lookup → native records; `resolve` chains the three backends, each independently callable, and returns `[]` only when every applicable backend answered empty |
| `ResolutionError` | raised by the three resolvers when a backend could not even ask (missing binary, unreachable server, deadline) — as opposed to an empty answer |
| `ping`, `PingResult` | reachability with RTT and TTL |
| `bind`, `bind_error_hint`, `interface_for`, `interfaces_for`, `is_local_address` | socket creation and local membership |
| `get_source_ip`, `get_free_port`, `tcp_check`, `wait_for_port` | socket helpers |
| `UdpEndpoint`, `Datagram` | UDP receive with arrival interface (`IP_PKTINFO` / `IPV6_RECVPKTINFO`, per family) |
| `Host` | hostname-or-address value type |
| `retry`, `backoff_delays` | bounded retry with exponential backoff |
| `APIPA`, `LOOPBACK_V4`, `LOOPBACK_V6`, `LINK_LOCAL_V6` | named networks |
| `get_route`, `Route`, `hop_count` | routing and distance |
| `discover_mtu`, `get_pmtu`, `get_tcp_mss` | path MTU by ICMP/UDP/TCP, the kernel's cached guess, or the negotiated MSS |
| `scan_ports`, `scan_hosts`, `PORT_RANGES` | concurrent scanning |
| `multicast_socket`, `join_group`, `leave_group`, `is_multicast` | multicast |
| `HOST_DN` | `platform.node()` of the running host, captured at import time |

## Working here

- **A green suite proves nothing about this package's platform behaviour.**
  Nearly every test that touches `ping`, `traceroute` or `nslookup` fakes
  `subprocess.run` and then asserts the argv the library *builds* — which can
  never catch a flag the platform does not have. That is not hypothetical: CI
  happily confirmed that `ping(ipv6=True)` puts `-6` in the argv for months
  while macOS `ping` answered `invalid option -- 6` and exited 64.
  `tests/test_platform_smoke.py` is the one file that runs the real binaries,
  loopback only, and **nothing in it may be mocked**. A claim about another
  platform needs a measurement on that platform (a `ci-*` tag runs the matrix),
  not a passing test here.
- **Don't collapse the per-platform `sockaddr` layouts** in `_ifaddrs.py`.
  macOS/BSD have a leading `sa_len` byte Linux lacks; using the Linux layout on
  BSD decodes `AF_INET` as `512` and *silently* drops every address instead of
  raising — a Linux-only CI stays green while Mac users lose data.
- **`is_loopback` comes from the interface *flags*, never the name**, with the
  address heuristic only as a fallback when the OS reported no flag.
  `IFF_LOOPBACK` (POSIX) and `IfType == IF_TYPE_SOFTWARE_LOOPBACK` (Windows)
  were already being read into `raw`. Names (`lo` / `lo0` / `Loopback
  Pseudo-Interface 1`) share no spelling, and addresses are not authoritative
  either: WSL2 binds a routable `10.255.255.254/32` to `lo`, so the address
  heuristic found **no** loopback interface at all there — and two tests
  silently took a skip branch marked `# pragma: no cover`.
- **`_ping._PLATFORM` is a three-way split** — `windows` / `linux` / `bsd` —
  not `os.name == "nt"`. Of the six flags the module emits, *five* mean
  something different or nothing at all on BSD: `-W` is milliseconds rather
  than seconds, `-t` is an overall deadline rather than the TTL (`-m` is the
  TTL there, while Linux's `-m` is a firewall mark), `-I` is multicast-only and
  is rejected for a unicast destination (`-S` is the source flag), and
  `-4`/`-6` do not exist at all — IPv6 is a separate **`ping6`** binary with
  its own grammar again (`-h` for the hop limit, no `-W`). Anything that is
  neither Windows nor Linux is treated as BSD deliberately: a flag we fail to
  emit is a missing feature, a flag that means something else is a wrong
  answer.
- **BSD `ping` does have a DF flag: `-D`.** A long-standing comment here said
  it did not, which is why `discover_mtu(method="icmp")` was reported as
  unfixable there. `ping6` is the one combination with no verified flag, so
  `dont_fragment=True` is rejected for it rather than silently sent without DF.
- The ctypes paths can't be asserted against fixed values, so
  `tests/test_interfaces.py` checks invariants plus the pure helpers and the
  fallback, which *are* exactly testable.
- **`duho` is a CLI-only dependency.** `cli.py` and `__main__.py` may import it;
  nothing else may, and `cli.py` imports it inside `run()` so that a
  no-extra install gets a message rather than an `ImportError` traceback.
  `tests/test_cli.py` skips itself when the extra is absent, and asserts the
  library still imports with duho blocked.
- **Tests must never hit the network, and `tests/conftest.py` now enforces
  it** rather than trusting it. An autouse fixture fails any off-host name
  resolution at the point of the call, naming the test; eleven such lookups
  existed when it was added, and simulating a wildcard resolver (the kind many
  ISP and corporate networks run) turned the suite red, because several tests
  assert that a name does *not* resolve. Two escape hatches, both
  self-documenting:
  - `no_such_host` — makes every off-host name fail deterministically. Use it
    whenever the precondition is "given a name that does not resolve"; picking
    something in `.invalid` and trusting the resolver is the flake itself.
  - `allow_resolver` — lifts the guard for one test, marking it as one whose
    failures may be the network's fault.

  The guard deliberately **allows address literals**:
  `getaddrinfo("1.1.1.1", ...)` parses four numbers and returns, no packet
  leaves the machine, and blocking it would push tests into mocking things that
  were never remote. `test_net.py` fakes `dns.resolver` and `subprocess.run`
  throughout; `test_scan.py`, `test_sockets.py`, `test_centralized.py` and
  `test_platform_smoke.py` use loopback only.
- **`_ip` is imported *before* the definitions** in `__init__`, unlike the other
  submodules which are imported last. `parse()` uses `IPAddress` as a default
  argument, and defaults evaluate at definition time.
- **Windows `ping` exits 0 for "TTL expired in transit."** Anything inferring
  success from the exit code alone is wrong; match the reply address instead,
  never the localised prose. Windows `ping -?` also exits 0, which is how
  `ping("-?")` used to come back truthy for a host that was never contacted.
- **Check for silent platform gaps before adding a socket option — and check
  *every* platform, not just Windows.** Measured on Windows and Linux (3.9
  through 3.14): `IP_MTU`, `IP_MTU_DISCOVER` and `IP_DONTFRAG` are exported by
  CPython on **neither**, so a `getattr(socket, "IP_MTU", None)` guard disables
  the code everywhere — which is exactly what silently killed `get_pmtu` for
  the life of the project. `SO_REUSEPORT`, `IPV6_PATHMTU`, `IPV6_RECVPATHMTU`
  and `IPV6_RECVPKTINFO` are missing on Windows but present on Linux; Windows
  has `IPV6_DONTFRAG` (14) and no `IP_DONTFRAGMENT`. Binding a multicast socket
  to the group address fails there too. Where the constant is documented and
  stable, use the literal and let `OSError` from the `set`/`getsockopt` be the
  "unsupported" signal.
- **IPv6 multicast names an adapter by *index*, IPv4 by *address*.** They are
  not two spellings of one thing: feeding an address to the v6 side does not
  raise, it lands as index `0`, which is "kernel's choice". Use
  `_iface_spec.interface_index()` for anything v6, `interface_address()` for
  v4. Both honour a `%zone` suffix.
- **POSIX delivers asynchronous ICMP errors only to *connected* UDP sockets.**
  An unconnected probe never sees a port-unreachable and just times out, while
  Windows reports it either way — so the unconnected version tests green here
  and under-reports on Linux CI. Also note `_discover_mtu_udp` is still
  unconnected by design; it treats such errors as failure anyway.
- **`ThreadPoolExecutor.__exit__` calls `shutdown(wait=True)`,** and its atexit
  hook joins worker threads too. It is therefore the wrong tool for bounding a
  blocking call: a daemon `threading.Thread` joined through a queue is what
  `_dns._bounded_lookup` uses, and why. Every blocking resolver call goes
  through it — the `ptr` branch called `gethostbyaddr` directly and was
  measured at 4.6s against a 0.1s deadline.
- **Match a ping reply by address token, and remember hostnames are plural.**
  `gethostbyname` is IPv4-only — use `getaddrinfo` with an explicit family, or
  `ipv6=` silently does nothing. The reply needle also has to tolerate BSD's
  punctuation: `ping6` prints `16 bytes from ::1, icmp_seq=0 hlim=64` — comma,
  and `hlim` rather than `ttl`.
- **Windows exposes no cached path MTU.** Already investigated, so do not
  re-derive it: `MIB_IPFORWARDROW.dwForwardMtu` reads 0 (unsupported), and
  `MIB_IPFORWARD_ROW2` has no MTU field. `Interface.mtu` is the link MTU;
  `discover_mtu` probing is the only way to get a path MTU there. Linux *does*
  answer — `get_pmtu` reads the `IP_MTU` literal for v4 and `IPV6_PATHMTU` for
  v6, the latter returning an `ip6_mtuinfo` struct rather than a bare int.
- **`GetBestRoute2`, not `GetIpForwardTable`.** It asks Windows which route it
  would pick, so the kernel does longest-prefix matching, and unlike
  `GetBestRoute` it serves both families. The POSIX side has no equivalent and
  parses `/proc/net/route` and `/proc/net/ipv6_route` by hand — which is where
  the loopback bug came from, since the v4 file omits loopback entirely, and
  where the v6 parser has to honour `RTF_UP`/`RTF_REJECT`, since WSL2 carries a
  `::/0` reject route on `lo` that would otherwise make every global IPv6
  address "on-link via loopback". BSD has neither file and shells out to
  `route -n get`.
- **`tests/typing/api.py` is checked with a *consumer's* mypy config**,
  `tests/typing/consumer.ini`, not the package's own — for two reasons, and
  the second one bites.
  1. The package sets `enable_incomplete_feature = ["TypeForm"]` so mypy will
     type-check `__init__.py`'s own overload definitions. Nobody downstream
     sets it, so checking `api.py` with it on is not the check that matters.
  2. It keeps the two `lint`-job invocations on different option sets, which
     is what stops the first from poisoning the second through `.mypy_cache`.
     Measured here with mypy 1.20.2: from a cold cache, `mypy
     tests/typing/api.py` alone is **clean**, but `mypy src/netimps` followed
     by `mypy tests/typing/api.py` under the *same* config reports **25**
     `call-overload` errors. `TypeForm[_T]` serialises into the cache as plain
     `type[_T]`, so the second run reads a degraded `netimps` and loses every
     union-alias overload. `--no-incremental` restores it.

  So: do not collapse the two invocations onto one config without passing
  `--no-incremental`, and do not read a `call-overload` error in `api.py` as a
  contract regression before re-running it from a cold cache.
- **Type-check for every platform, not just yours.** `mypy` checks every
  per-platform branch whatever host it runs on, but resolves names against the
  platform it *thinks* it is targeting — so `ctypes.WinDLL`,
  `socket.SIO_RCVALL` and `socket.ioctl` type fine on Windows and fail on the
  Linux runner. Run `mypy --platform linux`, `--platform darwin` and
  `--platform win32`; CI runs all three. A clean local run on one platform
  proved nothing and let five `attr-defined` errors reach CI.
- **Constants differ between the BSDs, not just between BSD and Linux.**
  `IP_DONTFRAG` is 67 on FreeBSD and **28 on Darwin**; one number for "BSD"
  made `_set_dont_fragment` fail silently on macOS, which for a DF option means
  the MTU search loses its whole point. `IPV6_DONTFRAG` (62) they do agree on.
- Run `black src/ tests/` before committing. CI's `lint` job runs
  `black --check src/ tests/`, `mypy src/netimps`, and the consumer-config
  check above; all three must pass.

## Develop

```bash
python -m venv .venv/dev
.venv/dev/Scripts/pip install -e ".[dev]"   # POSIX: .venv/dev/bin/pip
.venv/dev/Scripts/pytest -q                 # POSIX: .venv/dev/bin/pytest -q
```

Tests live in `tests/` and run via `pytest -q` from a checkout;
`pyproject.toml` puts `src/` on the path.

| File | Covers |
| --- | --- |
| `conftest.py` | the suite-wide network guard and its `no_such_host` / `allow_resolver` opt-outs |
| `test_ip.py` | `parse`/`try_parse`/`is_valid`, the aliases, CIDR maths |
| `test_mac.py` | `MACAddress` parsing, ordering, and the hash/eq law across every accepted spelling |
| `test_net.py` | DNS and ping, with `dns.resolver` and `subprocess.run` faked throughout |
| `test_interfaces.py` | `get_interfaces` invariants, the pure helpers, the degraded fallback |
| `test_sockets.py` | bind / `tcp_check` / route / MTU; loopback, or assertions about shape |
| `test_scan.py` | `scan_ports` / `scan_hosts` and the multicast helpers, loopback only |
| `test_centralized.py` | the helpers centralised from sibling repos: `bind`, `interface_for`, `UdpEndpoint`, `Host`, `retry` |
| `test_cli.py` | the CLI; skips itself when the `cli` extra is absent |
| `test_platform_smoke.py` | the **only** non-mocked tests — the real `ping`/`ping6` binary and real loopback sockets |
| `typing/api.py` | the static-typing contract; never executed, checked by mypy with `typing/consumer.ini` |

`tests/test_platform_smoke.py` must stay unmocked. Every other ping test
asserts the argv the library builds, which cannot catch a flag the platform
rejects; this file is what turns "CI is green" into evidence about the
platform. If one of its assertions fails, the library is broken there — do not
mock it to make it pass.

Run against **3.9 and 3.14** — 3.9 is the floor, so no unquoted `X | Y` unions
at runtime. CI runs the full 3.9–3.14 matrix on ubuntu plus both edges on
windows and macos, on a push to `main`, on a pull request against `main`, on a
`ci-*` tag (a throwaway tag, so an agent without dashboard access can trigger
and poll a run), and on `workflow_dispatch`. The docs site is built and
deployed by a separate `docs.yml` — on a docs-affecting push to `main`, on
`workflow_dispatch`, and on `release: published` — so a wrong sentence on the
landing page can be corrected without cutting a version.

Code is formatted with **black** (`target-version = py39`, configured in
`pyproject.toml`; installed by the `dev` extra):

```bash
.venv/dev/Scripts/black src/ tests/          # format
.venv/dev/Scripts/black --check src/ tests/  # verify, as CI does
```

`benchmarks/run.py` is a perf suite run **on demand**, never per push — shared
runners are too noisy for the numbers to mean anything. `python
benchmarks/run.py --save` writes one JSON per (platform, interpreter,
architecture) into `benchmarks/results/`, which is tracked so a before/after
comparison stays recoverable.

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md). Pre-1.0, MINOR means "the documented API
broke" and nothing else — additions and fixes are PATCH. Pushing a tag matching
`v*` triggers the release workflow: test gate → build → strict docs build
(a *gate*, not a deploy) → GitHub release → publish to PyPI with
`skip-existing: true`, so a run that fails partway through can be re-run.
Creating the release fires `docs.yml`, which owns every Pages deploy. Package
builds locally with `hatchling`.

## License

MIT — see [LICENSE](LICENSE).
