# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **`resolve_system(timeout=)` now bounds wall time.** The lookup ran inside a
  `with ThreadPoolExecutor(...)` block, whose `__exit__` joins the worker
  still blocked in `getaddrinfo` -- so the timeout changed *what* was raised
  but not *when*, and a 30s resolver hang still cost the caller 30s despite
  `timeout=5.0`. `resolve()`'s chain consequently never reached `nslookup` at
  the promised deadline either.
- **`interface=` is honoured for IPv6 multicast.** The spec was reduced to an
  address and then passed to `if_nametoindex()`, which always fails for an
  address string, so the `IPV6_JOIN_GROUP` index silently stayed `0` --
  "kernel's choice", the exact default `interface=` exists to override.
  `IPV6_MULTICAST_IF` was never set at all, so sends left by the default
  route while joins listened elsewhere. Both now resolve the adapter to its
  interface index. IPv4 behaviour is unchanged.
- **`ping(hostname, ipv6=True)` is no longer always false.** The reply address
  was resolved with the IPv4-only `gethostbyname`, so a v6 reply was checked
  against a v4 expectation and never matched. The expectation now comes from
  `getaddrinfo` honouring `ipv6=`, and a name resolving to several addresses
  counts as answered if the reply came from any of them.
- **`ping(..., method="tcp"/"udp")` reaches IPv6 destinations.** Both probes
  opened `AF_INET` sockets unconditionally, so a v6 destination failed inside
  `connect`/`sendto` and was reported as unreachable -- a wrong falsy answer
  rather than an error. `ipv6=` now applies to all three methods.
- **`ping(..., method="udp")` detects ICMP port-unreachable on POSIX.** The
  probe socket was never connected, and POSIX delivers asynchronous ICMP
  errors only to connected UDP sockets -- so the documented "host answered,
  nothing listening" signal worked on Windows alone and the probe just timed
  out on Linux/macOS. `ECONNREFUSED` and `ECONNRESET` both now count.

### Documentation

- The shipped API header named `PingResult.source` and `Route.source`; both
  attributes are spelled `.src` (and `PingResult.host` was unlisted).
- Recorded the per-family multicast interface selection, `ping`'s `ipv6=`
  reach across all three methods, and `resolve_system`'s real wall-time
  deadline in the shipped header.
- Added the known, still-unverified macOS/BSD `ping6` reply-shape gap
  (`from <addr>,` rather than `from <addr>:`) to the header rather than
  guessing a parser change without a macOS runner.

## [0.2.1] - 2026-07-30

### Added

- **`AddressLike`**, a new type alias (`str | IPv4Address | IPv6Address |
  IPv4Interface | IPv6Interface`) accepted by every `dst`-typed parameter:
  `ping`, `tcp_check`, `wait_for_port`, `get_route`, `hop_count`, `get_pmtu`,
  `discover_mtu`, `get_tcp_mss`, `scan_ports(host)`, `get_ip`,
  `UdpEndpoint.send`, and `resolve`'s (and its backends') `query`. An
  `IPv4Interface`/`IPv6Interface` unwraps to its `.ip` -- previously passing
  one stringified with its `/prefix` intact, which every consumer
  (subprocess argument, socket call, DNS query) read as garbage. A network
  (`IPv4Network`/`IPv6Network`) raises `TypeError`, since it has no single
  address to use.
- **`resolve()` (and all three backends) auto-select `rdtype`.** It now
  defaults to `None`, which picks `"ptr"` when `query` is an address literal
  and `"a"` otherwise -- `resolve("8.8.8.8")` now returns `['dns.google']`
  instead of attempting a nonsensical A lookup on a literal address. Pass an
  explicit `rdtype` to opt out. `resolve_system()` gains `"ptr"` support (via
  `socket.gethostbyaddr()`) to make this work across every backend.

### Fixed

- **`ping(src=...)` crashed with `NameError` instead of returning a falsy
  result** when `src` named an interface with no usable address (e.g. an
  unknown adapter name, or a MAC not currently present) -- a leftover
  reference to an undefined `hostname` variable instead of `dst`. Found via
  a `mypy` pass while auditing type annotations; a regression test now
  covers the path.

### Changed

- Public functions across the package now carry complete parameter and
  return type annotations (previously missing on, among others, `collapse`,
  `subtract`, `get_ip`, `PingResult`, `Route`, `scan_hosts`, `is_multicast`,
  `join_group`/`leave_group`, `multicast_socket`, `UdpEndpoint`, and `bind`).
  The recurring "loose interface spec" parameter (`ping(src=)`,
  `bind(interface=)`, `discover_mtu(src=)`, `multicast_socket(interface=)`,
  etc.) now shares one internal type alias instead of being unannotated at
  each call site.

## [0.2.0] - 2026-07-29

### Added

- **Three independently callable DNS backends**, plus `resolve()` chaining
  them: `resolve_dnspython()` (the original `dnspython`-backed
  implementation, every record type), `resolve_system()`
  (`socket.getaddrinfo()` -- hosts file, NSS, OS resolver cache, address
  records only), and `resolve_nslookup()` (shells out to `nslookup`, parses
  both BIND-style and Windows-style output, address records only). `resolve()`
  now tries `["dnspython", "system", "nslookup"]` in order by default and
  returns the first definitive answer, skipping/falling through backends that
  can't serve the request (non-address `rdtype`, missing binary, `dnspython`
  not installed). A custom order/subset is available via
  `resolve(..., backends=[...])` (or a single name as a plain string).
- `resolve()` (and all three backends) gain a `search` parameter for the
  system resolver's search list (`resolv.conf`'s `search`/`domain`
  directive, or the Windows per-adapter DNS suffix list). It defaults to
  `True`, so an unqualified name like `resolve("db1")` is expanded the way
  `ping db1` would be; `search=False` looks the name up literally (as a
  fully-qualified name, so the OS resolver's own search-list logic doesn't
  kick in either), and a list of domain names tries exactly those suffixes
  instead of the system list.
- `dnspython` is now an **optional** dependency (`pip install netimps[dns]`),
  since `resolve()` can fall back to `resolve_system()`/`resolve_nslookup()`
  without it. The CLI's `resolve` subcommand now reports a missing-backend
  failure as a clean CLI error rather than an uncaught exception.

### Changed

- **`resolve()`'s default behavior for unqualified names.** Previously an
  unqualified `query` was only ever looked up as-is; it now also tries the
  system resolver's search list first (see `search` above). Pass
  `search=False` to keep the old literal-only behavior. `ns=None` already
  used the system resolver's nameservers; an invalid `ns=` now raises before
  any query is attempted rather than silently falling back to the system
  default.
- **`resolve()` is no longer purely `dnspython`-backed.** Behavior should be
  unchanged for existing callers when `dnspython` is installed (it's still
  tried first), but a lookup that previously raised or returned `[]` because
  `dnspython` failed for a reason unrelated to the DNS answer itself (e.g. a
  malformed system resolver config) may now succeed via the `system` or
  `nslookup` fallback instead.

## [0.1.0] - 2026-07-25

### Added

- **Complete local-interface membership lookups.** `interfaces_for()` yields
  every adapter matching an interface, exact address/`IPInterface`, network,
  or `MACAddress`, while `interface_for()` keeps the first-match scalar
  contract. `is_local_address()` distinguishes an assigned or loopback address
  from one that is merely private, link-local, on-link or reachable.
- **Static parser contracts.** `TypeForm` overloads preserve union and concrete
  result types, callable builders, and explicit `try_parse(default=...)`
  fallbacks. `IPInterfaceLike` now complements the existing input aliases.

### Changed

- `interface_for()` accepts networks and MAC addresses, including MAC text and
  6-byte packed values. Integer MACs remain explicit `MACAddress` values. Its legacy
  `strict=False` synthetic fallback remains address-only because a missing
  network or MAC has no honest single-interface representation.
- The IP input aliases now include packed bytes plus the exact stdlib
  two-tuple and existing-interface forms accepted by the interface/network
  factories. `is_valid()` is documented as a boolean convertibility check
  rather than an unsound type guard for the original object.

## [0.0.2] - 2026-07-23

### Added

- **`ws`/`wss` in the built-in scheme→port table** (80/443). WebSocket schemes
  (RFC 6455) ride the HTTP/HTTPS ports but are absent from `/etc/services`, so
  `get_default_port("wss")` previously returned `None` and every websocket
  consumer had to `register_port` them. `http`/`https` remain canonical for
  80/443.

## [0.0.1] - 2026-07-22

### Added

- **Command-line interface** (`netimps ...` / `python -m netimps`), built on
  duho and installed by the new `cli` extra. Eleven subcommands cover the
  diagnostic surface: `interfaces`, `ping`, `resolve`, `check`, `route`, `mtu`,
  `scan`, `addr`, `source`, `port`, `split`. Every one takes `--json`, and exit
  codes distinguish success from "the answer was no" from a caller error.
  `duho` is CLI-only -- importing the library does not require it.

## [0.0.0] - 2026-07-22

Initial release.

Earlier version numbers appear in this project's git history but were never
tagged or published, so there is no upgrade path to describe -- everything
below is simply what the package contains.

### Added

- **Interface discovery** -- `get_interfaces()` reports adapter names, MACs,
  MTU and *real* prefix lengths on Linux, macOS/BSD and Windows, via `ctypes`
  bindings to `getifaddrs(3)` and `GetAdaptersAddresses`. No third-party
  dependency. `Interface.is_loopback` is derived from the addresses rather than
  the name, since `lo`, `lo0` and `Loopback Pseudo-Interface 1` share no
  spelling. `Interface.primary_ip()` picks one entry; `iter_addresses()` is the
  flattened per-address view.
- **Types and parsing** -- `IPAddress`/`IPInterface`/`IPNetwork` union aliases
  to annotate with, and one `parse(value, type, **kwargs)` entry point with
  non-raising `try_parse` and boolean `is_valid` siblings. Concrete types are
  strict about family; networks are non-strict about host bits by default.
- **`MACAddress`** -- colon/hyphen/dot/bare plus `int`/`bytes`, hashable and
  ordered, with `.packed`, `.oui`, `.is_multicast`, `.is_local` and
  case-selectable rendering. A value type exposing `.packed`, not a `bytes`
  subclass, matching how `ipaddress` models addresses.
- **Socket helpers** -- `bind()`, `bind_error_hint()`, `interface_for()`,
  `get_source_ip()`, `get_free_port()`, `tcp_check()`, `wait_for_port()`.
- **`UdpEndpoint`** -- UDP receive reporting which interface a datagram arrived
  on via `IP_PKTINFO`, degrading where `recvmsg` does not exist.
- **Routing and MTU** -- `get_route()` (first hop, unprivileged), `hop_count()`
  (raw sockets or a traceroute fallback, so it works without elevation),
  `discover_mtu()` (measures the real path -- `method="icmp"` with DF-flagged
  pings, `"udp"` with datagrams, or `"tcp"` deriving from the negotiated MSS
  since TCP cannot be probed), `get_pmtu()` (the kernel's cached answer, usually
  `None`), `get_tcp_mss()`, and `Interface.mtu`. Header arithmetic is
  family-aware: IPv6 adds 20 bytes over IPv4, and assuming v4 on a v6 path
  under-reports by exactly that.
- **CIDR maths and host parsing** -- `collapse()`, `subtract()` (absent from
  `ipaddress`), and `normalize_host()`, which keeps `"::1"` an address rather
  than host `"::"` port `1`.
- **Scheme/port registry** -- `get_default_port()`, `get_default_scheme()`,
  `register_port()`.
- **DNS** -- `resolve()` returning native types (`A`/`AAAA` as `ipaddress`
  objects), `[]` on a genuine lookup failure, and `ValueError` for a malformed
  query rather than a silent empty result.
- **`ping()`** -- returns a `PingResult` with round-trip time and TTL that stays
  truthy. `method="icmp"|"tcp"|"udp"` reaches hosts through firewalls that drop
  echo; all three ask "is the *host* up?", so a TCP refusal or an ICMP
  port-unreachable counts as success. `tcp_check` remains the "is the *service*
  up?" question, where a refusal is a failure. `ttl=` behaves identically on every platform, because Windows `ping`
  exits 0 for "TTL expired in transit" and the reply address is verified
  instead of the exit code.
- **Scanning** -- concurrent `scan_ports()` / `scan_hosts()`, ports addressable
  by scheme name.
- **Multicast** -- `multicast_socket()`, `join_group()`, `leave_group()`,
  wrapping a setup whose failure modes are otherwise silent.
- **`Host`**, **`retry()`/`backoff_delays()`**, and the named networks `APIPA`,
  `LOOPBACK_V4`, `LOOPBACK_V6`, `LINK_LOCAL_V6`.

[Unreleased]: https://github.com/jose-pr/netimps/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/jose-pr/netimps/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/jose-pr/netimps/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jose-pr/netimps/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/jose-pr/netimps/releases/tag/v0.0.2
[0.0.1]: https://github.com/jose-pr/netimps/releases/tag/v0.0.1
[0.0.0]: https://github.com/jose-pr/netimps/releases/tag/v0.0.0
