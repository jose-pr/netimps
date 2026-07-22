# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/jose-pr/netimps/compare/v0.0.0...HEAD
[0.0.0]: https://github.com/jose-pr/netimps/releases/tag/v0.0.0
