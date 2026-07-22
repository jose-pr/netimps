# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-07-22

Additive: the helpers found duplicated across the sibling repos, centralized so
they can adopt one implementation. No breaking changes.

### Added

- **`bind(address, port, ...)`** -- socket creation, option-setting and binding
  in one call, with `reuse_address`/`reuse_port`/`broadcast`/`listen` named and
  arbitrary `(level, name, value)` triples via `options`. `reuse_port` is a
  **no-op where `SO_REUSEPORT` does not exist** (Windows) rather than an error.
  The socket is closed before any exception propagates.
- **`bind_error_hint(exc, port)`** -- turns a bind failure into an actionable
  sentence, recognising both the POSIX errnos and the Windows `10013`/`10048`
  codes. Returns `None` for anything unrecognised, so the caller keeps the
  original error rather than a worse paraphrase.
- **`interface_for(address, strict=True)`** -- reverse lookup from an address to
  the `Interface` holding it. `strict=False` synthesizes a host-route interface
  named `"<unknown>"` for callers that need *something* to attribute traffic to.
- **`UdpEndpoint` / `Datagram`** -- UDP receive that reports which interface a
  datagram arrived on, via `IP_PKTINFO`. Degrades to plain `recvfrom` with
  `interface=None` where unavailable (Windows has no `recvmsg`); check
  `.supports_pktinfo`. `send(..., source=)` pins the outgoing interface.
- **`Interface.primary_ip(ipv6=False, loopback_ok=True)`** -- picks the one
  entry representing an adapter, preferring non-loopback. Named *primary*
  because it is a selection: the full lists stay on `.ips`/`.ipv4`/`.ipv6`.
  Returns the same `ip_interface` element type as `.ips`, and the result is one
  of them; use `.ip` for the bare address.
- **`iter_addresses(interfaces=None, family=None)`** -- the flattened
  `(interface, address)` view, for consumers that filter or act per address
  rather than per adapter.
- **`Host`** -- a hostname-or-address value type that keeps the original text,
  resolves lazily and caches. `str(host)` is always what was given, so a URL can
  still be rebuilt when resolution fails.
- **`retry(func, ...)`** and **`backoff_delays(...)`** -- bounded retry with
  exponential backoff and jitter. Only `OSError` is retried by default, since a
  `ValueError` means the call is malformed and will fail identically; the last
  exception is re-raised unwrapped so the traceback still points at the real
  problem.
- **Named networks**: `APIPA`, `LOOPBACK_V4`, `LOOPBACK_V6`, `LINK_LOCAL_V6`.

### Changed

- The loose "which interface?" coercion accepted by `ping(source=)`,
  `multicast_socket(interface=)` and now `bind(interface=)` is one shared
  implementation instead of two near-copies, and **returns a parsed address
  rather than a string** -- matching the rest of the package, with `str()`
  applied at the OS boundary.

## [0.2.0] - 2026-07-21

The distribution was renamed and the API reshaped in one release. 0.1.0 was
never published, so there are **no deprecation shims** — call sites must be
updated.

### Changed

- **Renamed the package `netutils` → `netimps`**, import name included. The old
  name is taken on PyPI and is generic.
- **`IPAddress` / `IPInterface` / `IPNetwork` are now type aliases**, not
  factory functions — the v4/v6 unions you annotate with, reading the way
  `ipaddress.IPv4Address` does. The factories took the short names `IPAddr()`,
  `IPIface()`, `IPNet()`, mirroring the stdlib's callable `ip_address()`.
- **`nslookup` was replaced by `resolve`**, which takes the record type second
  — the argument callers actually vary — instead of after the nameserver.
- **DNS lookups no longer swallow every exception into `[]`.** Genuine lookup
  failures (NXDOMAIN, no answer, all nameservers failed, timeout) still return
  `[]`; a malformed query or unknown record type now raises `ValueError`. A
  bare `except Exception` previously made a typo'd record type indistinguishable
  from "no such record".
- `timeout` bounds the **whole resolution including retries**, not a single
  query — a list of dead nameservers used to run far past any expectation.
- Renamed `is_loopback_or_link_local` → **`is_link_scoped`**, naming the shared
  property (confined to link scope or narrower) rather than listing the two
  cases. Note it is *not* "is private": RFC 1918 ranges are globally scoped and
  return `False`.

- **`parse(value, type, **kwargs)` replaces the `IPAddr`/`IPIface`/`IPNet`
  factories.** One entry point taking the result type directly -- the same
  union aliases callers already annotate with. `kwargs` reach the underlying
  builder, so the non-strict network default is overridable with
  `strict=True`. `try_parse` and `is_valid` delegate to it and share the `type`
  parameter name.
- `is_valid_ip`/`is_valid_network`/`is_valid_mac` collapse into
  `is_valid(value, type)`.
- `ping(ttl=...)` behaves identically on every platform. Windows `ping` exits
  `0` for "TTL expired in transit", so the reply address is verified rather
  than the exit code trusted.
- The package is split into private submodules (`_ip`, `_mac`, `_ifaddrs`,
  `_sockets`, `_dns`, `_ping`, `_scan`, `_multicast`, `_scheme`). The import
  surface is unchanged -- everything is still re-exported from `netimps`.

### Added

- **Socket helpers** every network tool rewrites: `get_source_ip` (the
  UDP-connect trick, correct where hostname resolution picks a VM adapter),
  `free_port`, `tcp_check`, `wait_for_port`.
- **Routing and distance**: `get_route` reports source and first hop, available
  unprivileged on every platform. `hop_count` uses raw-socket probes when
  permitted and otherwise drives the system `traceroute`, so it works without
  elevation; only the hop number and destination address are parsed, never the
  localised prose.
- **MTU**: `Interface.mtu` everywhere, and `path_mtu` for the Linux `IP_MTU`
  case (absent on Windows, where it returns `None` rather than guessing).
- **CIDR set maths**: `collapse` and `subtract` -- the latter missing from
  `ipaddress`, which ships `collapse_addresses` but nothing to punch holes.
- **`normalize_host`**: `host:port` splitting that keeps `"::1"` an address
  rather than host `"::"` port `1`.
- **Scanning**: concurrent `scan_ports` and `scan_hosts` over `tcp_check`.
  Ports accept a named range, a scheme name resolved through
  `get_default_port`, a number, or any mix. `scan_hosts` refuses anything
  larger than a /16.
- **Multicast**: `multicast_socket`, `join_group`, `leave_group`,
  `is_multicast`, wrapping a setup whose failure modes are silent -- binding to
  the group fails on Windows, `SO_REUSEPORT` does not exist there, and the
  wrong interface means the socket simply never receives.
- **`ping` returns a `PingResult`** carrying `rtt_ms`/`ttl`/`source`, still
  truthy and still equal to `bool`. New `source` (accepting an `Interface`,
  address, MAC, adapter name or string), `size`, `ttl` and `dont_fragment`
  arguments.
- **`resolve` returns native types**: `A`/`AAAA` as `ipaddress` objects, names
  without the trailing root dot, TXT strings unquoted.
- **`MACAddress.is_valid` / `.try_parse`** classmethods -- the type-local
  spelling. `classmethod`, so a subclass validates against itself.
- **`get_interfaces()`** — native interface discovery with adapter names, MACs
  and *real* prefix lengths, via `ctypes` bindings to `getifaddrs(3)` (POSIX)
  and `GetAdaptersAddresses` (Windows). **No third-party dependency**; `ifaddr`
  is not used. Results are normalised across platforms, with `Interface.raw`
  as an opt-in escape hatch for platform-specific data.
- `Interface` type, including `is_loopback` computed from the *addresses*
  rather than the name — `lo`, `lo0` and `Loopback Pseudo-Interface 1` share no
  spelling.
- **`try_parse(value, parser)`** — generic non-raising parse returning the value
  or `None` — and **`is_valid(value, parser)`**, the boolean counterpart. Both
  work with any factory, and swallow only `ValueError`/`TypeError`; anything
  else propagates rather than being disguised as a rejected value.
- `is_valid_network`, alongside the existing `is_valid_ip` and a new
  `is_valid_mac`.
- Type aliases `IPAddressLike`, `IPNetworkLike`, `MACLike` for accepted-input
  positions.
- `MACAddress` gains ordering (so MACs sort), `.oui`, `.is_multicast`,
  `.is_local` / `.is_universal`, and `as_str(sep, upper=True)` for the
  uppercase rendering Windows tooling favours. Case stays presentational — it
  never affects equality or hashing.
- `resolve()` gains `timeout`, `port` and `tcp`.
- `ping` gains `timeout` and `ipv6` family selection, a wall-clock cap on the
  subprocess (`-W` bounds the reply wait, not a hung resolver), and a
  missing-binary guard. Sub-second timeouts round **up**, never to 0 — some
  `ping` implementations read 0 as "wait forever".
- `get_ip`, `get_default_port`, and `is_link_scoped`, ported from a downstream
  consumer.
- **`port_scheme(port)`** — the inverse of `get_default_port`, and
  **`register_port(scheme, port, canonical=False)`** to extend or override the
  table. The built-in list grew from 6 entries to ~30. Where several schemes
  share a port, the canonical one is returned, and registering an alias does not
  silently change what a port maps back to.

### Removed

- **`parse_ip` / `parse_network` / `is_valid_ip` / `is_valid_network` /
  `is_valid_mac`** -- superseded by `parse`/`try_parse`/`is_valid`.
- **`IPAddr` / `IPIface` / `IPNet`** -- superseded by `parse(value, type)`.
- **`active_nic_addresses`, `get_ip_address`, `nic_info`.** All three are
  superseded by `get_interfaces()`, which is correct where they were not.
  `active_nic_addresses()` returned an arbitrary *single* address — whatever
  `gethostbyname_ex` happened to list first, routinely a WSL/VM/VPN adapter
  rather than the real NIC — and discarded the rest despite the plural name.
  `get_ip_address`/`nic_info` were POSIX-only.
- **`nslookup`.** Superseded by `resolve()`, which is the same lookup with a
  better argument order; keeping both would have been two names for one thing.
- **`parse_ip` / `parse_network`.** They mapped only empty strings to `None`
  while still raising on malformed input — a split contract that made "returns
  `None`" mean two different things. Use `try_parse(value, IPAddr)` /
  `try_parse(value, IPNet)`.

## [0.1.0] - 2026-07-18

### Added

- Initial release.
- IP factories `IPAddress`, `IPInterface`, `IPNetwork` (non-strict networks) over
  the standard library, plus concrete-type re-exports (`IPv4Address`, ...).
- `MACAddress` type: parses colon/hyphen/dot/bare forms, case-normalised,
  hashable, with `as_str(sep)` rendering and a `_VALID_MAC` pattern.
- Tolerant `parse_ip` / `parse_network` (empty input → `None`) and a
  non-raising `is_valid_ip`.
- `nslookup` (list-of-strings contract, `[]` on failure, uses `resolver.resolve`),
  `ping`, and local NIC helpers `active_nic_addresses` / `get_ip_address` /
  `nic_info`.

[Unreleased]: https://github.com/jose-pr/netimps/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jose-pr/netimps/releases/tag/v0.3.0
[0.2.0]: https://github.com/jose-pr/netimps/releases/tag/v0.2.0
[0.1.0]: https://github.com/jose-pr/netimps/releases/tag/v0.1.0
