# `netimps` — public API header

Header-file-style reference for the `netimps` package: every `__all__` export
with its signature, arguments, contract, and gotchas, so this module can be
consumed without reading its source.

Everything is imported from `netimps` directly. The `_`-prefixed submodules
(`_ip`, `_mac`, `_ifaddrs`, `_sockets`, `_dns`, `_ping`, `_scan`, `_multicast`,
`_scheme`) are implementation detail — **do not import them**. For the project
overview see the repo-root `AGENTS.md`.

`netimps.__version__` — the package version string (currently `"0.0.0"`).

## Types vs parsing — read this first

The noun names are **types you annotate with**; you turn values into them with
one function:

```python
def route(dst: netimps.IPAddress, via: netimps.IPNetwork) -> None: ...   # type

addr = parse("10.0.0.5")                      # -> IPv4Address
net  = parse("10.0.0.5/24", IPNetwork)        # -> IPv4Network('10.0.0.0/24')
```

The union aliases are **not callable** — `IPAddress("10.0.0.5")` is a
`TypeError`. Use `parse`.

## Type aliases

| Name | Meaning |
| --- | --- |
| `IPAddress` | `IPv4Address \| IPv6Address` |
| `IPInterface` | `IPv4Interface \| IPv6Interface` (address + prefix) |
| `IPNetwork` | `IPv4Network \| IPv6Network` |
| `IPAddressLike` | anything accepted *as input* for an address |
| `IPNetworkLike` | anything accepted *as input* for a network |
| `MACLike` | `str \| int \| bytes \| MACAddress` |

Plus the stdlib concretes re-exported so callers need not import `ipaddress`:
`IPv4Address`, `IPv4Interface`, `IPv4Network`, `IPv6Address`, `IPv6Interface`,
`IPv6Network`.

**The `*Like` aliases are input-only** and are rejected in a `type` position —
they describe what goes in, not what to build.

## Parsing

- **`parse(value, type=IPAddress, **kwargs)`** — build `type` from `value`,
  raising on bad input. `type` is a union alias, a concrete class, or any
  callable. Extra `kwargs` pass to the underlying builder.
- **`try_parse(value, type=IPAddress, default=None, **kwargs)`** — same, but
  returns `default` instead of raising.
- **`is_valid(value, type=IPAddress, **kwargs)`** — same, returning `bool`.

All three spell the second argument `type`, so it works positionally or by
keyword. Key behaviours:

- **Every type accepts the full stdlib input range** — `str`, `int`, packed
  `bytes`, or an existing object — because the builders are `ipaddress.ip_*`,
  not the concrete constructors.
- **Unions accept either family; concrete types are strict.**
  `parse("::1", IPAddress)` works; `parse("::1", IPv4Address)` raises, because
  asking for v4 and receiving v6 would defeat the request.
- **Networks are non-strict by default**, unlike the stdlib:
  `parse("10.0.0.5/24", IPNetwork)` normalises to `10.0.0.0/24` instead of
  raising. Pass `strict=True` for stdlib behaviour.
- **Only `ValueError`/`TypeError` count as "invalid".** Anything else (an
  `OSError` from a network-touching builder, a bug in it) propagates rather
  than being disguised as a rejected value.
- An unusable `type` raises `TypeError` **even from `try_parse`** — a caller
  bug is not a rejected value.

> **Gotcha:** `is_valid` uses an internal sentinel rather than testing
> `try_parse(...) is not None`, so a builder that legitimately returns `None`
> for valid input still counts as valid. Do not "simplify" that away.

## `MACAddress`

**`MACAddress(value)`** — an IEEE 802 hardware address. Accepts colon
(`AA:BB:CC:DD:EE:FF`), hyphen, dot/Cisco (`aabb.ccdd.eeff`) or bare
(`AABBCCDDEEFF`) text, a 48-bit `int`, 6 raw `bytes`, or another `MACAddress`.

Normalised to lowercase, compared and hashed by canonical bytes, so it works as
a dict key and two values differing only in parsed case are equal.

| Member | Meaning |
| --- | --- |
| `.as_str(sep=":", upper=False)` | render with any separator; `sep=""` for bare form |
| `.packed` | the 6 raw bytes |
| `.oui` | 3-byte vendor prefix |
| `.is_multicast` | group bit (low bit of octet 0) |
| `.is_local` / `.is_universal` | the U/L bit |
| `int(mac)`, `str(mac)` | integer / colon form |
| `<`, `<=`, `>`, `>=` | ordering, so MACs sort |
| `MACAddress.is_valid(v)` / `.try_parse(v)` | classmethods; the type-local spelling |

- **Not a `bytes` subclass** — deliberately, matching how `ipaddress` models
  addresses. Use `.packed` at wire boundaries.
- Case is presentational only: `upper=True` never affects equality or hashing.
- `.is_local` means *locally administered* (VMs, containers, MAC randomisation),
  so such addresses are **not stable identifiers**.
- The classmethods are `classmethod`, not `staticmethod`, so a subclass
  validates against itself.

## Interface discovery

**`get_interfaces(raw=False) -> List[Interface]`** — adapter names, MACs, MTU
and **real prefix lengths**, via `ctypes` bindings to `getifaddrs(3)` (POSIX)
and `GetAdaptersAddresses` (Windows). **No third-party dependency**; `ifaddr`
is deliberately not used.

**`Interface`** — normalised identically across platforms:

| Attribute | Meaning |
| --- | --- |
| `.name` | human-usable name (`eth0`, `en0`, Windows *friendly* name — never a GUID) |
| `.index` | `if_nametoindex` value, `0` if unknown |
| `.mac` | `MACAddress` or `None` |
| `.ips` | every address with its real prefix |
| `.ipv4` / `.ipv6` | the split views |
| `.mtu` | link MTU in bytes, or `None` |
| `.primary_ip(ipv6=False, loopback_ok=True)` | pick **one** entry from `.ips` (non-loopback preferred), or `None` |
| `.is_loopback` | **computed from the addresses, not the name** |
| `.raw` | `None` unless `raw=True`; platform-specific leftovers |

- **`is_loopback` never matches on names.** `lo`, `lo0` and
  `Loopback Pseudo-Interface 1` share no spelling; `127.0.0.0/8` and `::1` do.
- **`.raw` is not portable** and sits outside the stability guarantee — the
  escape hatch for adapter GUIDs, `IFF_*` flags, WMI correlation.
- **Never raises for enumeration failure.** If the native call is unavailable it
  degrades to hostname resolution, where **prefixes are fiction** (every address
  becomes `/32` or `/128` under an interface named `"<unknown>"`). Check
  `iface.name == "<unknown>"` to detect it.
- **`primary_ip()` is a selection, not "the" address** — an adapter routinely
  has several. It returns the **same element type as `.ips`** (an
  `ip_interface`, carrying the prefix) and the result *is* one of them; use
  `.ip` for the bare address that socket options take.

**`iter_addresses(interfaces=None, family=None)`** — the flattened
`(interface, address)` view, yielded once per address rather than per adapter,
for consumers that filter or act per address. The full `Interface` comes along,
so nothing is lost. Pass an existing enumeration in a loop; it is a syscall.

## Address and network helpers

- **`get_ip(address) -> IPAddress | None`** — literal *or hostname* to an
  address. **May block on DNS**, unlike `try_parse`, which never touches the
  network.
- **`is_link_scoped(ip) -> bool`** — loopback (host scope) or link-local (link
  scope): confined to this host or link. **Not "is private"** — RFC 1918 ranges
  are globally scoped and return `False`.
- **`collapse(networks) -> List[IPNetwork]`** — merge adjacent/overlapping
  networks into the minimal equivalent list. Mixed families collapse
  independently.
- **`subtract(networks, remove) -> List[IPNetwork]`** — set difference, which
  `ipaddress` omits (it ships `collapse_addresses` but nothing to punch holes).
  Result is collapsed.
- **`normalize_host(text, default_port=None) -> (host, port)`** — split
  `host:port`, handling IPv6 brackets. **`"::1"` stays an address**, never host
  `"::"` port `1` — the mistake hand-rolled splitters make. Only a bracketed v6
  address may carry a port; scope ids are preserved.

## Scheme ↔ port registry

- **`get_default_port(scheme) -> int | None`** — built-in table (~30 entries,
  including the socks variants absent from `/etc/services`), then
  `getservbyname`. Case-insensitive.
- **`get_default_scheme(port) -> str | None`** — the inverse, then
  `getservbyport`.
- **`register_port(scheme, port, canonical=False)`** — extend or override.

Where several schemes share a port (1080 → socks/socks4/socks5) the **canonical**
one is returned. Registering an alias does not steal that slot unless
`canonical=True`.

## DNS

**`resolve(query, rdtype="a", ns=None, timeout=5.0, port=53, tcp=False)`**

Returns a `list`, **empty on any genuine lookup failure** (NXDOMAIN, no answer,
all nameservers failed, timeout) — never `None`, so `if result:` and
`result[0]` are safe.

**Records are native types**: `A`/`AAAA` are `ipaddress` objects, everything
else is `str` with the trailing root dot stripped and TXT strings unquoted.

- **A malformed query or unknown record type raises `ValueError`** — a caller
  bug, not a DNS result. A broad `except` here would make a typo'd record type
  indistinguishable from "no such record".
- `timeout` bounds the **whole resolution including retries**, so a list of
  dead nameservers cannot run past it.
- Requires `dnspython` — the package's only runtime dependency.

## Reachability

**`ping(hostname, tries=1, timeout=1.0, ipv6=None, source=None, size=None, ttl=None, dont_fragment=False) -> PingResult`**

`PingResult` is **truthy on success** and compares equal to `bool`, so
`if ping(host):` and `== True` keep working, while carrying `.ok`, `.rtt_ms`,
`.ttl`, `.source`, `.attempts`.

| Argument | Notes |
| --- | --- |
| `source` | `Interface`, address, **MAC**, adapter name or string. A MAC is resolved to the adapter holding it. |
| `size` | ICMP payload bytes. The wire packet is **28 bytes larger** (20 IP + 8 ICMP). |
| `ttl` | initial hop limit — `-i` on Windows, `-t` on POSIX (the letters are **swapped**). |
| `dont_fragment` | DF bit. With `size`, the manual MTU probe: largest passing `size` + 28 = path MTU. Ignored on macOS/BSD. |

- **`ttl` behaves identically on every platform.** Windows `ping` exits `0` for
  "TTL expired in transit", so the reply address is verified rather than
  trusting the exit code. Locale-independent — it matches on addresses, never
  prose.
- An unusable `source` (unknown MAC, adapter with no address, foreign address)
  gives a falsy result — it **never silently falls back** to the default route.
- Never raises: missing binary, hung subprocess and non-zero exit are all falsy.
- **ICMP echo is not "is the host up"** — most cloud firewalls drop it. Prefer
  `tcp_check`.

## Socket helpers

- **`bind(address="", port=0, *, family, kind, reuse_address=True, reuse_port=False, broadcast=False, interface=None, options=(), listen=None)`**
  — create, configure and bind in one call. `interface` accepts the usual union
  (`Interface`, MAC, adapter name, address) and **raises** if unresolvable
  rather than silently binding the wildcard. `reuse_port` is a **no-op where
  `SO_REUSEPORT` does not exist** (Windows), not an error. The socket is closed
  before any exception propagates, so a failed call leaks nothing.
- **`bind_error_hint(exc, port=None) -> str | None`** — an actionable sentence
  for a bind failure, recognising POSIX errnos *and* Windows `10013`/`10048`.
  Returns `None` for anything unrecognised, so the caller keeps the original
  error. **Does not raise** — what to do with a failure is the caller's call.
- **`interface_for(address, strict=True) -> Interface | None`** — reverse
  lookup. `strict=False` synthesizes a host-route interface named
  `"<unknown>"` instead of returning `None`.
- **`get_source_ip(dest="8.8.8.8", port=80)`** — which local address the kernel
  would use to reach `dest`. **Sends no packets.** The answer depends on
  `dest`: with a VPN up, a public probe returns the tunnel address and a LAN
  probe the physical one. Correct where hostname resolution picks a VM adapter.
- **`free_port(host="127.0.0.1", family=AF_INET) -> int`** — bind port 0 and
  read it back. **Inherently racy** — the port frees the instant it returns; if
  you can, bind port 0 in the server itself instead. `SO_REUSEADDR` is
  deliberately *not* set (it would hand back a `TIME_WAIT` port).
- **`tcp_check(host, port, timeout=3.0) -> bool`** — the honest reachability
  test. Never raises. Proves the handshake completed, not that the service is
  healthy; a filtered port is indistinguishable from a closed one.
- **`wait_for_port(host, port, timeout=30.0, interval=0.1, connect_timeout=None)`**
  — poll until it answers. Backs off to 1s; honours the overall deadline even
  when individual connects block.

## Routing, hops and MTU

- **`get_route(dest="8.8.8.8") -> Route`** — `.source`, `.gateway`,
  `.interface_index`, `.on_link`. **First hop only, deliberately** — that is
  available unprivileged everywhere, unlike the full path. Never raises;
  unknown pieces are `None`/`0`. The gateway resolves on Windows and Linux only.
- **`hop_count(dest, max_hops=30, timeout=1.0, allow_traceroute=True)`** — uses
  raw-socket probes when permitted, otherwise drives the system
  `traceroute`/`tracert`, so it **works unprivileged**. Only the hop number and
  destination address are parsed, never localised prose.
  `allow_traceroute=False` requires the in-process path and raises
  `PermissionError` instead. **`None` means "no answer", never "unreachable"** —
  firewalls routinely drop ICMP even for an elevated process.
- **`path_mtu(dest, port=80) -> int | None`** — reads `IP_MTU`. **Linux only in
  practice**: `IP_MTU`, `IP_MTU_DISCOVER` and `IP_DONTFRAG` do not exist on
  Windows, so it returns `None` there rather than guessing. For the local link
  MTU — which *is* available everywhere — use `Interface.mtu`.

## Scanning

- **`scan_ports(host, ports="common", timeout=1.0, workers=100) -> List[int]`**
- **`scan_hosts(network, port=None, ports=None, timeout=1.0, workers=100)`** —
  returns `[(address, [open_ports]), ...]`, hosts with nothing open omitted.

`ports` accepts a **`PORT_RANGES` name** (`"common"`, `"well-known"`, `"all"`),
a **scheme name** resolved via `get_default_port` (`"https"` → 443), a number, a
numeric string, or any iterable mixing those. Range names win over scheme names
where they collide.

- **`scan_hosts` refuses anything larger than /16** (IPv6 /112): a /8 sweep is
  16M addresses, a mistake rather than an intention.
- A **TCP** sweep, so a host answering on none of the probed ports does not
  appear — it is not ARP/ICMP discovery, and a firewalled host is
  indistinguishable from an absent one.
- Ordinary full connects: **no SYN/stealth scanning, no fingerprinting**.
  Connections are logged by the target like any other. Use on hosts you are
  responsible for.

## Multicast

- **`multicast_socket(group=None, port=0, interface=None, ttl=1, loop=True, bind=True, reuse=True)`**
  — a UDP socket configured and joined in one call. `group=None` gives a
  send-only socket.
- **`join_group(sock, group, interface=None)`** / **`leave_group(...)`**
- **`is_multicast(address) -> bool`** — `224.0.0.0/4` or `ff00::/8`; never raises.

The failure modes this exists to prevent are all **silent** — the socket binds,
receives nothing, and looks fine:

- Binds to `""`, not the group address: **binding to the group fails on Windows**.
- `SO_REUSEPORT` **does not exist on Windows** and is skipped there rather than
  raising.
- **`ttl=1` by default**, keeping traffic on the local link; raise it
  deliberately.
- `interface` accepts an `Interface`, MAC, adapter name or address, and pins
  *both* send and receive. Without it the kernel picks by routing table, which
  on a multi-homed host is regularly the wrong adapter. An unknown interface
  **raises** rather than falling back.

## UDP with arrival interface

**`UdpEndpoint(sock, pktinfo=True)`** — wraps a bound UDP socket so each
datagram reports which interface it arrived on, via `IP_PKTINFO`. Essential for
broadcast protocols, where a wildcard-bound server otherwise cannot tell which
network a request came from.

`recv(bufsize, resolve_interface=True) -> Datagram`, with `.data`, `.sender`,
`.local_address`, `.interface_index` and `.interface`.
`send(data, address, port, source=None)` pins the outgoing interface.

- **Degrades rather than failing.** `recvmsg` does not exist on Windows and
  `IP_PKTINFO` is not universal; there the interface fields are simply empty.
  Check `.supports_pktinfo` to know which mode you are in.
- Pass `resolve_interface=False` in a hot loop and use `.interface_index` —
  enumeration is a syscall.
- Wraps rather than subclasses the socket; the raw one stays on `.socket`.

## Retry

**`retry(func, attempts=3, delay=0.5, multiplier=2.0, max_delay=30.0, jitter=0.1, retryable=(OSError,), on_retry=None)`**

Calls `func()`, retrying transient failures with exponential backoff. Returns
whatever `func` returns; if every attempt fails **the last exception is
re-raised unwrapped**, so the traceback still points at the real problem.

- **Only `OSError` is retried by default** — that covers the socket family. A
  `ValueError` means the call is malformed and will fail identically, so it
  propagates immediately.
- `attempts` counts *total* calls: `attempts=1` calls once and never sleeps.
- `jitter` spreads retries so simultaneous failures do not resynchronise into a
  thundering herd. Applied **after** the cap and only ever shortens, so
  `max_delay` is a real ceiling.
- `on_retry(attempt, exc, next_delay)` is the logging hook; this logs nothing
  itself.
- Synchronous — it blocks. For async, drive **`backoff_delays(...)`** from your
  own loop; it yields the same schedule.

## Host

**`Host(value)`** — a host named by either an address or a hostname.

`str(host)` is **always the original text**, so a URL can still be rebuilt when
resolution fails — the case a bare `get_ip()` handles badly, since it returns
`None` and loses the name.

- `.is_address` — already a literal, no DNS needed.
- `.ip(refresh=False)` — resolve to an address or `None`. **Cached, including
  failure**, since the common use is several lookups on one object; pass
  `refresh=True` to retry.
- Compares equal to a plain `str`, and hashes by its text.

## Constants

- **`HOST_DN`** — `platform.node()`, captured **at import time** (a later
  hostname change is not reflected).
- **`PORT_RANGES`** — `{"well-known", "common", "all"}` port tuples.
- **`APIPA`** (`169.254.0.0/16`), **`LOOPBACK_V4`** (`127.0.0.0/8`),
  **`LOOPBACK_V6`** (`::1/128`), **`LINK_LOCAL_V6`** (`fe80::/10`) — named
  networks, so callers stop spelling the literals out.
