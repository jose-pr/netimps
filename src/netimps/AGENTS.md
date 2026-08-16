# `netimps` — public API header

Header-file-style reference for the `netimps` package: every `__all__` export
with its signature, arguments, contract, and gotchas, so this module can be
consumed without reading its source.

Everything is imported from `netimps` directly. The `_`-prefixed submodules
(`_ip`, `_mac`, `_ifaddrs`, `_sockets`, `_dns`, `_ping`, `_scan`, `_multicast`,
`_scheme`, `_retry`, `_udp`, `_iface_spec`) are implementation detail —
**do not import them**.

**This file documents using the library**, and ships inside the package, so it
is self-contained: it references nothing outside the installed distribution.
`README.md` ships alongside it as the overview -- read either with
`importlib.resources.files("netimps")`. Development documentation (building,
testing, releasing) is not shipped; it lives with the source at
<https://github.com/jose-pr/netimps>.

`netimps.__version__` — the package version string (currently `"0.2.1"`).

## Argument naming

The package is consistent about what the first argument means:

| Name | Meaning | Examples |
| --- | --- | --- |
| `dst` | where traffic is **sent** | `ping`, `tcp_check`, `wait_for_port`, `get_route`, `hop_count`, `discover_mtu`, `get_tcp_mss`, `get_pmtu`, `scan_ports(host)` |
| `src` | where traffic is **sent from** | `ping(src=)`, `get_free_port(src=)`, `discover_mtu(src=)` |
| `host` / `network` | the thing being **examined** | `scan_ports(host)`, `scan_hosts(network)` |
| `address` / `ip` | an address being **classified** (no DNS) | `get_ip`, `interface_for`, `interfaces_for`, `is_local_address`, `is_multicast`, `is_link_scoped` |

`dst`/`src` are abbreviated symmetrically, matching packet-header convention.
A `dst` accepts a hostname; an `address` does not.

**Every `dst`-typed parameter accepts `AddressLike`** — a hostname string, an
address string, an existing `IPv4Address`/`IPv6Address`, or an
`IPv4Interface`/`IPv6Interface` (its `.ip` is used, dropping the `/prefix`,
which every consumer of a destination -- a subprocess argument, a socket
call, a DNS query -- would otherwise read as garbage). A network
(`IPv4Network`/`IPv6Network`) raises `TypeError`, since it has no single
address to send to. `get_ip` and `resolve`'s `query` accept the same forms.

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
| `IPInterfaceLike` | anything accepted *as input* for an address + prefix |
| `IPNetworkLike` | anything accepted *as input* for a network |
| `AddressLike` | `str \| IPv4Address \| IPv6Address \| IPv4Interface \| IPv6Interface` -- any `dst`-typed parameter |
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
- **`IPInterface` and non-strict `IPNetwork` accept the stdlib two-tuple
  form**, such as `("10.0.0.5", 24)`. `IPNetwork` also accepts an existing
  `IPInterface` and normalises its host bits. `IPAddress` accepts neither.
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
- Static type checkers preserve the selected result type, including the
  `IPAddress`/`IPInterface`/`IPNetwork` unions, concrete classes, callable
  builders, and the union with an explicit `try_parse(default=...)`.
- **`is_valid` returns a plain `bool`; it does not narrow the original input.**
  It proves convertibility, and parsing can create a different object.

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
  including the socks variants and the `ws`/`wss` websocket schemes, all absent
  from `/etc/services`), then `getservbyname`. Case-insensitive.
- **`get_default_scheme(port) -> str | None`** — the inverse, then
  `getservbyport`.
- **`register_port(scheme, port, canonical=False)`** — extend or override.

Where several schemes share a port the **canonical** one is returned (1080 →
`socks`, not `socks4`/`socks5`; 80 → `http`, not `ws`; 443 → `https`, not
`wss`). Registering an alias does not steal that slot unless `canonical=True`.

## DNS

Three independently callable backends, plus `resolve()`, which chains them.
All four share one contract: a `list`, **empty on any genuine lookup
failure** (NXDOMAIN, NODATA, timeout) — never `None` — with **native
types**: `A`/`AAAA` records are `ipaddress` objects, everything else is
`str` (trailing root dot stripped, TXT strings unquoted).

**`resolve(query, rdtype=None, ns=None, timeout=5.0, port=53, tcp=False, search=True, backends=None)`**

`query` accepts `AddressLike` (a hostname string, an address string, an
`IPv4Address`/`IPv6Address`, or an `IPv4Interface`/`IPv6Interface` -- its
`.ip` is used), not just a plain string.

`rdtype=None` (default) **auto-selects**: `"ptr"` when `query` is an address
literal (an `"a"`/`"aaaa"` lookup *of* an address makes no sense), `"a"`
otherwise -- the same default as before this was configurable::

    resolve("example.com")   # rdtype auto -> "a"  -> ['93.184.216.34']
    resolve("8.8.8.8")       # rdtype auto -> "ptr" -> ['dns.google']

Pass an explicit `rdtype` to opt out -- `rdtype="a"` on an address still
attempts a literal (and empty) A lookup rather than being silently
overridden.

Tries each backend in `backends` (default `["dnspython", "system",
"nslookup"]`) until one gives a **definitive** answer — records, or a real
empty result (NXDOMAIN/NODATA) — and returns that. A backend that could not
even *attempt* the query (missing binary, `dnspython` not installed, a
`rdtype`/`ns` it structurally can't serve) is skipped or falls through,
never mistaken for "no records". If every applicable backend fails that way,
the last such error is raised. `backends` also accepts a single name as a
plain string (`backends="system"`), or a custom order/subset
(`backends=["nslookup", "dnspython"]`).

- **`system`** is skipped automatically for a `rdtype` outside
  `"a"`/`"aaaa"`/`"ptr"`, or an explicit `ns=`/`port=` — it has no per-call
  nameserver override, so running it anyway would silently ignore the
  caller's choice.
- A malformed query or unknown record type raises `ValueError` immediately,
  without trying every backend — that's a caller bug, not a resolution
  outcome.

**`resolve_dnspython(query, rdtype=None, ns=None, timeout=5.0, port=53, tcp=False, search=True)`**

The original backend: `dnspython`, structured records, every `rdtype`. Same
`AddressLike` `query` and auto-`rdtype` behavior as `resolve()`. A `"ptr"`
lookup (explicit or auto-selected) uses dnspython's `resolve_address()`,
which builds the reverse (`in-addr.arpa`/`ip6.arpa`) name from the literal
address itself -- the caller never constructs that name by hand.

- **`ns=None` (default) uses the system resolver configuration** —
  `/etc/resolv.conf` on POSIX, the registry on Windows. Pass `ns=` (a string
  or list) to query specific nameservers instead; a malformed `ns=` raises
  immediately, before any query is attempted.
- **`search=True` (default) tries the resolver's search list** (the
  `search`/`domain` directive in `resolv.conf`, or the Windows per-adapter DNS
  suffix list) for an unqualified `query` — e.g. `resolve_dnspython("db1")`
  trying `db1.internal.example.com`, the same as `ping db1` would.
  `search=False` looks up `query` literally. A **list of domain names**
  (`search=["eng.example.com", "example.com"]`) tries exactly those suffixes
  instead of the system list, regardless of `ns`. Ignored for an
  already-qualified (trailing-dot) `query`.
- `timeout` bounds the **whole resolution including retries**, so a list of
  dead nameservers cannot run past it.
- `dnspython` is an **optional** dependency (`pip install netimps[dns]`).
  Raises `ResolutionError` (not `ValueError`) if it isn't installed, so
  `resolve()`'s chain falls through to the next backend instead of erroring
  outright.

**`resolve_system(query, rdtype=None, timeout=5.0, search=True)`**

The OS resolver, via `socket.getaddrinfo()`/`socket.gethostbyaddr()` — **hosts
file, NSS (`nsswitch.conf`) and DNS, in the order the OS applies them**,
including any OS-level resolver cache. This is what `resolve_dnspython`
cannot see (its own DNS query bypasses all of that). Same `AddressLike`
`query` and auto-`rdtype` behavior as `resolve()`.

- **Address and reverse records only**: `rdtype` must be `"a"`, `"aaaa"` or
  `"ptr"`; anything else raises `ResolutionError` immediately, no query
  attempted. `"ptr"` goes through `gethostbyaddr()` rather than
  `getaddrinfo()` and returns `[hostname]`.
- **No `ns=` override** — the OS resolver functions always ask whatever
  nameserver the OS is configured with; there's no per-call parameter at that
  layer (not even via `ctypes` — reaching a specific nameserver without
  shelling out means speaking DNS wire protocol yourself, which is what
  `dnspython` already does).
- **`search`** (ignored for `"ptr"`, which has no suffix to expand):
  `getaddrinfo` itself takes no search-list parameter either, so
  `search=True` (default) just leaves `query` as given and the OS resolver's
  own configured search list (glibc `ndots`/`search`, Windows per-adapter DNS
  suffix) applies as it normally would. `search=False` appends a trailing
  `.`, which every resolver reads as "already fully qualified" — the same
  trick `host`/`getent` scripts use. A **list of domain names** tries `query`
  qualified with each, in order, one `getaddrinfo` call per candidate,
  independent of (and untouched by) the OS's own search list.
- **`timeout` bounds wall time, per candidate name tried.** `getaddrinfo` has
  no timeout of its own, so each attempt runs in a daemon helper thread that
  is abandoned at the deadline; the underlying call is not cancelled, but
  neither the caller nor interpreter exit waits for it. A broken resolver
  therefore costs `timeout`, not however long it takes to give up — which is
  also what lets `resolve()`'s chain reach `nslookup` on schedule.

**`resolve_nslookup(query, rdtype=None, ns=None, timeout=5.0, search=True)`**

Shells out to the `nslookup` binary — a fallback for when neither Python-level
path is usable. Address records only: `rdtype` must be `"a"`, `"aaaa"` or
`"ptr"`. Same `AddressLike` `query` and auto-`rdtype` behavior as `resolve()`.

- Parses **both BIND-style** (`Address: 1.2.3.4`, one line per address) **and
  Windows-style** (`Addresses:` with continuation lines, and NODATA as a bare
  `Name:` line with no address and no error text) output. Windows also prints
  its NXDOMAIN message on **stderr**, not stdout — both streams are checked.
- `ns=` is passed as `nslookup`'s trailing `server` argument (a single
  nameserver, not a list).
- **`search`** has the same three-way contract as the other backends
  (ignored for `"ptr"`), but `nslookup` has no built-in search-list
  handling — this issues one `nslookup` call per candidate name, in order,
  stopping at the first with actual records. `search=True` (default) draws
  the candidate list from the system resolver's search config (reusing
  `dnspython`'s `resolv.conf`/registry parsing if it's installed; `[]` —
  literal name only — if not).
- Raises `ResolutionError` (not `ValueError`) for a missing binary, a
  timeout, or an unparseable output shape — a genuine "no such name" is
  still `[]`.

## Reachability

**`ping(dst, tries=1, timeout=1.0, ipv6=None, src=None, size=None, ttl=None, dont_fragment=False, method="icmp", port=None) -> PingResult`**

`PingResult` is **truthy on success** and compares equal to `bool`, so
`if ping(host):` and `== True` keep working, while carrying `.ok`, `.host`,
`.rtt_ms`, `.ttl`, `.src`, `.attempts`.

| Argument | Notes |
| --- | --- |
| `dst` | `AddressLike` (hostname, address string, address object, or `IPv4Interface`/`IPv6Interface` -- its `.ip` is pinged). `ping(get_interfaces()[0].ipv4[0])` works directly. |
| `src` | `Interface`, address, **MAC**, adapter name or string. A MAC is resolved to the adapter holding it. |
| `size` | ICMP payload bytes. The wire packet is **28 bytes larger** (20 IP + 8 ICMP). |
| `ttl` | initial hop limit — `-i` on Windows, `-t` on POSIX (the letters are **swapped**). |
| `dont_fragment` | DF bit. With `size`, the manual MTU probe: largest passing `size` + 28 = path MTU. Ignored on macOS/BSD. |
| `method` | `"icmp"` (default), `"tcp"` or `"udp"`. The latter two reach hosts through firewalls that drop echo. |
| `port` | required for `tcp`/`udp`, ignored for ICMP. |

**All three methods ask "is the *host* up?"** — so a TCP refusal counts as
success (the RST proves something answered), as does an ICMP port-unreachable
for UDP. Use `tcp_check` for "is the *service* up?", where a refusal is a
failure. `tcp` and `udp` also report `rtt_ms`; only ICMP reports `ttl`.

- **`ttl` behaves identically on every platform.** Windows `ping` exits `0` for
  "TTL expired in transit", so the reply address is verified rather than
  trusting the exit code. Locale-independent — it matches on addresses, never
  prose.
- **`ipv6=` applies to all three methods**, not just the ICMP binary: it picks
  the `-6`/`-4` flag, the family the reply address is resolved in, and the
  family the `tcp`/`udp` probe sockets use. `ipv6=None` accepts either. A
  hostname with several addresses counts as answered if the reply came from
  any of them.
- **The `udp` probe connects its socket before sending**, which is why the ICMP
  port-unreachable is seen on POSIX and not only on Windows — an unconnected
  UDP socket is never delivered an asynchronous ICMP error on Linux/BSD.
  `ECONNREFUSED` and `ECONNRESET` both count as "the host answered".
- **Known gap: macOS/BSD `ping6` reply lines.** Verification looks for
  `from <addr>:`; BSD `ping6` is documented as printing `from <addr>,`. If
  that holds, a v6 *literal* ping on macOS verifies as falsy despite a healthy
  reply. Unverified on real hardware, so deliberately not "fixed" by guess.
- An unusable `src` (unknown MAC, adapter with no address, foreign address)
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
- **`interface_for(query, strict=True) -> Interface | None`** — first matching
  adapter in OS enumeration order. `query` accepts an `Interface`, exact
  `IPAddress`, exact `.ip` from an `IPInterface`, an `IPNetwork` containing at
  least one assigned address, or an exact `MACAddress`. Address-like strings,
  integers and packed bytes remain accepted; a slash-bearing string is a
  network. MAC text and 6-byte packed values are recognised after IP parsing.
  Integer MACs must be wrapped in `MACAddress` because integers are also valid
  IP-address inputs. Invalid input and misses return `None`. With
  `strict=False`, only an address or `IPInterface` miss synthesizes a host-route
  interface named `"<unknown>"`; networks and MACs have no honest synthetic
  result.
- **`interfaces_for(query) -> Iterator[Interface]`** — every match for the same
  query forms, in OS order and with each adapter yielded once even if several
  assigned addresses match. An `Interface` yields itself without enumeration.
  Addresses need not be unique across adapters (unscoped IPv6 link-local is a
  common example), so use this plural form when every owner matters.
- **`is_local_address(address) -> bool`** — true only for loopback or an
  address assigned to a local adapter. Private, link-local, on-link, routable
  or reachable alone do not count. Malformed input raises like `parse`;
  loopback answers before interface discovery.
- **`get_source_ip(dst="8.8.8.8", port=80)`** — which local address the kernel
  would use to reach `dst`. `dst` accepts `AddressLike` (an address object or
  `IPv4Interface`/`IPv6Interface`, not just a string). **Sends no packets.**
  The answer depends on `dst`: with a VPN up, a public probe returns the
  tunnel address and a LAN probe the physical one. Correct where hostname
  resolution picks a VM adapter.
- **`get_free_port(src="127.0.0.1", family=AF_INET) -> int`** — bind port 0 and
  read it back. **Inherently racy** — the port frees the instant it returns; if
  you can, bind port 0 in the server itself instead. `SO_REUSEADDR` is
  deliberately *not* set (it would hand back a `TIME_WAIT` port).
- **`tcp_check(dst, port, timeout=3.0) -> bool`** — the honest reachability
  test. Never raises. Proves the handshake completed, not that the service is
  healthy; a filtered port is indistinguishable from a closed one.
- **`wait_for_port(dst, port, timeout=30.0, interval=0.1, connect_timeout=None)`**
  — poll until it answers. Backs off to 1s; honours the overall deadline even
  when individual connects block.

## Routing, hops and MTU

- **`get_route(dst="8.8.8.8") -> Route`** — `.dst`, `.src`, `.gateway`,
  `.interface_index`, `.on_link`. **First hop only, deliberately** — that is
  available unprivileged everywhere, unlike the full path. Never raises;
  unknown pieces are `None`/`0`. The gateway resolves on Windows and Linux only.
- **`hop_count(dst, max_hops=30, timeout=1.0, allow_traceroute=True)`** — uses
  raw-socket probes when permitted, otherwise drives the system
  `traceroute`/`tracert`, so it **works unprivileged**. Only the hop number and
  destination address are parsed, never localised prose.
  `allow_traceroute=False` requires the in-process path and raises
  `PermissionError` instead. **`None` means "no answer", never "unreachable"** —
  firewalls routinely drop ICMP even for an elevated process.
- **`discover_mtu(dst, low=576, high=9000, timeout=1.0, src=None, port=80, probe=True, method="icmp", **ping_kwargs)`**
  — **measures** the path MTU by binary-searching probes, so packets really
  traverse the path. Returns the MTU **including headers**, comparable with
  `Interface.mtu`. `None` means the destination never answered —
  indistinguishable from "every size was too big".

  | `method` | How |
  | --- | --- |
  | `"icmp"` | DF-flagged echo. Default; works anywhere `ping` does. |
  | `"udp"` | Datagrams of growing size to `port`. Needs something there that replies. Measures what a **UDP application** can actually push, which a middlebox may cap below the ICMP figure. |
  | `"tcp"` | **Does not probe** — TCP is a stream and the kernel segments it, so a large `send()` becomes many packets. Reads the negotiated MSS and adds the header back. |

  Extra `**ping_kwargs` reach `ping` for the ICMP method (`ipv6=`, `tries=`).
  `size` and `dont_fragment` are what the search varies, so passing them raises.
- **`get_tcp_mss(dst, port, timeout=3.0) -> int | None`** — the negotiated TCP
  maximum segment size. Opens a real connection to read it. A reduced value
  signals a tunnel shrinking the path; `None` where `TCP_MAXSEG` is
  unavailable.
- **`get_pmtu(dst, port=80) -> int | None`** — a **lookup**, not a
  measurement: reads the `IP_MTU` the kernel has *already* learned, and sends
  nothing. Usually `None`, because the kernel only knows a path MTU once prior
  traffic forced it to learn one; **always `None` on Windows**, which has no
  `IP_MTU`. `discover_mtu(..., probe=False)` is exactly this.

> **These answer different questions.** On one real host the local link was
> 9000, `get_pmtu` returned `None`, and `discover_mtu` found the true 1500 — a
> bottleneck several hops away that nothing local could reveal. Use
> `Interface.mtu` for the local link, `discover_mtu` for the path.
>
> **Header sizes are family-aware.** IPv4 overhead is 20+8 (ICMP/UDP) or 20+20
> (TCP); IPv6 is 40+8 and 40+20. Assuming IPv4 on a v6 path under-reports by
> exactly 20 bytes.

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
- **The two families identify an adapter differently**, and the spec is
  resolved accordingly: IPv4 by local *address* (`IP_ADD_MEMBERSHIP`,
  `IP_MULTICAST_IF`), IPv6 by interface *index* (`IPV6_JOIN_GROUP`,
  `IPV6_MULTICAST_IF`). An adapter the platform reports **no index** for
  raises for an IPv6 group, because index `0` means "kernel's choice" — the
  default `interface=` was passed to override.

## UDP with arrival interface

**`UdpEndpoint(sock, pktinfo=True)`** — wraps a bound UDP socket so each
datagram reports which interface it arrived on, via `IP_PKTINFO`. Essential for
broadcast protocols, where a wildcard-bound server otherwise cannot tell which
network a request came from.

`recv(bufsize, resolve_interface=True) -> Datagram`, with `.data`, `.sender`,
`.local_address`, `.interface_index` and `.interface`.
`send(data, address, port, src=None)` pins the outgoing interface. `address`
accepts `AddressLike`; `src` the usual loose interface spec (`Interface`,
MAC, adapter name or address).

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

## Command line

Installed by the ``cli`` extra (``pip install netimps[cli]``), which adds
`duho`. **Importing `netimps` never requires it** -- the library half has no
dependency on the CLI half.

```
netimps interfaces                       # names, MACs, MTU, addresses
netimps ping 8.8.8.8 -m tcp -p 443       # icmp | tcp | udp
netimps resolve example.com aaaa
netimps resolve 8.8.8.8                  # no rdtype -> auto ptr -> dns.google
netimps check example.com https          # port or scheme name
netimps route 8.8.8.8 --hops
netimps mtu 8.8.8.8 -m udp -p 9999
netimps scan 192.0.2.0/29 -p common
netimps addr 00:00:5e:00:53:01           # address, network or MAC
netimps source 8.8.8.8                   # which local address reaches it
netimps port https                       # 443; `netimps port` gives a free one
netimps split '[::1]:8080'               # -> ::1  8080
```

- **`--json` on every command**, so output is scriptable. Text output is for
  humans and its exact wording is not a stability guarantee; the JSON shape is.
- **Exit codes are meaningful**: `0` success, `1` "the answer was no"
  (unreachable, closed, no records), `2` a caller error (bad argument, unknown
  scheme). `ping` mirrors `ping(8)`.
- `python -m netimps` is equivalent to the `netimps` console script.

## Constants

- **`HOST_DN`** — `platform.node()`, captured **at import time** (a later
  hostname change is not reflected).
- **`PORT_RANGES`** — `{"well-known", "common", "all"}` port tuples.
- **`APIPA`** (`169.254.0.0/16`), **`LOOPBACK_V4`** (`127.0.0.0/8`),
  **`LOOPBACK_V6`** (`::1/128`), **`LINK_LOCAL_V6`** (`fe80::/10`) — named
  networks, so callers stop spelling the literals out.
