# `netimps` interface discovery — public API header

Header-file-style reference for the interface-discovery names of the `netimps`
package: every public export with its signature, arguments, contract and
gotchas, so it can be used without reading its source. It ships inside the
package and is self-contained; the top header is `netimps/AGENTS.md`.
Development documentation lives with the source at
<https://github.com/jose-pr/netimps>.

This directory (`netimps/_ifaddrs/`) is private and not an import path: every
name below is imported from `netimps`.

## Interface discovery

**`get_interfaces(*, raw=False, cache=False) -> List[Interface]`** — adapter names, MACs, MTU
and **real prefix lengths**, via `ctypes` bindings to `getifaddrs(3)` (POSIX)
and `GetAdaptersAddresses` (Windows). **No third-party dependency**; `ifaddr`
is deliberately not used.

**`Interface`** — normalised identically across platforms, and **hashable**
(`set(get_interfaces())` and dict keys work):

| Attribute | Meaning |
| --- | --- |
| `.name` | human-usable name (`eth0`, `en0`, Windows *friendly* name — never a GUID) |
| `.index` | `if_nametoindex` value, `0` if unknown |
| `.mac` | `MACAddress` or `None`; an all-zero hardware address is reported as `None` |
| `.ips` | every address with its real prefix, as a **tuple** |
| `.ipv4` / `.ipv6` | the split views, **tuples** like `.ips` |
| `.mtu` | link MTU in bytes, or `None` |
| `.primary_ip(ipv6=False, *, loopback_ok=True)` | pick **one** entry from `.ips`, ranked routable → loopback → link-local, or `None` |
| `.is_up` | `bool` or `None`: `IFF_UP` and `IFF_RUNNING` on POSIX, the operational status on Windows; `None` when the system did not say |
| `.is_loopback` | the **kernel's** loopback flag when it was reported, otherwise derived from the addresses |
| `.raw` | `None` unless `raw=True`; a **read-only mapping** of platform-specific leftovers, tuples where the system gave a list |

The constructor raises `TypeError` for a field of the wrong type: `name` is a `str`,
`index` an `int`, `mac` a `MACAddress` or `None`, each of `ips` an
`IPv4Interface`/`IPv6Interface`, `mtu` an `int` or `None`, `is_up` and `is_loopback`
a `bool` or `None`. `repr` is a constructor call that rebuilds an equal value.

- **`is_loopback` is the kernel's answer, and never the name.** `IFF_LOOPBACK`
  on POSIX, `IF_TYPE_SOFTWARE_LOOPBACK` on Windows, captured during
  enumeration — `lo`, `lo0` and `Loopback Pseudo-Interface 1` share no
  spelling, so matching on one is never right. The address heuristic runs
  **only when no flag was reported** (the degraded path, and hand-built
  objects: `Interface(..., is_loopback=None)`), and it is a guess: it needs a loopback address and no routable one,
  so it reports "no loopback interface at all" on a host that binds a routable
  address to `lo` — WSL2 does exactly that with `10.255.255.254/32`, as does
  any keepalived/anycast/VIP setup. Link-local addresses are ignored by it,
  since macOS's `lo0` also carries `fe80::1/64`.
- **`.mac is None` means the same thing everywhere.** Linux reports the
  loopback MAC as `00:00:00:00:00:00` where macOS and Windows report nothing;
  the all-zero address is normalised away.
- **`.raw` is not portable** and sits outside the stability guarantee — the
  escape hatch for adapter GUIDs, `IFF_*` flags, WMI correlation. It is
  read-only, so a cached result shares nothing a caller could change.
- **`is_up` and a down interface.** POSIX keeps the addresses of an interface
  that is down: they are configured and can be bound, and `is_up` is how a caller
  tells. **On Windows an adapter that is down stays listed** with its name, MAC,
  index and MTU, but an address the system marks tentative or duplicate is left
  out of `ips`: a media-disconnected adapter holds a self-assigned `169.254`
  address in the state *Tentative*, which `bind` refuses with `WSAEADDRNOTAVAIL`
  and `ipconfig` does not show. Deprecated and preferred addresses are kept.
- **The Windows `index` is `IfIndex`, or `Ipv6IfIndex` when that is 0** (an
  adapter with IPv4 unbound).
- **BSD netmasks.** macOS trims a netmask sockaddr after its last non-zero
  byte (`255.0.0.0` arrives with `sa_len` 5), so a short one stands for the
  zero-filled mask. The prefix is what `getifaddrs(3)` reports: on FreeBSD 16
  that is `127.0.0.1/8` for `lo0`, a full-length `255.0.0.0`, where `ifconfig`
  there prints `netmask 0x0`.
- **Degrades when the platform will not answer.** An `OSError` from the native
  call gives hostname resolution, where **prefixes are fiction** (every address
  becomes `/32` or `/128` under an interface named `"<unknown>"`, with no flag
  reported, the reason in `raw["reason"]` and logged once at debug). Check
  `iface.name == "<unknown>"` to detect it. Any other exception is a defect in
  the walk and propagates.
- **`clear_interface_cache()` also discards an enumeration already running**: its
  result is not stored, so `get_interfaces(cache=math.inf)` after a clear never
  serves a snapshot that predates it.
- **`primary_ip()` is a selection, not "the" address** — an adapter routinely
  has several. It returns the **same element type as `.ips`** (an
  `ip_interface`, carrying the prefix) and the result *is* one of them; use
  `.ip` for the bare address that socket options take.
- **`primary_ip()` ranks: routable, then loopback, then link-local**, keeping OS
  order within a rank. The rank is the point — an interface commonly lists its
  link-local address *first*, since `fe80::` is configured before SLAAC or
  DHCPv6 completes on Linux and macOS NICs, so "the first entry that is not
  loopback" returned an address useless as a bind target and unreachable
  off-link. LINK_LOCAL_V4 `169.254/16` is the IPv4 twin and ranks below a DHCP lease.

  **Loopback outranks link-local deliberately**: the only interface carrying
  both is the loopback adapter, where `::1` is what every caller means, and a
  real NIC has no loopback entry so the rank takes nothing from it. A NIC
  holding *only* a link-local address still yields it, and `loopback_ok=False`
  skips the loopback rank rather than returning `None`.
- `__eq__` compares name, index, MAC, addresses, MTU and `is_up`, and the hash
  covers exactly those; the loopback flag and `.raw` are deliberately outside both.

**`iter_addresses(interfaces=None, *, family=None)`** — the flattened
`(interface, address)` view, yielded once per address rather than per adapter,
for callers that filter or act per address. The full `Interface` comes along,
so nothing is lost. Pass an existing enumeration in a loop; it is a syscall.

- **`family` is `4` or `AF_INET`, `6` or `AF_INET6`**, the same two spellings
  everywhere a family is taken (`bind`, `get_free_port`, `has_pktinfo`,
  `iter_addresses`). Anything else raises `ValueError` **from the call itself**,
  not from the first `next()`: a generator that validates lazily reports a bad
  argument from a traceback that does not name the caller. `AF_INET6` is 10 on
  Linux, 23 on Windows and 30 on macOS, so compare against the constant, never a
  literal.

## Interface lookups and the enumeration cache

- **The adapter enumeration is cacheable, and it is opt-in**:
  `get_interfaces(cache=...)`, and the same argument on `get_interface`,
  `iter_interfaces` and `is_local_address`. `cache=False` (the default) never
  caches and never reads a cached value, so nothing changes unless asked;
  `cache=True` uses `INTERFACE_CACHE_TTL` (**1 second**); a number is that TTL in
  seconds. `cache=0` is a TTL of zero, so it enumerates and reseeds — which
  is the whole of "force a refresh", and why there is no second argument for it.
  `clear_interface_cache()` invalidates without a lookup.

  Measured with 7 adapters: `get_interface` goes **0.98 ms → 0.010 ms**, and
  `is_local_address` likewise. On a host with many adapters the uncached call
  reaches 35–42 ms, which is slow enough that a packet flood can deny service
  on its own — so this is an availability question, not only a speed one.

  > **Prefer an event to a TTL when you have one.** A TTL is a guess about how
  > long the answer stays true. If your program already knows the moment it can
  > change — it binds a socket, or handles a netlink / `WM_NETWORKCHANGE` event
  > — then `cache=math.inf` plus `clear_interface_cache()` at that moment is
  > strictly better: no window of wrong answers, and no re-enumeration while
  > nothing has changed. The 1 s default is sized to collapse a *burst* of
  > calls rather than to hold a snapshot, bounding the cost at one syscall per
  > second whatever the arrival rate.

  **`interface_enumerations() -> int`** counts the real enumerations this
  process has done — the syscall, never a cached hit, which is the number worth
  watching once a lookup and an enumeration stop being the same event. Useful
  as a metric (how often is this host re-reading its adapters?) and as the
  assertion a test wants: `before = interface_enumerations()`, do the work,
  expect `+1`. Both `raw` flags count into the one total, and the cache is keyed
  by `raw`, so a process using both warms up twice.
  `clear_interface_cache()` does not advance it — dropping a cache enumerates
  nothing by itself.

  A **cached call returns the stored `Interface` objects in a fresh list.**
  An `Interface` cannot change after construction and `.ips` is a tuple, so
  one caller cannot corrupt another's view. Only `.raw`, a dict, is copied.

- **`get_interface(query=None, *, index=None, strict=True, cache=False) -> Interface | None`** — first matching
  adapter in OS enumeration order. `query` accepts an `Interface`, exact
  `IPAddress`, exact `.ip` from an `IPInterface`, an `IPNetwork` containing at
  least one assigned address, an exact `MACAddress`, or **an adapter name**
  (text that is no address, network or MAC): `get_interface(iface.name)` and
  `get_interface(index=iface.index)` return `iface`, the two keys the library
  hands out. Pass a `query` or `index=`, not both and not neither (`TypeError`);
  `index=` is a positive `int` (`ValueError` otherwise), and an `int` *query* stays
  an address. A `%zone` on an address is a filter: it must name the adapter that
  holds the address (the index on Linux and Windows, the name on the BSDs), and
  `interface_index` and `interface_address` apply the same rule, so
  `::1%nosuchadapter` and `::1%999` name no interface and a strict lookup of
  them raises. Address-like strings,
  integers and packed bytes remain accepted; a slash-bearing string is a
  network. MAC text and 6-byte packed values are recognised after IP parsing.
  Integer MACs must be wrapped in `MACAddress` because integers are also valid
  IP-address inputs. Invalid input and misses return `None`. With
  `strict=False`, only an address or `IPInterface` miss synthesizes a host-route
  interface named `"<unknown>"`; networks and MACs have no honest synthetic
  result.
- **`iter_interfaces(query=None, *, index=None, cache=False) -> Iterator[Interface]`** — every match for the same
  query forms (names and `index=` included), in OS order and with each adapter yielded once even if several
  assigned addresses match. An `Interface` yields itself without enumeration.
  Addresses need not be unique across adapters (unscoped IPv6 link-local is a
  common example), so use this plural form when every owner matters.
- **`is_local_address(address, *, cache=False) -> bool`** — true only for loopback or an
  address assigned to a local adapter. Private, link-local, on-link, routable
  or reachable alone do not count. Text that is no address raises
  `NetimpsValueError`; loopback answers before interface discovery.
- **`is_local_host(host, *, resolve=False, cache=False) -> bool`** — whether a
  host string names this machine. True for a literal `is_local_address` accepts
  (zone ignored, v4-mapped judged as v4, and the short and numeric spellings
  `inet_aton` reads, such as `127.1` and `2130706433`), for `localhost` and `*.localhost`, and
  for this machine's own host name (case and trailing dot ignored); a `:port` or
  brackets are accepted and ignored. **A name is not resolved unless
  `resolve=True`**, which asks the OS resolver and is true when any address it
  returns is local (and also accepts this machine's fully qualified name); that
  can block on the network. Never raises: a value that is not a host is `False`.
- **A `%zone` suffix is honoured by all three of the above**, not rejected.
  `ipaddress` keeps the zone as part of the address, so `fe80::1%15` matched
  nothing in enumeration and the library denied that an address it had just
  reported was local. The bare address is matched and the zone is used for
  what it is — a name for the adapter, the **index** on Linux/Windows and the
  adapter **name** on BSD. A zone naming an adapter that does not hold the
  address is a miss, the honest answer to a contradiction. That form is what
  `getsockname()` and `getaddrinfo` hand back, so it can be passed straight in.

## Broadcast and unicast

**`is_broadcast(address: IPAddressLike, interface: Interface | None = None, *, cache=False)`** — whether *address* is an IPv4
broadcast, limited **or** subnet. What a wildcard-bound server asks about
`Datagram.destination` before answering: RFC 1123 says a TFTP server ignores a
broadcast request, and DHCP must tell a broadcast DISCOVER from a unicast RENEW.

- `255.255.255.255` needs no context, and short-circuits before any lookup. The
  **subnet** broadcast does — `10.0.0.255` is only a broadcast if some interface
  carries `10.0.0.0/24` — so this consults interface prefixes, which is why it
  lives beside interface enumeration.
- **Pass `interface` (from `Datagram.interface`) whenever you have it**: it
  checks one adapter and skips the enumeration entirely, measured at
  **0.004 ms against 1.25 ms**. A server asking this of every request otherwise
  pays a full enumeration per packet. `cache=` is the fallback for when the
  interface is genuinely unknown — the arrival index did not resolve — and means
  what it means on `get_interfaces`.
- A **v4-mapped** address is unmapped first, since a dual-stack listener reports
  an IPv4 arrival as `::ffff:a.b.c.d`.
- **IPv6 has no broadcast** — it uses multicast — so a genuine v6 address is
  always `False`. `is_multicast` is the companion, kept separate on purpose: "do
  not answer this" is usually the `or` of the two, and one name meaning both would
  hide which matched.
- Raises `NetimpsValueError` for text that is no address.
- A `/31` or `/32` is skipped: it has no broadcast address distinct from its
  hosts, though `broadcast_address` still answers for one.

**`is_unicast(address: IPAddressLike, interface: Interface | None = None, *, cache=False) -> bool`**
— whether a datagram sent to *address* was meant for one host: `False` for the
wildcard (`0.0.0.0`, `::`), a multicast group and a broadcast (limited or
subnet), `True` otherwise. The "answer it or ignore it" test a DHCP or TFTP
server runs on `Datagram.destination`, in place of `is_broadcast` and
`is_multicast` plus a wildcard test. `interface` and `cache` mean what they do
on `is_broadcast`, the only part that can enumerate. A v4-mapped address is
judged as the v4 address inside; a `%zone` is ignored; text that is no address
raises `NetimpsValueError`.
