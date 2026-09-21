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

`netimps.__version__` — the package version string, the same value the
installed distribution's metadata carries.

## Argument naming

The package is consistent about what the first argument means:

| Name | Meaning | Examples |
| --- | --- | --- |
| `dst` | where traffic is **sent** | `ping`, `tcp_check`, `wait_for_port`, `get_route`, `hop_count`, `discover_mtu`, `get_tcp_mss`, `get_pmtu`, `scan_ports(host)` |
| `src` | where traffic is **sent from** | `ping(src=)`, `get_free_port(src=)`, `discover_mtu(src=)`, `UdpEndpoint.send(src=)` |
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

**Every `port` a network helper takes is validated** before a socket sees it:
`tcp_check`, `wait_for_port`, `scan_ports`, `scan_hosts`, `get_pmtu`,
`discover_mtu`, `get_tcp_mss` and `register_port` raise `ValueError` outside
`0-65535` and `TypeError` for a non-`int` — including `bool`, and including a
service-name string such as `"http"`, which must go through
`get_default_port` first. The socket layer would otherwise mask the value to
16 bits, so `port + 65536` silently answered about `port`. The two *table*
lookups, `get_default_port`/`get_default_scheme`, still return `None` instead:
"no such entry" is the honest answer from a lookup, not an error.

**Several parameters are named `ipv6=`** and mean one thing throughout --
`True` IPv6, `False` IPv4, `None` (the default) whichever the resolver
answers with: `get_ip`, `get_source_ip`, `get_route`, `hop_count`, `get_pmtu`,
`ping`, and `discover_mtu` via `**ping_kwargs`. A literal `dst` decides for
itself.

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
| `IPAddressLike` | `str \| int \| bytes \| IPv4Address \| IPv6Address` -- accepted *as input* for an address |
| `IPInterfaceLike` | anything accepted *as input* for an address + prefix |
| `IPNetworkLike` | anything accepted *as input* for a network |
| `AddressLike` | `str \| IPv4Address \| IPv6Address \| IPv4Interface \| IPv6Interface` -- any `dst`-typed parameter |
| `MACLike` | `str \| int \| bytes \| bytearray \| MACAddress` |

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
(`AA:BB:CC:DD:EE:FF`), hyphen (`AA-BB-CC-DD-EE-FF`), dot per octet
(`aa.bb.cc.dd.ee.ff`), dot/Cisco triplets (`aabb.ccdd.eeff`) or bare
(`AABBCCDDEEFF`) text, a 48-bit `int`, 6 raw `bytes` or `bytearray`, or another
`MACAddress`.

Normalised to lowercase, compared and hashed by canonical bytes, so it is
**hashable** — usable as a dict key and a set member — and two values differing
only in the case or separator they were parsed from are equal.

| Member | Meaning |
| --- | --- |
| `.as_str(sep=":", upper=False)` | render with any separator; `sep=""` for bare form |
| `.packed` | the 6 raw bytes |
| `.oui` | the first three octets, **verbatim** (see below) |
| `.is_multicast` | group bit (low bit of octet 0) |
| `.is_local` / `.is_universal` | the U/L bit |
| `int(mac)`, `str(mac)` | integer / colon form |
| `<`, `<=`, `>`, `>=` | ordering against another `MACAddress`, so MACs sort |
| `MACAddress.is_valid(v)` / `.try_parse(v)` | classmethods; the type-local spelling |

- **Equality holds only against another `MACAddress`.**
  `mac == "aa:bb:cc:dd:ee:ff"` is `False`, in both directions, and
  `mac != text` is `True`. Parse the text first:
  `MACAddress.try_parse(text) == mac`. Coercing a `str` here cannot be made
  lawful — every spelling of one address would compare equal, while
  `str.__hash__`, which is not this package's to change, hashes each spelling
  differently, so `mac == text` and `mac in {text}` would disagree. Dropping
  the coercion is what makes `mac in {MACAddress(...)}` and
  `{mac: v}[MACAddress(other_spelling)]` work. Ordering is `MACAddress`-only
  too; `mac < text` raises `TypeError`.
- **Separators may not be mixed.** `MACAddress("00-11:22-33:44-55")` raises
  `ValueError`; each accepted form must be used consistently.
- **A `bool` is rejected** with `TypeError`, despite being an `int` subclass —
  `MACAddress(True)` would otherwise be `00:00:00:00:00:01`. `is_valid(True)`
  is `False` and `try_parse(True)` is `None`.
- **`.oui` keeps the flag bits.** The I/G (group) and U/L (locally
  administered) flags live in the low two bits of octet 0 and are *not* masked
  out, so for a multicast or locally administered address this is **not** a
  registered IEEE OUI: `MACAddress("01:00:5e:00:00:01").oui` is `01:00:5e`
  where the registered assignment is `00:00:5e`. Mask before a registry
  lookup: `bytes([mac.oui[0] & 0xFC]) + mac.oui[1:]`. The bits are kept
  because this is the prefix as it appears on the wire; `.is_multicast` and
  `.is_local` say when the masked form would differ.
- **`MACAddress.is_valid` returns a plain `bool` and does not narrow** its
  argument, matching the module-level `is_valid`: a `TypeGuard` here would let
  a checker certify `.packed` on something that is still a `str`. Use
  `try_parse` when you want the object.
- **Not a `bytes` subclass** — deliberately, matching how `ipaddress` models
  addresses. Use `.packed` at wire boundaries.
- Case is presentational only: `upper=True` never affects equality or hashing.
  `as_str(".")` emits `aa.bb.cc.dd.ee.ff` (one dot per octet) and round-trips
  through the constructor; the Cisco triplet form is accepted on input and
  never produced. `":"`, `"-"`, `"."` and `""` all round-trip; any other
  separator renders but does not.
- `.is_local` means *locally administered* (VMs, containers, MAC randomisation),
  so such addresses are **not stable identifiers**.
- The classmethods are `classmethod`, not `staticmethod`, so a subclass
  validates against itself.

## Interface discovery

**`get_interfaces(raw=False) -> List[Interface]`** — adapter names, MACs, MTU
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
| `.ips` | every address with its real prefix |
| `.ipv4` / `.ipv6` | the split views |
| `.mtu` | link MTU in bytes, or `None` |
| `.loopback` | the **kernel's** loopback flag, or `None` when it was not reported |
| `.primary_ip(ipv6=False, loopback_ok=True)` | pick **one** entry from `.ips` (non-loopback preferred), or `None` |
| `.is_loopback` | `.loopback` when known, otherwise derived from the addresses |
| `.raw` | `None` unless `raw=True`; platform-specific leftovers |

- **`is_loopback` is the kernel's answer, and never the name.** `IFF_LOOPBACK`
  on POSIX, `IF_TYPE_SOFTWARE_LOOPBACK` on Windows, captured into `.loopback`
  during enumeration — `lo`, `lo0` and `Loopback Pseudo-Interface 1` share no
  spelling, so matching on one is never right. The address heuristic runs
  **only when `.loopback` is `None`** (the degraded path, and hand-built
  objects), and it is a guess: it needs a loopback address and no routable one,
  so it reports "no loopback interface at all" on a host that binds a routable
  address to `lo` — WSL2 does exactly that with `10.255.255.254/32`, as does
  any keepalived/anycast/VIP setup. Link-local addresses are ignored by it,
  since macOS's `lo0` also carries `fe80::1/64`.
- **`.mac is None` means the same thing everywhere.** Linux reports the
  loopback MAC as `00:00:00:00:00:00` where macOS and Windows report nothing;
  the all-zero address is normalised away.
- **`.raw` is not portable** and sits outside the stability guarantee — the
  escape hatch for adapter GUIDs, `IFF_*` flags, WMI correlation.
- **Never raises for enumeration failure.** If the native call is unavailable it
  degrades to hostname resolution, where **prefixes are fiction** (every address
  becomes `/32` or `/128` under an interface named `"<unknown>"`, with
  `.loopback` unset). Check `iface.name == "<unknown>"` to detect it.
- **`primary_ip()` is a selection, not "the" address** — an adapter routinely
  has several. It returns the **same element type as `.ips`** (an
  `ip_interface`, carrying the prefix) and the result *is* one of them; use
  `.ip` for the bare address that socket options take.
- `__eq__` compares name, index, MAC, addresses and MTU, and the hash covers
  exactly those; `.loopback` and `.raw` are deliberately outside both.

**`iter_addresses(interfaces=None, family=None)`** — the flattened
`(interface, address)` view, yielded once per address rather than per adapter,
for consumers that filter or act per address. The full `Interface` comes along,
so nothing is lost. Pass an existing enumeration in a loop; it is a syscall.

- **`family` is the short form, `4` or `6`** — *not* `socket.AF_INET`/
  `AF_INET6`, which `bind` and `get_free_port` take. Anything else raises
  `ValueError` **from the call itself**, not from the first `next()`: a
  generator that validates lazily reports a bad argument from a traceback that
  no longer names the caller. Passing an `AF_*` constant says so in the message.

## Address and network helpers

- **`get_ip(address, ipv6=None) -> IPAddress | None`** — literal *or hostname*
  to an address. **May block on DNS**, unlike `try_parse`, which never touches
  the network. The lookup goes through `getaddrinfo`, **not** the IPv4-only
  `gethostbyname`, so `ipv6=True` really reaches an AAAA-only name — one that
  used to resolve to `None` here and read as "no such host". A literal of the
  "wrong" family is returned as-is: `ipv6` selects among a *name's* records,
  and no lookup happens for a literal.
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
  address may carry a port; brackets are stripped from the returned host and a
  scope id is preserved (`"[fe80::1%eth0]:80"` → `("fe80::1%eth0", 80)`).

  Raises `ValueError` for empty input, an unclosed bracket, a port that is not
  an integer in `0-65535`, and — this one is new — **an unbracketed string with
  two or more colons that is not a valid IPv6 address**. `"host:80:extra"` and
  a half-typed address used to come back whole as the *host*, so the caller
  looked up a name that cannot exist instead of being told what was wrong.

## Scheme ↔ port registry

- **`get_default_port(scheme) -> int | None`** — built-in table (30 entries,
  including the socks variants and the `ws`/`wss` websocket schemes, all absent
  from `/etc/services`), then `getservbyname`. Case-insensitive.
- **`get_default_scheme(port) -> str | None`** — the inverse, then
  `getservbyport`. An out-of-range `port` is `None` rather than an error: this
  is a table lookup, not a socket operation.
- **`register_port(scheme, port, canonical=False)`** — extend or override.
  Raises `ValueError` for an empty scheme or a port outside `0-65535` (the
  range is named in the message) and `TypeError` for a non-`int` port.

Where several schemes share a port the **canonical** one is returned (1080 →
`socks`, not `socks4`/`socks5`; 80 → `http`, not `ws`; 443 → `https`, not
`wss`). Registering an alias does not steal that slot unless `canonical=True`.

- **The services database is asked for TCP first, then UDP.** A protocol-less
  `getservbyname`/`getservbyport` picks per platform, so port 514 answered
  `shell`/`cmd` on one host and `syslog` on another. The TCP entry now wins
  everywhere, and the answers are identical across platforms; nothing in the
  built-in table changes.
- **Re-registering a scheme *moves* it.** After `register_port("myproto", 8888)`
  an earlier `register_port("myproto", 9999)` no longer maps `9999` back to
  `myproto` — the registry would otherwise state both facts at once. If another
  scheme still claims the vacated port it inherits the slot (earliest
  registration first, the same rule the initial index uses).

## DNS

Three independently callable backends, plus `resolve()`, which chains them.
All four share one contract: a `list`, **empty on any genuine lookup
failure** (NXDOMAIN, NODATA, timeout) — never `None` — with **native
types**: `A`/`AAAA` records are `ipaddress` objects, everything else is
`str` (trailing root dot stripped, TXT strings unquoted).

**`ResolutionError(Exception)`** — a backend could not even *attempt* the
query: a missing `nslookup` binary, `dnspython` not installed, an `rdtype` the
backend structurally cannot serve, a timeout, a transport failure. It is
deliberately **not** how "no such record" is reported — that is `[]`. It is
the documented raised type of `resolve`, `resolve_system` and
`resolve_nslookup`, and it is exported from `netimps`, so catching it no
longer means importing a private module.

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

Backends are tried in order, default `["dnspython", "system", "nslookup"]`:
dnspython first (structured records, every `rdtype`, explicit `ns=`/`search=`
control), then the OS resolver (hosts file, NSS, OS cache), then `nslookup` as
a last resort. `backends` also accepts a single name as a plain string
(`backends="system"`), or a custom order/subset
(`backends=["nslookup", "dnspython"]`).

- **Only a non-empty answer stops the chain.** An empty one does **not**, and
  that is the point: the backends resolve by structurally *different*
  mechanisms, so DNS's "no such name" says nothing about what the OS resolver
  can still answer. `dnspython` gets NXDOMAIN for `localhost` on Windows and
  macOS while `resolve_system` answers it from the hosts file; the same holds
  for `.local`/mDNS names and anything else only an NSS source knows.
- A backend that could not even attempt the query (a `ResolutionError`:
  missing binary, `dnspython` absent, timeout, transport failure) falls
  through the same way; one that structurally cannot serve the request is
  skipped without being called at all.
- The result is `[]` when **every applicable backend answered empty**. If
  every one of them failed to attempt instead, the last such error is raised.
  If the chain holds no backend that could even be tried, `ValueError` names
  what excluded them.

**The cost is latency on a genuinely non-existent name:** two or three backend
calls instead of one, the last of which may spawn `nslookup`. Narrow
`backends` to opt out — `backends="dnspython"` restores the single call.

- **`system` is skipped automatically** for a `rdtype` outside
  `"a"`/`"aaaa"`/`"ptr"`, and for an explicit `ns=`, a `port=` other than 53,
  or `tcp=True` — the OS resolver takes no per-call nameserver, port or
  transport, so running it would answer a different question from the one
  asked. With `backends=["system"]` plus one of those, the resulting
  `ValueError` names the reason.
- **`nslookup` is skipped** only for a `rdtype` outside `"a"`/`"aaaa"`/`"ptr"`.
  It has no `port=`/`tcp=` parameters, so a `resolve(q, port=5353)` that falls
  through to it is answered against port 53 over UDP — a known gap; pin
  `backends="dnspython"` when the port or transport matters.
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
- **`timeout` bounds wall time, per candidate name tried — `"ptr"` included.**
  Neither `getaddrinfo` nor `gethostbyaddr` has a timeout of its own, so each
  attempt runs in a daemon helper thread that is abandoned at the deadline,
  raising `ResolutionError`; the underlying call is not cancelled, but neither
  the caller nor interpreter exit waits for it. A broken resolver therefore
  costs `timeout`, not however long it takes to give up — which is also what
  lets `resolve()`'s chain reach `nslookup` on schedule. The reverse path used
  to ignore `timeout` outright: measured 4.6s against a 0.1s deadline.

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
  literal name only — if not). `timeout` bounds **each** subprocess attempt.
- **Raises `ValueError` before any subprocess is spawned** for a `query` that
  starts with `-`, is empty or whitespace-only, or contains whitespace or
  control characters. `nslookup` has **no `--` end-of-options separator**, so
  such a query cannot be escaped into position: the binary reads it as an
  option, finds no name argument, and drops into *interactive* mode — where it
  reads names to look up from **stdin**. Measured: that drained the calling
  program's stdin and sent each line to the configured nameserver as a query.
- **The subprocess is given `stdin=DEVNULL`**, so it can never read the
  caller's stdin whatever else happens.
- Raises `ResolutionError` (not `ValueError`) for a missing binary, a
  timeout, an unparseable output shape, or **a non-zero exit carrying none of
  the "no such name" markers** (no reachable server, a refused connection).
  That last case used to return `[]`, which made a transport failure look like
  NXDOMAIN and stopped `resolve()`'s chain. A genuine "no such name" — exit 1
  *with* the marker text — is still `[]`.

## Reachability

**`ping(dst, tries=1, timeout=1.0, ipv6=None, src=None, size=None, ttl=None, dont_fragment=False, method="icmp", port=None) -> PingResult`**

`PingResult` is **truthy on success** and compares equal to `bool`, so
`if ping(host):` and `== True` keep working, while carrying `.ok`, `.host`,
`.rtt_ms`, `.ttl`, `.src`, `.attempts`.

| Argument | Notes |
| --- | --- |
| `dst` | `AddressLike` (hostname, address string, address object, or `IPv4Interface`/`IPv6Interface` -- its `.ip` is pinged). `ping(get_interfaces()[0].ipv4[0])` works directly. |
| `src` | `Interface`, address, **MAC**, adapter name or string. A MAC is resolved to the adapter holding it. Applies to `tcp`/`udp` as well as ICMP. |
| `size` | ICMP payload bytes. The wire packet is larger by the IP header plus 8: **28 bytes for IPv4**, 48 for IPv6. |
| `ttl` | initial hop limit. The flag letter differs per platform (below); applies to `tcp`/`udp` too. |
| `dont_fragment` | DF bit — Windows `-f`, Linux `-M do`, BSD `-D`. With `size`, the manual MTU probe: largest passing `size` + 28 = IPv4 path MTU. |
| `method` | `"icmp"` (default), `"tcp"` or `"udp"`. The latter two reach hosts through firewalls that drop echo. |
| `port` | required for `tcp`/`udp`, ignored for ICMP. |

**All three methods ask "is the *host* up?"** — so a TCP refusal counts as
success (the RST proves something answered), as does an ICMP port-unreachable
for UDP. Use `tcp_check` for "is the *service* up?", where a refusal is a
failure. `tcp` and `udp` also report `rtt_ms`; only ICMP reports `ttl`.

- **The flags are three grammars, not two.** Of the six this emits, *five*
  differ on BSD/macOS: `-W` is milliseconds there rather than seconds, `-t` is
  an overall deadline rather than the TTL, `-I` is *rejected* for a unicast
  destination (`-S` is the source flag), DF is `-D` rather than `-M do`, and
  `-4`/`-6` do not exist at all — **IPv6 goes through a separate `ping6`
  binary**. Anything that is neither Windows nor Linux is treated as BSD,
  which is the safer default for Solaris/AIX: a flag not emitted is a missing
  feature, while a flag meaning something else is a wrong answer.
- **`ttl=` does not map to one flag.** It is `-i` on Windows, `-t` on Linux,
  `-m` on BSD `ping` and `-h` on BSD `ping6`. What *is* identical everywhere is
  the **result**: a `ttl` too small to reach the target is falsy. That takes
  explicit work on Windows, whose `ping` exits `0` for "TTL expired in
  transit"; the reply address is verified instead of the exit code, matching on
  addresses and never on localised prose.
- **`dont_fragment` is refused, never ignored,** where it cannot be set. BSD
  `ping` has `-D`; its `ping6` has no verified DF flag, and that one
  combination raises `ValueError` rather than sending fragmentable probes that
  would make every size "survive". It also raises for `method="tcp"`/`"udp"`,
  which build no probe packet of their own.
- **`ipv6=` applies to all three methods**, not just the ICMP binary: it picks
  the `-6`/`-4` flag (the `ping6` binary on BSD), the family the reply address
  is resolved in, and the family the `tcp`/`udp` probe sockets use.
  `ipv6=None` accepts either. A hostname with several addresses counts as
  answered if the reply came from any of them.
- **The `udp` probe connects its socket before sending**, which is why the ICMP
  port-unreachable is seen on POSIX and not only on Windows — an unconnected
  UDP socket is never delivered an asynchronous ICMP error on Linux/BSD.
  `ECONNREFUSED` and `ECONNRESET` both count as "the host answered".
- **`rtt_ms` is `0.0` for a sub-millisecond reply.** Windows prints `time<1ms`,
  an upper bound rather than a measurement — reading the `1` would over-report
  by up to 100%. `0.0` is falsy, so test `rtt_ms is None` for "not reported".
- **Reply lines are matched by address token, and the punctuation differs.**
  Windows writes `Reply from 127.0.0.1:`, Linux `64 bytes from 127.0.0.1:`,
  BSD `ping6` `16 bytes from ::1,` — a colon-only needle never matched the
  last, so a healthy v6 reply on macOS verified as falsy.
- An unusable `src` (unknown MAC, adapter with no address, foreign address)
  gives a falsy result — it **never silently falls back** to the default route.
- **Reachability failures never raise; caller mistakes always do.** A missing
  binary, a hung subprocess, a non-zero exit and an empty `dst` are all falsy.
  `ValueError` is raised for an unknown `method`, a negative `size`, a `ttl`
  outside `1-255`, a `tcp`/`udp` probe with no `port`, a `dont_fragment` that
  cannot be honoured, and a `dst` beginning with `-` — the binary reads that as
  an option, and Windows `ping -?` prints usage and **exits 0**, which used to
  be reported as a successful ping of a host never contacted.
- `PingResult` is **hashable**, over `(ok, host, rtt_ms, ttl)`. One asymmetry
  to know about: it compares equal to a `bool` but does not hash like one, so
  `result == True` is `True` while `{True: x}[result]` raises `KeyError`.
- **ICMP echo is not "is the host up"** — most cloud firewalls drop it. Prefer
  `tcp_check`.

## Socket helpers

- **`bind(address="", port=0, *, family=AF_INET, kind=SOCK_DGRAM, reuse_address=True, allow_address_takeover=False, reuse_port=False, broadcast=False, interface=None, options=(), listen=None)`**
  — create, configure and bind in one call. `interface` accepts the usual union
  (`Interface`, MAC, adapter name, address) and **raises `ValueError`** if
  unresolvable rather than silently binding the wildcard. `reuse_port` is a
  **no-op where `SO_REUSEPORT` does not exist** (Windows), not an error;
  `listen` is ignored for datagram sockets. The socket is closed before any
  exception propagates, so a failed call leaks nothing. A failed bind raises
  `OSError` — see `bind_error_hint`.

  > **`reuse_address=True` is not one socket option.** On POSIX it sets
  > `SO_REUSEADDR`, which only permits binding an address still in
  > `TIME_WAIT`; two live sockets still cannot hold one `addr:port`. On
  > **Windows** `SO_REUSEADDR` means something else entirely: it lets **any
  > process** bind an `addr:port` another socket is already listening on, and
  > the later binder can win subsequent connections — reproduced on Windows 11,
  > where a plain second bind was refused with `EACCES` while one through this
  > function succeeded. So on Windows `reuse_address=True` sets
  > **`SO_EXCLUSIVEADDRUSE`** instead, the safe request with the same intent
  > and what a plain stdlib bind gets by default. The literal option remains
  > reachable, but only by asking for it by its consequence:
  > `allow_address_takeover=True`. On POSIX that flag adds nothing, since
  > `reuse_address` already sets exactly that option.
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
- **A `%zone` suffix is honoured by all three of the above**, not rejected.
  `ipaddress` keeps the zone as part of the address, so `fe80::1%15` matched
  nothing in enumeration and the library denied that an address it had just
  reported was local. The bare address is matched and the zone is used for
  what it is — a name for the adapter, the **index** on Linux/Windows and the
  adapter **name** on BSD. A zone naming an adapter that does not hold the
  address is a miss, the honest answer to a contradiction. That form is what
  `getsockname()` and `getaddrinfo` hand back, so it can be passed straight in.
- **`get_source_ip(dst="8.8.8.8", port=80, ipv6=None) -> IPAddress | None`** —
  which local address the kernel would use to reach `dst`. `dst` accepts
  `AddressLike`. **Sends no packets** — `connect()` on a UDP socket only
  consults the routing table. The answer depends on `dst`: with a VPN up, a
  public probe returns the tunnel address and a LAN probe the physical one.
  Correct where hostname resolution picks a VM adapter. `ipv6=` selects the
  family; it used to be guessed with `":" in dst`, and **a hostname never
  contains a colon**, so every name was probed as IPv4 and a v6-only one
  answered `None`. The returned address carries **no `%zone`** — the zone
  identifies the adapter, and `interface_for` is the way back to it.
- **`get_free_port(src="127.0.0.1", family=AF_INET) -> int`** — bind port 0 and
  read it back. **Inherently racy** — the port frees the instant it returns; if
  you can, bind port 0 in the server itself instead. `SO_REUSEADDR` is
  deliberately *not* set (it would hand back a `TIME_WAIT` port).
- **`tcp_check(dst, port, timeout=3.0) -> bool`** — the honest reachability
  test. Proves the handshake completed, not that the service is healthy; a
  filtered port is indistinguishable from a closed one.

  Never raises for a reachability *outcome* — refused, timed out, unresolvable
  and unreachable are all `False` — but two argument bugs are raised rather
  than answered: a network as `dst` (`TypeError`), and a `port` outside
  `0-65535` (`ValueError`) or not an `int` (`TypeError`).

  **`timeout` bounds the whole call**, across every address `dst` resolves to.
  It used to be handed to `socket.create_connection`, which applies it once
  *per resolved address* after an unbounded `getaddrinfo`, so a name with N
  addresses could take N × `timeout`. `timeout=0` is **floored** to 0.05s
  rather than taken literally: `settimeout(0)` means non-blocking, which
  reported every open port as closed. `timeout=None` blocks.
- **`wait_for_port(dst, port, timeout=30.0, interval=0.1, connect_timeout=None)`**
  — poll until it answers. Backs off to 1s. The overall deadline is honoured
  even when individual connects block — it cannot overrun by more than one
  attempt, which became true only once `tcp_check` started bounding *itself*
  overall rather than per resolved address. `connect_timeout` defaults to
  `interval` raised to at least 1s. An out-of-range `port` raises from
  `tcp_check`.

## Routing, hops and MTU

- **`get_route(dst="8.8.8.8", ipv6=None) -> Route`** — `.dst`, `.src`,
  `.gateway`, `.interface_index`, `.on_link`. **First hop only, deliberately**
  — that is available unprivileged everywhere, unlike the full path. Never
  raises for an unknown route; unknown pieces are `None`/`0`. A network as
  `dst` still raises `TypeError`. A hostname goes through `getaddrinfo`, so
  `ipv6=` selects which of its records the route is computed for — the
  IPv4-only `gethostbyname` used before meant an AAAA-only name reached no
  lookup at all.

  Both families are looked up on every supported platform: `GetBestRoute2` on
  Windows (it asks the kernel which route *it* would pick, so the
  longest-prefix matching is not reimplemented), `/proc/net/route` and
  `/proc/net/ipv6_route` on Linux, and `route -n get` on macOS/BSD — the one
  platform where this spawns a short-lived process (`stdin=DEVNULL`, 5s cap),
  because there is no `/proc` to read. Loopback short-circuits without
  spawning anything.

  > **`Route.on_link` is `Optional[bool]`**: `True` when no gateway is needed,
  > `False` when one is, and **`None` when the next hop could not be looked up
  > at all**. It used to be `gateway is None`, which turned "we never looked"
  > into a confident `True` — on macOS, where the lookup had no source to read,
  > `get_route("1.1.1.1")` reported `on_link=True` from a `192.168.64.3/24`
  > host. `None` is falsy, so `if route.on_link:` still takes the safe branch;
  > `route.on_link is True` is now a question with an answer, and
  > `route.on_link is False` really means "through a router". A present
  > `gateway` wins over the recorded flag, since it is proof on its own.
  >
  > **Test `on_link` itself** — there is no `.gateway is None` workaround to
  > write any more, and that spelling was exactly the confusion. `Route` is
  > **hashable**, and `__eq__` compares `dst`, `src`, `gateway`,
  > `interface_index` and `on_link`.
- **`hop_count(dst, max_hops=30, timeout=1.0, allow_traceroute=True, ipv6=None)`**
  — uses raw-socket probes when permitted, otherwise drives the system
  `traceroute`/`tracert`, so it **works unprivileged**. Only the hop number and
  destination address are parsed, never localised prose.
  `allow_traceroute=False` requires the in-process path and raises
  `PermissionError` instead. `ipv6=` picks the family and the probes follow
  (ICMPv6 with `IPV6_UNICAST_HOPS`, and the platform's v6 traceroute); the
  IPv4-only lookup used before returned `None` for a v6 destination, read as
  "never answered" rather than "never asked". **`None` means "no answer", never
  "unreachable"** — firewalls routinely drop ICMP even for an elevated process.
- **`discover_mtu(dst, low=576, high=9000, timeout=1.0, src=None, port=80, probe=True, method="icmp", **ping_kwargs)`**
  — **measures** the path MTU by binary-searching probes, so packets really
  traverse the path. Returns the MTU **including headers**, comparable with
  `Interface.mtu`.

  | `method` | How |
  | --- | --- |
  | `"icmp"` | DF-flagged echo. Default; works anywhere `ping` does. |
  | `"udp"` | Datagrams of growing size to `port`, with DF set per platform (`IP_MTU_DISCOVER` on Linux, `IP_DONTFRAGMENT` on Windows, `IP_DONTFRAG` on BSD, plus the `IPV6_` counterparts). Needs something there that replies. Measures what a **UDP application** can actually push, which a middlebox may cap below the ICMP figure. |
  | `"tcp"` | **Does not probe** — TCP is a stream and the kernel segments it, so a large `send()` becomes many packets. Reads the negotiated MSS and adds the header back (40 for IPv4, 60 for IPv6). |

  **`None` has two meanings, both deliberate.** Either the destination never
  answered — indistinguishable from "every size was too big", and common since
  most cloud firewalls drop echo — **or the don't-fragment bit could not be
  set** for this destination on this platform (BSD's `ping6`, and any kernel
  that refuses the DF option on the `udp` path). Without DF the probe is
  fragmented and reassembled, every size survives, and the search would return
  `high` as though it had measured something.

  Extra `**ping_kwargs` reach `ping` for the ICMP method (`ipv6=`, `tries=`);
  the `udp` method reads only `ipv6=` from them. `size` and `dont_fragment` are
  what the search varies, so passing either raises `TypeError`. `probe=False`
  skips probing entirely and returns `get_pmtu` instead.
- **`get_tcp_mss(dst, port, timeout=3.0) -> int | None`** — the negotiated TCP
  maximum segment size. **Opens a real connection** to read it, then closes.
  MSS is normally the path MTU minus 40, so a reduced value signals a tunnel
  shrinking the path (measured: 1412 over a VPN on a 1500-MTU link, 32741 on
  loopback). `None` where `TCP_MAXSEG` is unavailable or the connection fails.
  This is what the two *kernels agreed*, not what a middlebox further along
  will pass.
- **`get_pmtu(dst, port=80, ipv6=None) -> int | None`** — a **lookup**, not a
  measurement: reads the path MTU the kernel has *already* learned, and sends
  nothing. `discover_mtu(..., probe=False)` is exactly this.

  - **Linux answers for both families**, via `IP_MTU` and `IPV6_PATHMTU`
    (measured: 65535 for `127.0.0.1`, 65536 for `::1`). It is still a weaker
    question than `discover_mtu`: the kernel only knows a path MTU once its own
    discovery has learned one, so `None` remains a common answer for a fresh
    destination, and a value it does have may be the **local link** MTU rather
    than the path minimum.
  - **Windows always returns `None`**, and there is no other route to the
    answer. It has no `IP_MTU`, `IP_MTU_DISCOVER` or `IPV6_PATHMTU`;
    `MIB_IPFORWARDROW.dwForwardMtu` reads **0** (verified via `GetBestRoute`;
    Microsoft lists it as unsupported), and the newer `MIB_IPFORWARD_ROW2`
    dropped the field entirely. Route MTU lives at the interface level there,
    which is `Interface.mtu`; probing with `discover_mtu` is the only way to
    learn a *path* MTU.
  - macOS/BSD expose no IPv4 equivalent either, so v4 there is `None` too.

  > **This used to return `None` everywhere**, Linux included, because
  > `IP_MTU`, `IP_MTU_DISCOVER` and `IP_PMTUDISC_DO` are **not exported by
  > CPython on any platform** (measured on 3.13 and 3.14) and the code guarded
  > on `getattr(socket, "IP_MTU", None)`. The Linux numbers are named from
  > `<linux/in.h>` instead. `IPV6_PATHMTU` also returns a `struct ip6_mtuinfo`
  > — a `sockaddr_in6` followed by the MTU — not the bare int `IP_MTU` gives
  > back, so reading it as an int decoded the address family as the MTU.

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
  returns `[(address, [open_ports]), ...]` sorted by address, hosts with
  nothing open omitted.

`ports` accepts a **`PORT_RANGES` name** (`"common"`, `"well-known"`, `"all"`),
a **scheme name** resolved via `get_default_port` (`"https"` → 443), a number, a
numeric string, or any iterable mixing those. Range names win over scheme names
where they collide. `scan_hosts(port=...)` is shorthand for `ports=[port]` and
accepts a scheme name too; passing both raises `ValueError`.

- **Every port is validated to `0-65535`** and raises `ValueError` otherwise,
  instead of being masked to 16 bits — `scan_ports(host, [p + 65536])` used to
  answer about `p`. An unknown scheme or range name raises `ValueError` too.
- **An explicitly empty `ports` means "nothing to scan"** and returns `[]`. It
  does **not** fall back to the 36-port `"common"` set, which would sweep a
  network the caller just said to probe on no ports; `scan_hosts`
  distinguishes an empty list from omission.
- **`timeout` is floored to 1ms** — `settimeout(0)` is *non-blocking* and
  reported every port closed — and a **negative** `timeout` raises
  `ValueError`. Note the scanners floor at 1ms while `tcp_check` floors at
  50ms.
- **`host` is resolved once per scan**, not once per port. That is a
  correctness fix, not only a speed one: a rate-limited resolver turned open
  ports into "closed". A name that does not resolve returns `[]` after a single
  lookup; a name with several addresses is still probed on each.
- **`scan_hosts` refuses anything larger than /16** (IPv6 /112): a /8 sweep is
  16M addresses, a mistake rather than an intention. Only usable host addresses
  are probed — network and broadcast addresses are skipped.
- A **TCP** sweep, so a host answering on none of the probed ports does not
  appear — it is not ARP/ICMP discovery, and a firewalled host is
  indistinguishable from an absent one.
- Ordinary full connects: **no SYN/stealth scanning, no fingerprinting**.
  Connections are logged by the target like any other. Use on hosts you are
  responsible for.

## Multicast

- **`multicast_socket(group=None, port=0, interface=None, ttl=1, loop=True, bind=True, reuse=True, ipv6=None)`**
  — a UDP socket configured and joined in one call. `group` is a group address
  or a list of them; `group=None` gives a send-only socket.
  `ipv6=None` takes the family from `group`, which is what you want whenever
  there is one. Pass it explicitly for the **send-only** case, where there is
  no group to infer from — that socket is IPv4 unless you say otherwise:
  `multicast_socket(ttl=32, bind=False, ipv6=True)`.
  Raises `ValueError` for a non-multicast group, for groups of **mixed address
  families** (one socket has one family — open two), and for an `ipv6` that
  contradicts `group`; `OSError` if binding or joining fails.
- **Link-local IPv6 groups (`ff02::/16`) need a scope**, and only some kernels
  will pick one. Index `0` means "kernel's choice" and is the right default:
  Linux and Windows honour it and join happily. macOS/BSD will not choose for a
  link-local group and fail the join with `EADDRNOTAVAIL`, so this supplies an
  index there — the first non-loopback adapter carrying a link-local address.
  An explicit `interface=` always wins, on every platform; the fallback only
  covers the case where nobody chose and the kernel would not either.
- **`join_group(sock, group, interface=None)`** / **`leave_group(...)`** —
  closing the socket drops membership too, so `leave_group` is only needed to
  leave while keeping the socket open.
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
datagram reports which interface it arrived on. Essential for broadcast
protocols, where a wildcard-bound server otherwise cannot tell which network a
request came from.

`recv(bufsize=65535, resolve_interface=True) -> Datagram`, a `NamedTuple` of
`.data`, `.sender`, `.local_address`, `.interface_index`, `.interface` and
`.control_truncated`. `send(data, address, port, src=None) -> int` pins the
outgoing interface; `address` accepts `AddressLike` and `src` the usual loose
interface spec (`Interface`, MAC, adapter name or address). `close()` closes
the wrapped socket, and the endpoint is a **context manager**
(`with UdpEndpoint(bind("", 67)) as endpoint:`).

- **One option per address family, and they are not spellings of each other.**
  `IP_PKTINFO` is the IPv4 option; setting it on an `AF_INET6` socket
  *succeeds* on Linux and then no cmsg ever arrives. The family selects the
  option to set (`IP_PKTINFO` / `IPV6_RECVPKTINFO`), the cmsg type to match
  (`IP_PKTINFO` / `IPV6_PKTINFO` — on Linux the v6 pair are distinct constants,
  49 and 50) **and** the struct layout (`in_pktinfo` is index-then-addresses,
  `in6_pktinfo` is the 16-byte address **first**, then the index). An IPv6
  endpoint therefore reports a real `interface_index`, `interface` and
  `local_address`, where it used to report `0`/`None`/`None` while claiming
  `supports_pktinfo`.
- **Two honest flags, decided once at construction from the socket's own
  family.** `supports_pktinfo` — `recv` will report the arrival interface;
  `False`, never an optimistic `True`, whenever the option for *this* family is
  missing or refused. `supports_src_pinning` — `send(src=)` can be honoured;
  `False` where the platform has no `sendmsg` (Windows) or no pktinfo cmsg for
  the family (macOS has no `IP_PKTINFO`).
- **Degrades rather than failing.** `recvmsg`/`sendmsg` do not exist on Windows
  whatever the constants say; there `recv` falls back to `recvfrom` and the
  interface fields are empty, while `send` sends unpinned without even
  resolving the spec. Check the two flags rather than inferring from an empty
  result.
- **`pktinfo=False` governs receiving only.** Sending needs no socket option,
  so `send(src=)` is still honoured on an endpoint built with it.
- **`send(src=)` pins the interface index as well as the source address.** The
  old code hardcoded `ipi_ifindex=0` and so only ever pinned an address. It
  raises `ValueError` for a `src` that names no local address or interface
  (silently sending from another adapter is the failure mode `src` exists to
  prevent) and for an IPv6 `src` on an `AF_INET` endpoint — Linux *accepts and
  ignores* a v6 cmsg on a v4 socket, so there is no correct silent behaviour
  available. An `OSError` from the kernel, meaning a source this host cannot
  send from, propagates; only platform incapability degrades to `sendto`.
- **`control_truncated`** reports `MSG_CTRUNC`: the kernel had more ancillary
  data than the buffer held. When it is `True` and the interface fields are
  empty, they are empty because something was dropped. The buffer is sized for
  four cmsgs rather than one, so an unrelated option on the raw socket
  (`SO_TIMESTAMP`, `IPV6_RECVHOPLIMIT`) no longer silently swallows the
  pktinfo — measured on Linux, where a one-slot buffer kept the timestamp and
  discarded the pktinfo.
- **A dual-stack `AF_INET6` socket needs only its own option.** An IPv4 arrival
  then reports the v4-mapped form (`::ffff:10.0.0.1`) in both `.sender` and
  `.local_address`.
- `.local_address` for a broadcast is the **broadcast** address, not the
  interface's own — use `.interface` to identify the adapter.
- Pass `resolve_interface=False` in a hot loop and use `.interface_index` —
  enumeration is a syscall. Resolving a MAC, adapter name or bare address in
  `send(src=)` enumerates too; pass an `Interface` in a send loop to avoid it.
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
  own loop; it yields the same schedule, `attempts - 1` values.

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
dependency on the CLI half. The `netimps` console script is installed either
way; without the extra it prints
`netimps: the CLI needs the 'cli' extra -- pip install 'netimps[cli]'` and
exits 1, instead of dying in an `ImportError` traceback.

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

Aliases: `resolve|dns`, `check|tcp`, `addr|parse`, `source|src`.

- **`--json` on every command**, so output is scriptable. Text output is for
  humans and its exact wording is not a stability guarantee; the JSON shape is.
- **stdout carries the answer and nothing else.** Every diagnostic —
  `error: ...`, `no interface named ...`, `no route to ...` — goes to
  **stderr**, so `--json` stays parseable exactly where a script needs it most:
  on failure stdout is empty and the exit code carries the verdict.
- **The positional argument is required** for `ping`, `resolve`, `check` (both
  of its two), `mtu`, `scan`, `addr` and `split`. It used to default to `""`,
  so `netimps ping` answered about the empty string; a missing one is now
  argparse's usage error on stderr with exit 2. `route` and `source` still
  default to `8.8.8.8`.
- **Exit codes are meaningful**: `0` success, `1` "the answer was no"
  (unreachable, closed, no records), `2` a **caller** error — a bad argument, a
  missing positional, `--method tcp` with no `--port`, or a scheme with no port
  where a port was needed. A `ValueError` out of the library becomes
  `error: <message>` on stderr with exit 2, never a traceback. `ping` mirrors
  `ping(8)`.
- **`netimps port <unknown>` exits 1, not 2.** A lookup that found no mapping
  is an *answer* — "none" — the same way an empty `resolve` is, and
  `netimps port 9999` (a valid port with no registered scheme) is not a caller
  mistake. `netimps check <host> <unknown-scheme>` does exit 2, because there
  is then no port to connect to and nothing was tested.
- `netimps route` prints an `on-link  <True|False|unknown>` line and renders a
  missing next-hop lookup as `gateway  (unknown)` rather than
  `(on-link, no router)`; `--json` accordingly has `"on_link": null` as a third
  possible value.
- `python -m netimps` is equivalent to the `netimps` console script.

## Constants

- **`HOST_DN`** — `platform.node()`, captured **at import time** (a later
  hostname change is not reflected).
- **`PORT_RANGES`** — `{"well-known", "common", "all"}` port tuples;
  `"common"` holds 36 ports.
- **`APIPA`** (`169.254.0.0/16`), **`LOOPBACK_V4`** (`127.0.0.0/8`),
  **`LOOPBACK_V6`** (`::1/128`), **`LINK_LOCAL_V6`** (`fe80::/10`) — named
  networks, so callers stop spelling the literals out.
