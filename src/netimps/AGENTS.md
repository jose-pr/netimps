# `netimps` — public API header

Header-file-style reference for the `netimps` package: every `__all__` export
with its signature, arguments, contract, and gotchas, so this module can be
consumed without reading its source.

Everything is imported from `netimps` directly. The `_`-prefixed submodules
(`_ip`, `_mac`, `_ifaddrs`, `_sockets`, `_dns`, `_ping`, `_scan`, `_multicast`,
`_scheme`, `_retry`, `_udp`) are implementation detail —
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
| `dst` | where traffic is **sent** | `ping`, `tcp_check`, `wait_for_port`, `get_route`, `count_hops`, `discover_mtu`, `get_tcp_mss`, `get_pmtu`, `scan_ports(host)` |
| `src` | where traffic is **sent from** | `ping(src=)`, `get_free_port(src=)`, `discover_mtu(src=)`, `UDPEndpoint.send(src=)` |
| `host` / `network` | the thing being **examined** | `scan_ports(host)`, `scan_hosts(network)` |
| `address` / `ip` | an address being **classified** (no DNS) | `get_interface`, `iter_interfaces`, `is_local_address`, `is_multicast`, `is_link_scoped` |

`dst`/`src` are abbreviated symmetrically, matching packet-header convention.
A `dst` accepts a hostname; an `address` does not, and a classifier given text
that is no address raises `NetimpsValueError`.

**Options are keyword-only.** A function takes the thing it acts on (and, where
the signature below shows it, one more operand) positionally; every other
parameter must be named, so `ping("h", 3)` is a `TypeError` and
`ping("h", tries=3)` is the call. The signature lines in this file show the `*`
where the keyword-only options begin. Constructors follow the same rule
(`Interface(name, index, *, mac=..., ...)`); `recvmsg`, `sendmsg`, `CMSG_LEN`
and `CMSG_SPACE` keep the standard library's shapes, and the `Datagram` and
`SocketOption` named tuples are positional by nature. Methods follow the
same rule: after the operand (and the second one where the signature shows
it) the options are keyword-only, so `endpoint.recv(1500, False)` is a
`TypeError` and `endpoint.recv(1500, resolve_interface=False)` the call.

**Durations are seconds.** `timeout` bounds one attempt and `deadline` a whole
operation made of several (`wait_for_port`); `PingResult.rtt` is a duration in
seconds, never milliseconds.

**Every `dst`-typed parameter accepts `HostLike`** — a hostname string, an
address string, an existing `IPv4Address`/`IPv6Address`, a `Host`, an `FQDN`,
or an `IPv4Interface`/`IPv6Interface` (its `.ip` is used, dropping the `/prefix`,
which every user of a destination -- a subprocess argument, a socket
call, a DNS query -- would otherwise read as garbage). A network
(`IPv4Network`/`IPv6Network`) raises `TypeError`, since it has no single
address to send to. **Anything else raises `TypeError`**, `None` included: it
is never read as the host named `"None"`. `resolve`'s `query` accepts the same
forms.

**Every `port` a network helper takes is validated** before a socket sees it:
`tcp_check`, `wait_for_port`, `scan_ports`, `scan_hosts`, `get_pmtu`,
`discover_mtu`, `get_tcp_mss` and `register_port` raise `ValueError` outside
`0-65535` and `TypeError` for a non-`int` — including `bool`, and including a
service-name string such as `"http"`, which must go through
`get_default_port` first. The socket layer would otherwise mask the value to
16 bits, so `port + 65536` would silently answer about `port`. The two *table*
lookups, `get_default_port`/`get_default_scheme`, return `None` instead:
"no such entry" is the honest answer from a lookup, not an error.

**Several parameters are named `ipv6=`** and mean one thing throughout --
`True` IPv6, `False` IPv4, `None` (the default) whichever the resolver
answers with: `Host.ip`, `get_source_ip`, `get_route`, `count_hops`, `get_pmtu`,
`ping`, and `discover_mtu`. A literal `dst` decides for
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

**The value types are read-only.** `MACAddress`, `FQDN`, `Host`, `Interface`,
`PingResult` and `Route` raise `AttributeError` on any assignment or deletion;
build a new one instead. Each is hashable where equality is defined, and each
copies (`copy.copy`, `copy.deepcopy`) and pickles; a subclass of `MACAddress`,
`FQDN` or `Host` comes back as itself, and its `parse`, `try_parse` (and, for
`FQDN`, `decode` and `decode_at`) return the class they were called on, typed so
too. The named networks `LOOPBACK_V4`, `LINK_LOCAL_V4` (`IPv4Network`) and
`LOOPBACK_V6`, `LINK_LOCAL_V6` (`IPv6Network`) carry their concrete classes.

## Type aliases

| Name | Meaning |
| --- | --- |
| `IPAddress` | `IPv4Address \| IPv6Address` |
| `IPInterface` | `IPv4Interface \| IPv6Interface` (address + prefix) |
| `IPNetwork` | `IPv4Network \| IPv6Network` |
| `IPAddressLike` | `str \| int \| bytes \| IPv4Address \| IPv6Address` -- accepted *as input* for an address |
| `IPInterfaceLike` | anything accepted *as input* for an address + prefix |
| `IPNetworkLike` | anything accepted *as input* for a network |
| `HostLike` | `str \| IPv4Address \| IPv6Address \| IPv4Interface \| IPv6Interface \| Host \| FQDN` -- any `dst`-typed parameter |
| `InterfaceLike` | `Interface \| MACAddress \| IPv4Address \| IPv6Address \| str \| None` -- names a local interface: `src=` and `interface=` parameters |
| `InterfaceQuery` | `Interface \| IPAddressLike \| IPInterface \| IPNetwork \| MACAddress` (text that is none of those is an adapter name) -- what `get_interface` and `iter_interfaces` look up |
| `PortsLike` | `str \| int \| Iterable[str \| int]` -- a port, a range name, a scheme name, a comma-separated string of those (`"22,https"`), or several: `scan_ports`, `scan_hosts` |
| `SocketAddress` | `(host, port)` or `(host, port, flowinfo, scope_id)` -- a socket address tuple, as in `Datagram.sender` |
| `MACAddressLike` | `str \| int \| bytes \| bytearray \| MACAddress` |

Plus the stdlib concretes re-exported so callers need not import `ipaddress`:
`IPv4Address`, `IPv4Interface`, `IPv4Network`, `IPv6Address`, `IPv6Interface`,
`IPv6Network`.

**The `*Like` aliases are input-only** and are rejected in a `type` position —
they describe what goes in, not what to build.

## Parsing

- **`parse(value, type=IPAddress, *, strict=None, **options)`** — build `type` from `value`,
  raising on bad input. `type` is a union alias, a concrete class, or any
  callable. `strict` is the network builders' option and is passed only when
  given; other `options` pass to the underlying builder.
- **`try_parse(value, type=IPAddress, *, default=None, strict=None, **options)`** — same, but
  returns `default` instead of raising.
- **`is_valid(value, type=IPAddress, *, strict=None, **options)`** — same, returning `bool`.
- **`classify(text) -> MACAddress | IPNetwork | IPInterface | IPAddress`** — read
  text as whichever of those it spells. Order: a MAC (any accepted spelling);
  text with a `/` is an `IPNetwork` when it has no host bits (`"10.0.0.0/24"`,
  `"10.0.0.5/32"`) and an `IPInterface` otherwise (`"10.0.0.5/24"`); text
  without one is an `IPAddress`. It reads the text alone and never asks a
  resolver, so a name raises: resolve it with `Host(name).resolve()` first.
  Raises `NetimpsValueError` for text that is none of them and `TypeError` for
  a non-`str`.

All three spell the second argument `type`, so it works positionally or by
keyword. Key behaviours:

- **For `MACAddress`, `FQDN` and `Host` (and their subclasses) a `str` goes
  through the type's own `Type.parse`**; anything else (an `int` or packed
  `bytes` MAC, a `Host` or `FQDN` already built) goes to the constructor.
  `try_parse(None, MACAddress)` is `None` — the generic form answers `default`
  for any object — whereas `MACAddress.try_parse(None)` raises `TypeError`.
- **An option the callable does not take raises `TypeError` from `try_parse` and
  `is_valid` too**, before the guarded call: `try_parse("10.0.0.5", IPAddress,
  strict=True)` is a caller's bug, not a rejected value, and is not `None`.
  Skipped for a callable with a `**` parameter or no inspectable signature.

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
- **Malformed input raises `NetimpsValueError`** (a `ValueError`), including
  the `ipaddress` builders' own `AddressValueError`/`NetmaskValueError`, which
  are chained as `__cause__`. A callable `type` that is not one of the
  package's builders raises whatever it raises.
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
| `.format(sep=":", *, upper=False)` | render with any separator; `sep=""` for bare form |
| `format(mac, spec)`, `f"{mac:spec}"` | empty spec is `str(mac)`; otherwise the spec is the separator, with a trailing `X` for upper case: `f"{mac:-X}"` is `mac.format("-", upper=True)` |
| `bytes(mac)` | the six raw octets, the same as `.packed` |
| `.hex(sep=None, bytes_per_sep=1)` | exactly `bytes.hex` — `'aabbccddeeff'`, `hex(":")`, `hex("-", 2)` → `'aabb-ccdd-eeff'` |
| `.packed` | the 6 raw bytes |
| `.oui` | the first three octets, **verbatim** (see below) |
| `.is_multicast` | group bit (low bit of octet 0) |
| `.is_local` / `.is_universal` | the U/L bit |
| `int(mac)`, `str(mac)` | integer / colon form |
| `<`, `<=`, `>`, `>=` | ordering against another `MACAddress`, so MACs sort |
| `MACAddress.parse(text)` | classmethod: text in any accepted spelling → `MACAddress`; `NetimpsValueError` for bad text, `TypeError` for a non-`str` |
| `MACAddress.try_parse(text, default=None)` | classmethod: `default` for bad text; still `TypeError` for a non-`str` |
| `MACAddress.is_valid(v)` | classmethod predicate over anything the constructor takes; never raises |

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
  is `False`, and `try_parse(True)` raises `TypeError` like any non-text.
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
  `format(".")` emits `aa.bb.cc.dd.ee.ff` (one dot per octet) and round-trips
  through the constructor; the Cisco triplet form is accepted on input and
  never produced. `":"`, `"-"`, `"."` and `""` all round-trip; any other
  separator renders but does not.
- `.is_local` means *locally administered* (VMs, containers, MAC randomisation),
  so such addresses are **not stable identifiers**.
- The classmethods are `classmethod`, not `staticmethod`, so a subclass
  validates against itself.

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

## Address and network helpers

- **`is_link_scoped(ip: IPAddressLike) -> bool`** — loopback (host scope) or
  link-local (link scope): confined to this host or link. **Not "is private"** —
  RFC 1918 ranges are globally scoped and return `False`. A v4-mapped address is
  judged as the v4 address inside, the same on every Python.
- **One rule for the classifiers** (`is_link_scoped`, `is_wildcard`,
  `is_multicast`, `is_local_address`, `is_broadcast`, `is_unicast`, and `unmap`):
  each takes `IPAddressLike` (text, `int`, packed `bytes`, an address object; an
  interface is read as its `.ip`) and raises `NetimpsValueError` for text that is
  no address, and `TypeError` for a network or a value of another type
  (`None`, `float`, `bool`, `list`). `is_wildcard` alone also takes `None` and
  blank text, which mean "every address". `is_local_host` alone takes a name:
  it never raises, and anything that is not a host is `False`.
- **`collapse(networks) -> List[IPNetwork]`** — merge adjacent/overlapping
  networks into the minimal equivalent list. Mixed families collapse
  independently.
- **`subtract(networks, remove) -> List[IPNetwork]`** — set difference, which
  `ipaddress` omits (it ships `collapse_addresses` but nothing to punch holes).
  Result is collapsed.
- **`join_host(host: HostLike, port=None) -> str`** — the **inverse** of
  `split_host`, and the direction everyone writes by hand and gets wrong on
  IPv6:

  ```python
  join_host("example.com", 8080)   # 'example.com:8080'
  join_host("::1", 8080)           # '[::1]:8080'   -- not '::1:8080'
  join_host("fe80::1%eth0", 80)    # '[fe80::1%eth0]:80'
  join_host("::1")                 # '::1'          -- no port, no brackets
  ```

  Accepts a `str`, an address, an `IPv4Interface`/`IPv6Interface` (its `.ip` is
  used) or an `FQDN`; an already-bracketed string is not double-bracketed.
  **Only an IPv6 *literal* is bracketed** — a hostname never is, however many
  colons it has, because brackets in a URI authority assert "the inside is an
  address". A port-less v6 comes back bare, which is what makes
  `split_host(join_host(h, p)) == (h, p)` hold in every case. Raises
  `NetimpsValueError` for an empty host, a port outside 0–65535, brackets around
  anything but an IPv6 address, or a mismatched bracket (`"[::1"` would
  otherwise emerge as `"[::1:80"`).
  Both of these take the package's usual loose union, not only a `str`: an address
  object, an `IPv4Interface`/`IPv6Interface` (its `.ip` is used), a `Host` or an
  `FQDN`. A *network*, and any other value (`None`, an `int`, `bytes`), raises
  `TypeError` — a network names no single host, and an allowlist replaces a
  `str()` fallback, which turned `None` into the hostname `"None"`.
  `split_zone` takes the same union and the same `TypeError`.
  **Port text is ASCII digits** (RFC 3986 `port = *DIGIT`): `"h:8_0"`, `"h:+80"`,
  `"h: 80"` and non-ASCII digits raise `NetimpsValueError`; a `port` argument of
  `join_host`, or the port of a `(host, port)` pair, is an `int` (a `bool`, a
  `float` or a numeric `str` raises `TypeError`; a pair may carry digit text).
  What sits inside brackets is validated as an IPv6 literal by `split_host` as
  `join_host` does, so `split_host("[10.0.0.5]:80")` raises.
- **`unmap(value) -> IPAddress`** — collapse an IPv4-mapped IPv6 address
  (`::ffff:10.0.0.5`) to plain IPv4; anything else passes through. The form a
  dual-stack socket reports an IPv4 peer in, and almost nothing a caller does wants
  it — an ACL comparing against `10.0.0.0/8`, a log line, a config lookup.

  Built on `IPv6Address.ipv4_mapped`, **not** a `"::ffff:"` prefix test, which
  looks equivalent and is not. Measured — all three of these *are* mapped, and a
  `startswith("::ffff:") and "." in text` check leaves every one untouched:
  `::FFFF:10.0.0.5` (case), `::ffff:0:1` (no dot), `0:0:0:0:0:ffff:0a00:0005`
  (expanded). One address has many spellings; only the parsed form sees through
  them. Takes `IPAddressLike`; raises `NetimpsValueError` for text that is no
  address.
- **`is_wildcard(value: IPAddressLike | None) -> bool`** — whether a value
  means "every local address": `""`, `None`, `"0.0.0.0"`, `"::"`, the v4-mapped
  `::ffff:0.0.0.0`, and any other spelling whose address form is unspecified. A
  `%zone` is stripped first. Raises `NetimpsValueError` for text that is no
  address. Agrees with what `bind("")` treats as the wildcard.
- **`split_zone(text) -> (host, zone | None)`** — split an IPv6 `%zone` suffix
  off a host: `"fe80::1%eth0"` → `("fe80::1", "eth0")`, `"10.0.0.5"` →
  `("10.0.0.5", None)`. Use it before `try_parse` or a comparison, because
  `ipaddress` keeps the zone as part of the address and `fe80::1%eth0` equals
  nothing an interface reports. Takes the loose host union; a `%` with nothing
  after it raises `NetimpsValueError`. Brackets are `split_host`'s.
- **`split_host(text, *, default_port=None) -> (host, port)`** — split
  `host:port`, handling IPv6 brackets. `text` is also a **`(host, port)` pair**
  with `port` an `int` or `None`, `default_port` filling the `None`:
  `split_host(("h", None), default_port=69)` → `("h", 69)`; a port written both
  in the host and beside it must agree. A bracketed literal with no port is the
  host alone, `"[::1]"` → `("::1", None)`. **`"::1"` stays an address**, never host
  `"::"` port `1` — the mistake hand-rolled splitters make. Only a bracketed v6
  address may carry a port; brackets are stripped from the returned host and a
  scope id is preserved (`"[fe80::1%eth0]:80"` → `("fe80::1%eth0", 80)`).

  Raises `ValueError` for empty input, an unclosed bracket, a port that is not
  an integer in `0-65535`, and **an unbracketed string with two or more colons
  that is not a valid IPv6 address**. `"host:80:extra"` and a half-typed
  address raise rather than come back whole as the *host*, which would send the
  caller to look up a name that cannot exist.

## Scheme ↔ port registry

- **`get_default_port(scheme) -> int | None`** — text that is a whole number is
  a port and comes back as an `int` (`"443"` → `443`; outside `0-65535` raises
  `NetimpsValueError`). Otherwise the built-in table (35 entries,
  including the socks variants, the `ws`/`wss` websocket schemes and the
  WS-Management spellings `wsman`/`wsmans` (IANA), `winrm`/`winrms` and `psrp`
  — 5985 for the plain forms, 5986 for the `s` forms — all absent from
  `/etc/services`), then `getservbyname`. Case-insensitive.
- **`get_default_scheme(port) -> str | None`** — the inverse, then
  `getservbyport`. The first scheme registered for a port is its canonical name,
  so `5985` is `"wsman"` and `5986` is `"wsmans"`, not their aliases. An out-of-range `port` is `None` rather than an error: this
  is a table lookup, not a socket operation.
- **`register_port(scheme, port, *, canonical=False)`** — extend or override.
  Raises `ValueError` for an empty scheme or a port outside `0-65535` (the
  range is named in the message) and `TypeError` for a non-`int` port.

Where several schemes share a port the **canonical** one is returned (1080 →
`socks`, not `socks4`/`socks5`; 80 → `http`, not `ws`; 443 → `https`, not
`wss`). Registering an alias does not steal that slot unless `canonical=True`.

- **The services database is asked for TCP first, then UDP.** A protocol-less
  `getservbyname`/`getservbyport` picks per platform, so port 514 answered
  `shell`/`cmd` on one host and `syslog` on another. The TCP entry wins
  everywhere, so the answers are identical across platforms; the built-in
  table is unaffected.
- **Re-registering a scheme *moves* it.** After `register_port("myproto", 8888)`
  a prior `register_port("myproto", 9999)` stops mapping `9999` back to
  `myproto` — the registry would otherwise state both facts at once. If another
  scheme still claims the vacated port it inherits the slot (earliest
  registration first, the same rule the initial index uses).

## DNS

Four independently callable backends (`resolve_dnspython`, `resolve_wire`,
`resolve_system`, `resolve_nslookup`), `resolve_doh` for one DNS-over-HTTPS
endpoint, and `resolve()`, which chains the four. They share one contract. The
answer is a `list` with **native types**: `A`/`AAAA` records are `ipaddress`
objects, everything else is `str` (trailing root dot stripped, TXT strings
unquoted). It is **empty when the resolver answered that there is no such name
or no such record** (NXDOMAIN, NODATA), never `None`. **A resolver that could
not be asked is not an empty answer**: every backend raises
`ResolutionTimeoutError` for a deadline and `ResolutionError` for a server that
does not answer, a SERVFAIL, a temporary `getaddrinfo` failure or a missing
program. Only `resolve()` without `strict=True` turns that into `[]`, so that
`if not resolve(h):` keeps working; `strict=True` re-raises it.

**Exceptions.** Every exception netimps raises on its own account descends
from **`NetimpsError(Exception)`**, and each one also inherits the builtin a
caller would already catch, so an existing `except ValueError` /
`TimeoutError` / `OSError` keeps working. All are exported from `netimps`:

| Class | Bases | Raised for |
| --- | --- | --- |
| `NetimpsError` | `Exception` | the base; catch it for "anything netimps reported" |
| `NetimpsValueError` | `NetimpsError`, `ValueError` | text that is not the value it was asked to become |
| `ResolutionError` | `NetimpsError`, `OSError` | a backend could not even attempt the query (an outage) |
| `NoAnswerError` | `ResolutionError` | `check=True`: the lookup completed and there is no such name or record |
| `ResolutionTimeoutError` | `ResolutionError`, `TimeoutError` | a backend's deadline expired |
| `DNSDecodeError` | `NetimpsValueError` | the DNS codec cannot read a reply or write a name |
| `AddressInUseError` | `NetimpsError`, `OSError` | `bind()` found the address taken |

A caller's own mistake (a bad option, a wrong argument type) is plain
`ValueError` / `TypeError`, never a `NetimpsError`. `NetimpsValueError` is what
a function whose job is to turn text into a value raises for text it cannot
read: `parse`, `MACAddress(...)`, `FQDN(...)`, `split`-style host and port
splitting (`split_host`, `join_host`) and `resolve_nslookup`'s query
check. A bad option elsewhere (`ping`'s `ttl`, `tcp_check`'s port, a
`timeout`) stays a plain `ValueError`.

**`ResolutionError` is an `OSError`**, as the standard library's own name
failure `socket.gaierror` is, so an `except OSError` around a connect catches it
and `retry()` retries it by default. **`NoAnswerError`** is the leaf for a lookup
that *completed* and found nothing; `Host`/`FQDN` `check=True` raises it for an
empty answer, and a plain `ResolutionError` or `ResolutionTimeoutError` for an
outage, so a caller can tell a name that does not exist from a resolver that
could not be asked. `retry` retries `NoAnswerError` too unless `retryable=` names
the types to retry instead of `OSError` itself.

**`ResolutionError`** — a backend could not even *attempt* the
query: a missing `nslookup` binary, `dnspython` not installed, an `rdtype` the
backend structurally cannot serve, a transport failure, a server that failed or
did not answer. It is
deliberately **not** how "no such record" is reported — that is `[]`. It is
the documented raised type of `resolve`, `resolve_system`, `resolve_nslookup`,
`resolve_wire` and `resolve_doh`. When the reason is an expired deadline
(`resolve_system`, `resolve_nslookup`, `resolve_wire`, `resolve_doh`) it is the
subclass **`ResolutionTimeoutError`**, so `except ResolutionError` and
`except TimeoutError` both catch it.

**`DNSDecodeError`** reaches a caller directly from `resolve_doh` (a `query`
with an empty or over-long label, raised before anything is sent) and from
`FQDN.encode()` (a name whose labels cannot be encoded) and from
`FQDN.decode()` / `FQDN.decode_at()` (bytes that are not a name). Inside `resolve_wire`
and `resolve_doh` an unreadable *reply* is not raised as such: it becomes a
`ResolutionError` whose `__cause__` is the `DNSDecodeError`.

**`resolve(query, rdtype=None, *, ns=None, timeout=5.0, port=53, tcp=False, search=True, backends=None, strict=False, source=None, cache=False, deadline=None)`**

**`timeout` is one attempt, `deadline` the whole call.** `timeout` bounds the
whole backend call for `dnspython` and `wire` (every nameserver and retry
included), and each candidate name of a search list for `system` and
`nslookup`; a record-type pair is one attempt per type. `deadline` (seconds,
`None` for no limit) is shared by every backend, record type and candidate:
each attempt gets `timeout` or the time left, whichever is smaller, and once it
has passed the remaining backends are not started. The outcome is `[]`, or with
`strict=True` a `ResolutionTimeoutError`. `Host.ip/fqdn/resolve` and
`FQDN.ip/resolve` take the same `deadline=`.

**The element type follows `rdtype`, for `resolve` and for each backend below:**
`"a"` gives `List[IPv4Address]`, `"aaaa"` `List[IPv6Address]`, `"ptr"`
`List[str]` (case-insensitive), and `None`, a tuple of types or any other
record type `List[Any]`. A type checker selects the overload from the literal.

`query` accepts `HostLike` (a hostname string, an address string, an
`IPv4Address`/`IPv6Address`, or an `IPv4Interface`/`IPv6Interface` -- its
`.ip` is used), not just a plain string.

`rdtype=None` (default) **auto-selects**: `"ptr"` when `query` is an address
literal (an `"a"`/`"aaaa"` lookup *of* an address makes no sense), `"a"`
otherwise::

    resolve("example.com")   # rdtype auto -> "a"  -> ['93.184.216.34']
    resolve("8.8.8.8")       # rdtype auto -> "ptr" -> ['dns.google']

Pass an explicit `rdtype` to opt out -- `rdtype="a"` on an address still
attempts a literal (and empty) A lookup rather than being silently
overridden.

`rdtype=("a", "aaaa")` asks for **both address families at once**. The OS
resolver answers with one `getaddrinfo` call, in the order it chose; every
other backend is asked for `"a"` then `"aaaa"` and the answers are joined, and
a backend that could not ask for one of the two fails the attempt unless the
other answered. Only address types, each once, are accepted (`ValueError`
otherwise). `Host.ip()` is built on it.

Backends are tried in order, default `["dnspython", "wire", "system", "nslookup"]`:
dnspython first (structured records, every `rdtype`, explicit `ns=`/`search=`
control), then `wire` -- the standard-library DNS client, **only for an
explicit `ns=` or `source=`**, so a named nameserver works without dnspython --
then the OS resolver (hosts file, NSS, OS cache), then `nslookup` as a last
resort. `backends` also accepts a single name as a plain string
(`backends="system"`), or a custom order/subset
(`backends=["nslookup", "dnspython"]`).

- **Only a non-empty answer stops the chain.** An empty one does **not**, and
  that is the point: the backends resolve by structurally *different*
  mechanisms, so DNS's "no such name" says nothing about what the OS resolver
  can still answer. `dnspython` gets NXDOMAIN for `localhost` on Windows and
  macOS while `resolve_system` answers it from the hosts file; the same holds
  for `.local`/mDNS names and anything else only an NSS source knows.
- A backend that could not even attempt the query (a `ResolutionError`:
  missing binary, server silent or failing, timeout, transport failure) falls
  through the same way; one that structurally cannot serve the request is
  skipped without being called at all.
- The result is `[]` when **every applicable backend answered empty**, and
  also when every one of them failed to *attempt* — a resolver outage reads
  the same as a name that does not exist, which is what `if not resolve(h):`
  expects. Pass **`strict=True`** to tell them apart: it re-raises
  the last backend's `ResolutionError` in that case, and only that case. It
  does not turn an empty answer into an error.
  If the chain holds no backend that could even be tried, `ValueError` names
  what excluded them.
- **Without the `dns` extra** `dnspython` is skipped, and the OS resolver,
  `nslookup` and (for an explicit `ns=`) `wire` still answer address and
  reverse records. A request only `dnspython` could serve (a record type the
  others do not read, with no `ns=` for `wire`) raises `ResolutionError`
  saying `pip install "netimps[dns]"`, strict or not: `[]` would claim there is
  no such record. `has_dns() -> bool` asks whether the extra is installed.

**The cost is latency on a genuinely non-existent name:** two or three backend
calls instead of one, the last of which may spawn `nslookup`. Narrow
`backends` to opt out — `backends="dnspython"` restores the single call.

- **`system` is skipped automatically** for a `rdtype` outside
  `"a"`/`"aaaa"`/`"ptr"`, and for an explicit `ns=`, a `port=` other than 53,
  or `tcp=True` — the OS resolver takes no per-call nameserver, port or
  transport, so running it would answer a different question from the one
  asked. With `backends=["system"]` plus one of those, the resulting
  `ValueError` names the reason. **`nslookup` is skipped** for an `ns=` entry
  with a port other than 53, for the same reason.
- **`ns=` is parsed once, before any backend runs**, with the parser
  `resolve_wire` documents (`host`, `host:port`, `[v6]`, `[v6]:port`), and every
  backend that takes it gets the address and the port.
- **`cache=`** reuses a recent answer, with `get_interfaces`' three spellings:
  `False` (the default) neither reads nor writes the cache, `True` keeps an
  answer for `RESOLUTION_CACHE_TTL` (**30 seconds**), a number is that many
  (`0` is always stale, i.e. refresh). Keyed on the name (without case) and
  **every** option, so another `ns`, `rdtype` or `timeout` is another entry.
  **An empty answer is cached like any other**, so a name that does not resolve
  is asked once per TTL; an outage (every backend failed to ask, with
  `strict=False`) and an exception are not cached. The cache is process-wide,
  thread-safe and holds at most 1024 entries. `clear_resolution_cache()` drops it
  when a record is known to have changed. `Host.ip/fqdn/resolve` and
  `FQDN.ip/resolve` take the same `cache=`, and a call that passes it neither
  reads nor writes a `Host`'s own memo.
- **`source=`** (an address, or one per family as a list) is the local address
  the queries leave from. `wire` honours either form; `dnspython` one address
  only (skipped for a list); `system` and `nslookup` are skipped, since neither
  can choose it.
- **`nslookup` is skipped** for a `rdtype` outside `"a"`/`"aaaa"`/`"ptr"`, and
  for `source=`.
  It has no `port=`/`tcp=` parameters, so a `resolve(q, port=5353)` that falls
  through to it is answered against port 53 over UDP — a known gap; pin
  `backends="dnspython"` when the port or transport matters.
- A malformed query or unknown record type raises `ValueError` immediately,
  without trying every backend — that's a caller bug, not a resolution
  outcome.

**`resolve_dnspython(query, rdtype=None, *, ns=None, timeout=5.0, port=53, tcp=False, search=True, source=None)`**

The original backend: `dnspython`, structured records, every `rdtype`. Same
`HostLike` `query` and auto-`rdtype` behavior as `resolve()`. A `"ptr"`
lookup (explicit or auto-selected) uses dnspython's `resolve_address()`,
which builds the reverse (`in-addr.arpa`/`ip6.arpa`) name from the literal
address itself -- the caller never constructs that name by hand.

- **`ns=None` (default) uses the system resolver configuration** —
  `/etc/resolv.conf` on POSIX, the registry on Windows. Pass `ns=` (a string
  or list) to query specific nameservers instead, each as `host`,
  `host:port`, a bare IPv6 address, `[v6]` or `[v6]:port` (an address; `port`
  fills in an entry that names none), or an `https://` DoH URL, which dnspython
  alone takes. A malformed `ns=` raises `NetimpsValueError` immediately, before
  any query is attempted, the same on every backend.
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
- `dnspython` is an **optional** dependency (`pip install "netimps[dns]"`;
  `has_dns()` says whether it is there). Without it this raises
  `ResolutionError` naming the extra, so `resolve()`'s chain skips it.
- **NXDOMAIN and "no answer" are `[]`.** A timeout is `ResolutionTimeoutError`;
  every server failing (a SERVFAIL, a refused or unreachable port) or no
  resolver configuration to read is `ResolutionError`; an `OSError` from the
  socket is `ResolutionError`. A malformed name or unknown record type is
  `ValueError`. Any other exception is the caller's or the library's bug and
  propagates unchanged.

**`resolve_system(query, rdtype=None, *, timeout=5.0, search=True)`**

The OS resolver, via `socket.getaddrinfo()`/`socket.gethostbyaddr()` — **hosts
file, NSS (`nsswitch.conf`) and DNS, in the order the OS applies them**,
including any OS-level resolver cache. This is what `resolve_dnspython`
cannot see (its own DNS query bypasses all of that). Same `HostLike`
`query` and auto-`rdtype` behavior as `resolve()`.

- **Address and reverse records only**: `rdtype` must be `"a"`, `"aaaa"` or
  `"ptr"`; anything else raises `ResolutionError` immediately, no query
  attempted. `"ptr"` goes through `gethostbyaddr()` rather than
  `getaddrinfo()` and returns `[hostname]`.
- **`[]` for `EAI_NONAME`, no data for the family (`EAI_NODATA`,
  `EAI_ADDRFAMILY`, Windows 11004) and, for `"ptr"`, `herror` 1 or 4;**
  every other code (`EAI_AGAIN`, `EAI_FAIL`, ...) is a `ResolutionError`.
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
  raising `ResolutionTimeoutError`; the underlying call is not cancelled, but neither
  the caller nor interpreter exit waits for it. A broken resolver therefore
  costs `timeout`, not however long it takes to give up — which is also what
  lets `resolve()`'s chain reach `nslookup` on schedule. The reverse path used
  to ignore `timeout` outright: measured 4.6s against a 0.1s deadline.

**`resolve_nslookup(query, rdtype=None, *, ns=None, timeout=5.0, search=True)`**

Shells out to the `nslookup` binary — a fallback for when neither Python-level
path is usable. Address records only: `rdtype` must be `"a"`, `"aaaa"` or
`"ptr"`. Same `HostLike` `query` and auto-`rdtype` behavior as `resolve()`.

- Parses **both BIND-style** (`Address: 1.2.3.4`, one line per address) **and
  Windows-style** (`Addresses:` with continuation lines, and NODATA as a bare
  `Name:` line with no address and no error text) output. Windows also prints
  its NXDOMAIN message on **stderr**, not stdout — both streams are checked.
- `ns=` is passed as `nslookup`'s trailing `server` argument (a single
  nameserver, not a list): an address or a name, as `host`, `[v6]`, or either
  with `:53`. `nslookup` has no per-call port, so another port raises
  `NetimpsValueError` naming `port=` before a program runs; `resolve_wire` and
  `resolve_dnspython` take one.
- **`search`** has the same three-way contract as the other backends
  (ignored for `"ptr"`), but `nslookup` has no built-in search-list
  handling — this issues one `nslookup` call per candidate name, in order,
  stopping at the first with actual records. `search=True` (default) draws
  the candidate list from the system resolver's search config (reusing
  `dnspython`'s `resolv.conf`/registry parsing if it's installed; `[]` —
  literal name only — if not). `timeout` bounds **each** `nslookup` run.
- **Raises `ValueError` before `nslookup` is run** for a `query`, an `ns` or a
  `search` domain that starts with `-`, is empty or whitespace-only, or
  contains whitespace or control characters. `nslookup` has **no `--` end-of-options separator**, so
  such a query cannot be escaped into position: the binary reads it as an
  option, finds no name argument, and drops into *interactive* mode — where it
  reads names to look up from **stdin**. Measured: that drained the calling
  program's stdin and sent each line to the configured nameserver as a query.
- **`nslookup` is run as described under "Programs the library runs"**:
  standard input closed, `LC_ALL=C`, output decoded `errors="replace"`.
- Raises `ResolutionError` (not `ValueError`) for a missing binary (found on
  `PATH` before anything runs, and named in the message), an unparseable output
  shape, a non-zero exit carrying no "can't find" line (no reachable server, a
  refused connection), or a "can't find <name>: <reason>" line whose reason is
  not a "no such name" answer: `SERVFAIL`, `REFUSED` and Windows' `No response
  from server` (exit 0). The reason after the colon decides, never the prefix.
  "Non-existent domain", `NXDOMAIN` and `No answer` are `[]`, whatever the
  exit status (BIND exits 1, Windows 0).

**`resolve_wire(query, rdtype=None, *, ns=None, timeout=5.0, port=53, tcp=False, search=True, source=None)`**

The DNS protocol itself, standard library only: one question over UDP to each
nameserver in turn, asked again over TCP when the reply is truncated (TCP
throughout with `tcp=True`). Same `HostLike` `query`, auto-`rdtype` and
native-value contract as the other backends.

- **`ns`**: `host`, `host:port`, a bare IPv6 address, `[v6]` or `[v6]:port`
  (an address, not a name; `port` fills in a missing one). `None` reads
  `/etc/resolv.conf` on POSIX; elsewhere it raises `ResolutionError`.
- **`rdtype`**: `a`, `aaaa`, `cname`, `ptr`, `mx`, `txt`, `ns`, `srv` --
  another raises `ResolutionError`, so `resolve()`'s chain moves on. A CNAME
  chain inside the reply is followed.
- **`source`**: the local address to send from, or a list with one per family;
  a server whose family has none is skipped (and named in the error).
- **`timeout`** bounds the whole resolution, TCP reads included; each server
  gets its share of what is left, so a dead first server cannot starve the next.
- **`search`**: a list of domains tries an unqualified `query` under each, then
  as given; `True`/`False` ask for `query` as given (no system search list).
- NXDOMAIN and "no record of this type" are `[]`; no server answering (or only
  SERVFAIL/REFUSED) is `ResolutionError`.
- **A reply is untrusted input.** Over UDP a datagram with another id or
  another question is discarded and the wait goes on to the deadline; the read
  buffer is the 1,232 bytes the query advertises (EDNS). A short MX or SRV
  record is an unreadable reply (`DNSDecodeError` as the `__cause__`), a name
  follows at most 32 compression pointers, and every byte of a decoded name
  outside letters, digits, hyphen and underscore is written `\DDD` (decimal),
  so a PTR answer carries no newline, escape, NUL or dot inside a label.
- A nameserver port outside 1-65535, or not ASCII digits, is a `ValueError`
  before a socket is made.

**`resolve_doh(query, url, *, rdtype=None, timeout=5.0, fetch=None, allow_http=False)`**

DNS over HTTPS (RFC 8484): the same DNS message POSTed to `url` as
`application/dns-message`. **Not part of `resolve()`'s chain** -- a caller that
names a DoH endpoint wants that answer alone.

- **`fetch(url, body, headers, timeout) -> bytes`** sends the request, so a
  caller with its own HTTP stack (a proxy, a CA bundle) routes DoH through it;
  `None` uses `urllib.request`, which follows **no redirect** (a 3xx is an HTTP
  error) and reads **at most 65,536 bytes**. An `OSError`/`ValueError` from it,
  an HTTP error, a body over the limit, a reply to another query, or a reply
  that is not `application/dns-message` is `ResolutionError`.
- **`url` must be `https://`** unless `allow_http=True`; anything else is a
  `ValueError` before a request is made. Messages show the URL without its
  credentials, query string or fragment, so a token in the URL stays out of
  logs.
- `rdtype` as `resolve_wire`; NXDOMAIN is `[]`, another error rcode
  `ResolutionError`.

## Programs the library runs

`ping`/`ping6`, `nslookup`, `route` and `traceroute`/`tracert` are started by one
private runner, so they all behave alike:

- **An argument list, never a shell.** The program is looked up in the absolute
  entries of `PATH` before anything runs; the working directory is never
  searched, even on Windows, and a relative or empty `PATH` entry is skipped.
  A missing one is reported by name (`FileNotFoundError`
  internally), and the caller keeps its own contract for it: `ping` is falsy,
  `get_route` and `count_hops` give `None`/unknown, `resolve_nslookup` raises
  `ResolutionError`. A program that resolves to a `.bat` or `.cmd` is refused.
- **Standard input is closed**, so a child can never read the caller's.
- **`LC_ALL=C` is added to a copy of the environment**, so the output does not
  change with the user's locale. Replies are still matched by address token,
  never by prose.
- **Output is decoded with `errors="replace"`**: the OEM code page on Windows
  (measured: `ping`, `nslookup` and `tracert` all echo a non-ASCII host name in
  it), UTF-8 elsewhere. Invalid bytes become U+FFFD and never raise.
- **Every run has a deadline** (there is no unbounded call), which kills the
  program and its children before the caller's timeout mapping applies
  (`ResolutionTimeoutError` for `nslookup`, falsy for `ping`). `route -n get`
  gets 5 seconds; `resolve_nslookup(timeout=None)` gets 30.
- **The exit status is read**: `route` and `traceroute`/`tracert` with a
  non-zero status give `None`, as a missing program does.
- **Supported programs**: the `ping`, `nslookup` and `tracert` that ship with
  Windows 10 and 11; `ping`, `ping6`, `nslookup`, `route` and `traceroute` on
  macOS 15 and FreeBSD 16; on Linux iputils `ping`, BIND `nslookup` and the
  `traceroute` package, as the CI images carry them. BusyBox applets are not
  supported: its `ping` rejects the don't-fragment flag.

## Reachability

**`ping(dst, *, tries=1, timeout=1.0, ipv6=None, src=None, size=None, ttl=None, dont_fragment=False, method="icmp", port=None) -> PingResult`**

`method` is `"icmp" | "tcp" | "udp"`.

`PingResult` is **truthy on success** and compares equal to `bool`, so
`if ping(host):` and `== True` keep working, while carrying `.ok`, `.dst`,
`.rtt` (seconds), `.ttl`, `.src`, `.attempts`.

`timeout` also bounds the lookup of a hostname `dst` (once, before the first
attempt): a name server that hangs costs `timeout`, not its own give-up time. A
`src` is resolved to the family of `dst`, so `ping("::1", src=<interface>)`
pins the interface's IPv6 address.

| Argument | Notes |
| --- | --- |
| `dst` | `HostLike` (hostname, address string, address object, or `IPv4Interface`/`IPv6Interface` -- its `.ip` is pinged). `ping(get_interfaces()[0].ipv4[0])` works directly. |
| `src` | `Interface`, address, **MAC**, adapter name or string. A MAC is resolved to the adapter holding it. Applies to `tcp`/`udp` as well as ICMP. |
| `size` | ICMP payload bytes. The wire packet is larger by the IP header plus 8: **28 bytes for IPv4**, 48 for IPv6. |
| `ttl` | initial hop limit. The flag letter differs per platform (below); applies to `tcp`/`udp` too. |
| `dont_fragment` | DF bit — Windows `-f`, Linux `-M do`, BSD `-D`. With `size`, the manual MTU probe: largest passing `size` + 28 = IPv4 path MTU. |
| `method` | `"icmp"` (default), `"tcp"` or `"udp"`. The latter two reach hosts through firewalls that drop echo. |
| `port` | required for `tcp`/`udp`, ignored for ICMP. |

**All three methods ask "is the *host* up?"** — so a TCP refusal counts as
success (the RST proves something answered), as does an ICMP port-unreachable
for UDP. Use `tcp_check` for "is the *service* up?", where a refusal is a
failure. `tcp` and `udp` also report `rtt`; only ICMP reports `ttl`.

**On Windows a TCP refusal takes about two seconds to arrive**: the SYN is
retried before the RST is reported (measured 2.02 s against a closed loopback
port on Windows 11; macOS 15.7 answers in 0.9 ms). With `method="tcp"` a
`timeout` under two seconds reports a refusing Windows host as down, so pass
at least 3 there.

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
- **`rtt` is in seconds, and `0.0` for a sub-millisecond reply.** Windows
  prints `time<1ms`, an upper bound rather than a measurement — reading the `1`
  would over-report by up to 100%. `0.0` is falsy, so test `rtt is None` for
  "not reported".
- **Reply lines are matched by address token, and the punctuation differs.**
  Windows writes `Reply from 127.0.0.1:`, Linux `64 bytes from 127.0.0.1:`,
  BSD `ping6` `16 bytes from ::1,` — a colon-only needle never matched the
  last, so a healthy v6 reply on macOS verified as falsy.
- An unusable `src` (unknown MAC, adapter with no address, foreign address)
  gives a falsy result — it **never silently falls back** to the default route.
- **Reachability failures never raise; caller mistakes always do.** A missing
  binary, a hung `ping` (killed after `max(timeout, 1) + 5` seconds), a
  non-zero exit and an empty `dst` are all falsy.
  `ValueError` is raised for an unknown `method`, a negative `size`, a `ttl`
  outside `1-255`, a `tcp`/`udp` probe with no `port`, a `dont_fragment` that
  cannot be honoured, and a `dst` beginning with `-` — the binary reads that as
  an option, and Windows `ping -?` prints usage and **exits 0**, which would
  be reported as a successful ping of a host never contacted.
- `PingResult` is **hashable**, over `(ok, dst, rtt, ttl)`. One asymmetry
  to know about: it compares equal to a `bool` but does not hash like one, so
  `result == True` is `True` while `{True: x}[result]` raises `KeyError`.
- **ICMP echo is not "is the host up"** — most cloud firewalls drop it. Prefer
  `tcp_check`.

## Socket helpers

- **`bind(address="", port=0, *, family=None, kind=SOCK_DGRAM, reuse_address=True, allow_address_takeover=False, reuse_port=False, broadcast=False, connreset=None, interface=None, options=(), listen=None)`**
  — create, configure and bind in one call. `family=None` takes the family
  from the address (`family` is `4`/`AF_INET` or `6`/`AF_INET6`, anything else
  raises `ValueError`): an IPv6 literal (or an `interface=` whose address is
  IPv6) gives `AF_INET6`, an IPv4 literal `AF_INET`, and a name `AF_INET`
  when it has an IPv4 address, else `AF_INET6`. **The wildcard `""` is
  IPv4**; ask for `"::"` to listen on IPv6. `connreset=None` is `False` for a
  datagram socket (Windows: an ICMP port-unreachable does not surface as
  `ConnectionResetError` on a later receive) and leaves other sockets alone;
  `True` keeps the platform's reporting. `interface` accepts the usual union
  (`Interface`, MAC, adapter name, address) and **raises `ValueError`** if
  unresolvable rather than silently binding the wildcard. `options` is read
  once, so a generator is honoured. `reuse_port=True` shares the port with other
  sockets that ask: `SO_REUSEPORT` on POSIX, and on **Windows**, which has no such
  option, a datagram socket takes the address-sharing path (`SO_REUSEADDR`), so
  two sockets that both pass it bind one port and another process can take the
  port over; a stream socket there stays exclusive. `listen` is ignored for datagram sockets. The socket is closed before any
  exception propagates, so a failed call leaks nothing. A failed bind raises
  `OSError` whose message already leads with the `bind_error_hint` text where
  that recognises the failure; an address that is taken is always
  `AddressInUseError`, any other failure keeps its own `OSError` subclass and
  `errno`.

  > **`reuse_address=True` is not one socket option, and does nothing for UDP.**
  > On POSIX it sets `SO_REUSEADDR` **only for a stream socket**, where it
  > permits binding an address still in `TIME_WAIT`. `TIME_WAIT` is a TCP
  > concept: on a *datagram* socket the option's one remaining effect on Linux
  > is to permit duplicate bindings of **live** sockets, so it is not set for
  > datagram sockets. Measured on WSL with the option set — a second `bind()`
  > of the same live UDP `addr:port` succeeded and the datagram went to the
  > **second** socket, with the holder getting no error. `socket(7)` is explicit
  > that the exception is an active *listening* socket, and a UDP socket never
  > listens. Share a UDP port deliberately with `reuse_port=True`
  > (`SO_REUSEPORT`, the option designed for it) or `allow_address_takeover=True`;
  > `multicast_socket` sets what it needs itself. On
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

  > **An explicit `(SOL_SOCKET, SO_REUSEADDR, nonzero)` in `options=` counts as
  > `allow_address_takeover=True`.** It has to: Windows refuses `SO_REUSEADDR` on
  > a socket that already carries `SO_EXCLUSIVEADDRUSE`, reporting a bare
  > `WSAEINVAL` that names neither option — and this function sets
  > `SO_EXCLUSIVEADDRUSE` for both values of `reuse_address`, so without the
  > rule the stdlib-shaped spelling of "share this address" would not work. A
  > zero value is an explicit opt-*out* and is not read as a request.
  > `bind_error_hint` explains `WSAEINVAL`, since on its own it is
  > undiagnosable.
  > **On Windows `SO_EXCLUSIVEADDRUSE` is set for *both* values of
  > `reuse_address`.** Setting it only for `True` would leave
  > `reuse_address=False` setting *nothing* -- and nothing is the unsafe state
  > there: a *more specific* `SO_REUSEADDR` bind takes traffic from a
  > non-exclusive wildcard holder. Reproduced: a thief on `127.0.0.1` received
  > the datagram while the holder on `0.0.0.0` got nothing and no error. So the
  > flag that reads as "strictest" would be the least strict one available.
  > `reuse_address` governs POSIX `SO_REUSEADDR` only;
  > `allow_address_takeover=True` is the single way to opt into a takeover.
- **`AddressInUseError(NetimpsError, OSError)`** — what `bind()` raises when the address is
  taken, on every platform and interpreter. The platforms surface that
  situation three ways: `PermissionError`/errno 13 on Windows 3.14,
  `OSError`/errno 10013 on 3.9, `OSError`/errno 10048 without
  `allow_address_takeover`. The first is actively misleading — Windows has no
  privileged ports, so a `PermissionError` there describes a mechanism that
  does not exist.

  `errno` is `EADDRINUSE`, the message is `bind_error_hint()`'s text, and the
  original exception is chained as `__cause__` (so `winerror` is still
  reachable). Subclasses `OSError` (and `NetimpsError`) but **not** `PermissionError`, so
  `except OSError` is unaffected while `except PermissionError` stops catching
  this. A real POSIX `EACCES` on a port below 1024 is untouched.

  A duplicate UDP bind is refused on every platform under the defaults — see
  the `reuse_address` box above. Sharing is opt-in through `reuse_port=True` or
  `allow_address_takeover=True`, and only then does a second bind succeed.
- **`SocketOption(level, name, value)`** — a named triple for `bind`'s
  `options=`. A `NamedTuple`, so it *is* a tuple: bare `(level, name, value)`
  tuples keep working and code that unpacks these does too. Purely so a list of
  them reads as something better than `Iterable[Tuple[int, int, Any]]`.
- **`disable_connreset(sock) -> bool`** — stop Windows reporting an ICMP
  port-unreachable provoked by an earlier send as `ConnectionResetError` on a
  *later, unrelated* receive, which kills a server's receive loop over a packet
  some other host did not want. Returns whether anything changed (`False` off
  Windows). `bind()` already applies it to every datagram socket it makes.

  This is the inverse face of a rule documented under `discover_mtu`: POSIX
  delivers asynchronous ICMP errors only to *connected* sockets, so the surprise
  does not arise there.

  **There is no stdlib route to it**, which is why it lives here. Measured on
  3.14: CPython exports no `socket.SIO_UDP_CONNRESET` on any version, and even
  given the documented value (`0x9800000C`) `socket.ioctl` **whitelists**
  commands and answers `ValueError: invalid ioctl command`. So this goes through
  `WSAIoctl` by `ctypes`. A `getattr(socket, "SIO_UDP_CONNRESET", None)` version
  — the obvious one — is a silent no-op on every platform.

  **A call, not a hidden side effect on a socket you made elsewhere.** The report
  is sometimes wanted: a client talking to one peer learns the peer is gone, so
  `bind(..., connreset=True)` keeps it. A server loop almost always wants it off.
- **`set_buffer_size(sock, *, receive=None, send=None) -> (receive, send)`** — grow
  `SO_RCVBUF`/`SO_SNDBUF` and report what was **granted**, read back with
  `getsockopt` rather than echoed from the request. Default UDP buffers are small
  (64 KiB on Windows), so a burst of large datagrams overruns them and the tail
  is dropped, which at the protocol level looks like loss and costs a timeout.

  **The kernel is not obliged to agree and does not say so**: `setsockopt`
  succeeds and then grants less, capped by `net.core.rmem_max` on Linux — which
  also *doubles* what is asked, so a read-back above the request is normal there
  and not a bug. The silent partial grant is the failure mode, hence the return
  value. Only ever grows, so it cannot undo earlier tuning; `None` skips a
  direction, and both `None` is a pure query. A shortfall is logged once per
  socket at `WARNING` on `logging.getLogger("netimps._sockets")`; no handler is
  installed.

  > **A link-local `interface=` address is bound with its zone.** The same
  > `fe80::` address can exist on several adapters, so the kernel cannot tell
  > which is meant from the address alone: BSD refuses the bare form with
  > "Can't assign requested address", while Windows and Linux happen to accept
  > it — which is why this only ever failed on macOS. The interface's index goes
  > in as the scope id, the same rule `UDPEndpoint.reply_socket` applies to a
  > link-local destination.

- **`bind_error_hint(exc, port=None) -> str | None`** — an actionable sentence
  for a bind failure, recognising POSIX errnos *and* Windows `10013`/`10048`.
  Returns `None` for anything unrecognised, so the caller keeps the original
  error. **Does not raise** — what to do with a failure is the caller's call.
  `bind()` already puts this text in its own exception; call this for an
  `OSError` from elsewhere.
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
- **`is_local_address(address) -> bool`** — true only for loopback or an
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
- **`get_source_ip(dst="8.8.8.8", port=80, *, ipv6=None) -> IPAddress | None`** —
  which local address the kernel would use to reach `dst`. `dst` accepts
  `HostLike`. **Sends no packets** — `connect()` on a UDP socket only
  consults the routing table. The answer depends on `dst`: with a VPN up, a
  public probe returns the tunnel address and a LAN probe the physical one.
  Correct where hostname resolution picks a VM adapter. `ipv6=` selects the
  family; it is not guessed from `":" in dst`, because **a hostname never
  contains a colon** and every name would be probed as IPv4, a v6-only one
  answering `None`. The returned address carries **no `%zone`** — the zone
  identifies the adapter, and `get_interface` is the way back to it.
- **`get_free_port(src="127.0.0.1", *, family=None) -> int`** — bind port 0 and
  read it back. `src` is any `HostLike` and `family` follows it as `bind`'s
  does (an IPv6 address gives `AF_INET6`). **Inherently racy** — the port frees the instant it returns; if
  you can, bind port 0 in the server itself instead. `SO_REUSEADDR` is
  deliberately *not* set (it would hand back a `TIME_WAIT` port).
- **`tcp_check(dst, port, *, timeout=3.0) -> bool`** — the honest reachability
  test. Proves the handshake completed, not that the service is healthy; a
  filtered port is indistinguishable from a closed one.

  Never raises for a reachability *outcome* — refused, timed out, unresolvable
  and unreachable are all `False` — but two argument bugs are raised rather
  than answered: a network as `dst` (`TypeError`), and a `port` outside
  `0-65535` (`ValueError`) or not an `int` (`TypeError`).

  **`timeout` bounds the whole call**, across every address `dst` resolves to.
  `socket.create_connection` would apply it once *per resolved address* after
  an unbounded `getaddrinfo`, so a name with N addresses could take
  N × `timeout`; here resolution happens once and the connects share one
  deadline. `timeout=0` is **floored** to 0.05s
  rather than taken literally: `settimeout(0)` means non-blocking, which
  reported every open port as closed. `timeout=None` blocks.
- **`wait_for_port(dst, port, *, deadline=30.0, interval=0.1, timeout=None)`**
  — poll until it answers. Backs off, growing by half each round, to the larger
  of 1s and `interval`, so an interval above a second is never shortened. `deadline` bounds the whole wait
  and is honoured even when individual connects block — it cannot overrun by
  more than one attempt, because `tcp_check` bounds *itself* overall rather
  than per resolved address. `timeout` is one attempt's connect timeout and
  defaults to `interval` raised to at least 1s. An out-of-range `port` raises
  from `tcp_check`.

## Routing, hops and MTU

- **`get_route(dst="8.8.8.8", *, ipv6=None) -> Route`** — `.dst`, `.src`,
  `.gateway`, `.interface_index`, `.on_link`. **First hop only, deliberately**
  — that is available unprivileged everywhere, unlike the full path. Never
  raises for an unknown route; unknown pieces are `None`/`0`. A network as
  `dst` still raises `TypeError`. A hostname goes through `getaddrinfo`, so
  `ipv6=` selects which of its records the route is computed for;
  `gethostbyname` is IPv4-only, so through it an AAAA-only name would reach no
  lookup at all.

  Both families are looked up on every supported platform: `GetBestRoute2` on
  Windows (it asks the kernel which route *it* would pick, so the
  longest-prefix matching is not reimplemented), `/proc/net/route` and
  `/proc/net/ipv6_route` on Linux, and `route -n get` on macOS/BSD — the one
  platform where this runs a short-lived program (`route`, 5s cap), because
  there is no `/proc` to read. A missing or hung `route` gives `on_link=None`.
  Loopback short-circuits without running anything.

  > **`Route.on_link` is `Optional[bool]`**: `True` when no gateway is needed,
  > `False` when one is, and **`None` when the next hop could not be looked up
  > at all**. `gateway is None` would turn "we never looked" into a confident
  > `True` — on macOS, where the lookup has no source to read,
  > `get_route("1.1.1.1")` from a `192.168.64.3/24` host would report
  > `on_link=True`. `None` is falsy, so `if route.on_link:` takes the safe
  > branch; `route.on_link is True` is a question with an answer, and
  > `route.on_link is False` really means "through a router". A present
  > `gateway` wins over the recorded flag, since it is proof on its own.
  >
  > **Test `on_link` itself**, not `.gateway is None`, which cannot tell
  > on-link from unknown. `Route` is **hashable**, and `__eq__` compares `dst`,
  > `src`, `gateway`, `interface_index` and `on_link`.
- **`count_hops(dst, *, max_hops=30, timeout=1.0, allow_traceroute=True, ipv6=None)`**
  — uses raw-socket probes when permitted, otherwise drives the system
  `traceroute`/`tracert`, so it **works unprivileged**. Only the hop number and
  destination address are parsed, never localised prose. A missing or hung
  program gives `None`.
  `allow_traceroute=False` requires the in-process path and raises
  `PermissionError` instead. `ipv6=` picks the family and the probes follow
  (ICMPv6 with `IPV6_UNICAST_HOPS`, and the platform's v6 traceroute);
  `gethostbyname` is IPv4-only, so through it a v6 destination would return
  `None`, read as "never answered" rather than "never asked". **`None` means
  "no answer", never
  "unreachable"** — firewalls routinely drop ICMP even for an elevated process.
- **`discover_mtu(dst, *, low=576, high=9000, timeout=1.0, src=None, port=80, probe=True, method="icmp", tries=1, ipv6=None, ttl=None)`**
  — **measures** the path MTU by binary-searching probes, so packets really
  traverse the path. Returns the MTU **including headers**, comparable with
  `Interface.mtu`. The name is **resolved once**: the target, the family and the
  header overhead (28 bytes for IPv4, 48 for IPv6) come from that one answer,
  and `ipv6=` picks it.

  **The answer is a measurement, not `high`.** A path cannot be wider than the
  link it leaves by, so a probe at `high` that is answered does not end the
  search: it goes on up to that link's MTU (`Interface.mtu` of the outgoing
  interface; the loopback interface for a destination on this host). A `high`
  above that MTU is lowered to it. Only when the MTU cannot be read is `high`
  the ceiling, and a result equal to it means **at least `high`**. The platform
  `ping` has a largest probe of its own: a 65500-byte payload on Windows, and
  `net.inet.raw.maxdgram` on macOS and the BSDs (8192 on macOS 15.7); a UDP
  socket there stops at `net.inet.udp.maxdgram` (a 9216-byte payload). A local
  destination the search takes that far is reported at the loopback MTU (65535
  on Windows, 65536 on Linux, 16384 on macOS); any other path that reaches the
  limit is retried with `"udp"` and otherwise reported at the limit, meaning
  "at least".

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

  `tries=` and `ttl=` reach `ping` for the ICMP method; `ipv6=` applies to
  every method. `size` and `dont_fragment` are what the search varies, so they
  are not parameters and passing either raises `TypeError`. `probe=False` skips
  probing entirely and returns `get_pmtu` instead. `method` is
  `"icmp" | "tcp" | "udp"`.
- **`get_tcp_mss(dst, port, *, timeout=3.0, ipv6=None) -> int | None`** — the negotiated TCP
  maximum segment size. `ipv6=` picks the family a host name connects over, and a
  destination of the other family gives `None`. **Opens a real connection** to read it, then closes.
  MSS is normally the path MTU minus 40, so a reduced value signals a tunnel
  shrinking the path (measured: 1412 over a VPN on a 1500-MTU link, 32741 on
  loopback). `None` where `TCP_MAXSEG` is unavailable or the connection fails.
  This is what the two *kernels agreed*, not what a middlebox further along
  will pass.
- **`get_pmtu(dst, port=80, *, ipv6=None) -> int | None`** — a **lookup**, not a
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

  > **A `getattr(socket, "IP_MTU", None)` guard returns `None` everywhere**,
  > Linux included, because `IP_MTU`, `IP_MTU_DISCOVER` and `IP_PMTUDISC_DO`
  > are **not exported by CPython on any platform** (measured on 3.13 and
  > 3.14). The Linux numbers are named from `<linux/in.h>` instead.
  > `IPV6_PATHMTU` also returns a `struct ip6_mtuinfo` — a `sockaddr_in6`
  > followed by the MTU — not the bare int `IP_MTU` gives back, so reading it
  > as an int would decode the address family as the MTU.

> **These answer different questions.** On one real host the local link was
> 9000, `get_pmtu` returned `None`, and `discover_mtu` found the true 1500 — a
> bottleneck several hops away that nothing local could reveal. Use
> `Interface.mtu` for the local link, `discover_mtu` for the path.
>
> **Header sizes are family-aware.** IPv4 overhead is 20+8 (ICMP/UDP) or 20+20
> (TCP); IPv6 is 40+8 and 40+20. Assuming IPv4 on a v6 path under-reports by
> exactly 20 bytes.

## Scanning

- **`scan_ports(host, ports="common", *, timeout=1.0, workers=100) -> List[int]`**
- **`scan_hosts(network, port=None, *, ports=None, timeout=1.0, workers=100)`** —
  returns `[(address, [open_ports]), ...]` sorted by address, hosts with
  nothing open omitted.

`ports` accepts a **`PORT_RANGES` name** (`"common"`, `"well-known"`, `"all"`),
a **scheme name** resolved via `get_default_port` (`"https"` → 443), a number, a
numeric string, a **comma-separated string** of those (`"22,https,8000"`; spaces
around an item are ignored, repeats are scanned once, an empty item raises
`NetimpsValueError`), or any iterable mixing them. Range names win over scheme names
where they collide. `scan_hosts(port=...)` is shorthand for `ports=[port]` and
accepts a scheme name too; passing both raises `ValueError`.

- **Every port is validated to `0-65535`** and raises `ValueError` otherwise,
  instead of being masked to 16 bits, which would make
  `scan_ports(host, [p + 65536])` answer about `p`. An unknown scheme or range
  name raises `NetimpsValueError` (a `ValueError`).
- **An explicitly empty `ports` means "nothing to scan"** and returns `[]`. It
  does **not** fall back to the 36-port `"common"` set, which would sweep a
  network the caller just said to probe on no ports; `scan_hosts`
  distinguishes an empty list from omission.
- **`timeout` is floored to 50 ms**, once, by `tcp_check` — `settimeout(0)` is
  *non-blocking* and reported every port closed — and a **negative** `timeout`
  raises `ValueError`.
- **`host` is resolved once per scan**, not once per port. That is a
  correctness fix, not only a speed one: a rate-limited resolver turned open
  ports into "closed". A name that does not resolve returns `[]` after a single
  lookup; a name with several addresses is still probed on each.
- **`scan_hosts` refuses anything larger than /16** (IPv6 /112) **and any sweep
  of more than 4,194,304 probes** (hosts × ports): a /8 sweep is 16M addresses
  and a /16 over `"all"` ports 4.3 billion probes, a mistake rather than an
  intention. Both raise `ValueError` before the first probe; a /16 with the
  `"common"` ports (2.36M) is within the bound. The pool is fed as it runs, so
  memory does not grow with the sweep (a /22 with `"common"` peaks near 0.1 MiB).
  Only usable host addresses are probed — network and broadcast addresses are
  skipped.
- A **TCP** sweep, so a host answering on none of the probed ports does not
  appear — it is not ARP/ICMP discovery, and a firewalled host is
  indistinguishable from an absent one.
- Ordinary full connects: **no SYN/stealth scanning, no fingerprinting**.
  Connections are logged by the target like any other. Use on hosts you are
  responsible for.

## Multicast

- **`multicast_socket(group=None, port=0, *, interface=None, ttl=1, loop=True, bind=True, reuse=True, ipv6=None)`**
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
- **`join_group(sock, group, *, interface=None)`** / **`leave_group(...)`** —
  closing the socket drops membership too, so `leave_group` is only needed to
  leave while keeping the socket open.
- **`is_multicast(address: IPAddressLike) -> bool`** — `224.0.0.0/4` or
  `ff00::/8`; an interface is read as its `.ip`.
  **Unmaps first**, so a v4-mapped group answers the same on every interpreter: the
  stdlib only began delegating a mapped address's `is_*` properties to the embedded
  v4 address in **3.13**, so `IPv6Address("::ffff:224.0.0.1").is_multicast` is `False`
  on 3.9 and `True` on 3.14. A mapped group is a real group — it is how a dual-stack
  listener sees one.

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

## `FQDN` — domain names as a value type

**`FQDN(*parts)`** — a domain name with label algebra. Immutable, hashable,
ordered. Built from a dotted string or from separate labels, **leftmost first**:
`FQDN("www.example.com")`, `FQDN("www", "example", "com")`,
`FQDN("www", FQDN("example.com"))`.

- **The algebra is inverted from `pathlib`, and that is the one thing to get
  right.** DNS puts the *most* significant label last, so every borrowed name
  points the other way:

  | | `FQDN` | `pathlib.PurePath` |
  | --- | --- | --- |
  | `.name` | **leftmost** label (`www`) | rightmost component |
  | `.parent` | strips the **leftmost** (`example.com`) | strips the rightmost |
  | `/` | **prepends** (`FQDN("example.com") / "www"` → `www.example.com`) | appends |

  Assume pathlib semantics and you get all three backwards.
- **DNS vocabulary is primary; the pathlib spelling is an alias on the same
  value.** `.labels`/`.parts`, `.hostname`/`.name`, `.domain`/`.parent`,
  `.domains`/`.parents`, `.is_fully_qualified()`/`.is_absolute()`,
  `.with_hostname()`/`.with_name()`. `.tld` has **no** `.suffix` alias, on
  purpose: a filesystem suffix is part of a name (`.txt`) while a TLD is a whole
  label, so that analogy misleads.
- **The trailing dot is absoluteness, and it is part of identity.**
  `example.com.` is fully qualified; bare `example.com` is relative to the
  resolver's search list and can mean different things on different hosts — so
  `FQDN("example.com") != FQDN("example.com.")`, exactly as
  `Path("a") != Path("/a")`. Compare `.labels` when qualification is not what
  you mean. `fully_qualified()` and `relative()` convert.
- **An address literal is refused**: `FQDN("10.0.0.1")` and `FQDN("::1")` raise
  `ValueError`. This is a *name* algebra — labels, a parent domain, a TLD are
  things an IP does not have. Use **`Host`** for a value that may be either, and
  **`Host.fqdn()`** to narrow (an `FQDN`, or the name an address reverses to).
  Digit-heavy real names are fine: `4.3.2.1.in-addr.arpa` and `0.pool.ntp.org`
  both parse. The check runs after IDNA mapping, so fullwidth digits and the
  ideographic full stops (U+3002, U+FF0E, U+FF61) that spell `127.0.0.1` are
  also refused; those full stops separate labels.
- **A label is printable ASCII (0x21 to 0x7E) without a dot, and holds none of
  `: / ? # [ ] @`.** A space, a control character or a URL
  (`FQDN("http://example.com")`) raises `NetimpsValueError`. The wire entry
  (`decode`/`decode_at`) takes the same printable-ASCII rule without the
  delimiter exclusion, so whatever the constructor accepts, `decode(encode())`
  returns. Parts are `str` or `FQDN`: `bytes`, and an iterable item of any other
  type, raise `TypeError`. `/`, `child` and `with_hostname` raise
  `NetimpsValueError` for a result over 253 octets, and `encode()` for one over
  255 on the wire.
- **`.domain` is not the registrable domain.** `FQDN("example.com").domain` is
  `FQDN('com')`, a public suffix. Telling `example.co.uk` (registrable) from
  `co.uk` (not) needs the Public Suffix List, a sizeable data file with its own
  update cadence, and this package has **no hard runtime dependencies**. The gap
  is documented rather than papered over with a heuristic that handles `.com`
  and mishandles `.co.uk`.
- `.domain` returns **`None`** at the top rather than itself. `Path("/").parent`
  is `Path("/")`, which is right for a filesystem root and would make
  `while f.domain:` loop forever here. `.domains` gives the whole chain,
  nearest first.
- **Ordered on *reversed* labels**, so `sorted()` groups by TLD then registrant
  — `['a.com', 'b.com', 'a.org']`, not the text order `['a.com', 'a.org',
  'b.com']`. All four operators come from one key (reversed folded labels, then
  absoluteness), so the order agrees with `==`: `example.com` sorts before
  `example.com.`. `is_subdomain_of` and `relative_to` compare case-blind, and
  `relative_to` returns the remainder in this name's spelling.
- **Equality is case-insensitive** (RFC 4343) and `__hash__` agrees. It does
  **not** coerce a `str`, for the same reason `MACAddress` does not; use
  `FQDN.try_parse(text) == name`.
- **`name in domain` is containment, the DNS reading of `address in network`** —
  the stdlib idiom this package layers over:

  ```python
  FQDN("www.example.com") in FQDN("example.com")   # True
  "mail.example.com" in FQDN("example.com")         # True — str accepted
  FQDN("example.com") in FQDN("example.com")        # True — "at or under"
  ```

  **Inclusive**, where `.is_subdomain_of()` is strict: the pair mirrors `<=`
  against `<`, and a zone contains its own apex just as a `/24` contains its
  network address. Qualification is ignored, and anything unparseable answers
  `False` rather than raising, so it stays safe in a filter. It is **not** a
  label test — that is `"com" in f.labels`.
- **Text interop**: `str(f)` is the name (with its trailing dot if it has one),
  and `f + str` / `str + f` give a **plain `str`**, for building a URL or a log
  line without reaching for `str()` first. `FQDN + FQDN` raises and points at
  `/`, since concatenating two names as text yields
  `'www.example.comexample.com'`.
- **`.to_unicode()`** — the display form, decoding punycode back:
  `FQDN("münchen.de").to_unicode()` is `'münchen.de'` while `str()` is
  `'xn--mnchen-3ya.de'`. Labels are stored ASCII because that is what goes on the
  wire and what comparisons use. An undecodable label passes through unchanged.
- **`.encode() -> bytes`** / `bytes(name)` / **`.wire_length`** — the DNS wire
  encoding (`b'\x03www\x07example\x03com\x00'`), uncompressed, delegated to the
  package's own encoder so it cannot drift from what `resolve_wire()` sends.
  Always absolute; there is no relative wire form. `.wire_length` is the figure
  the **255**-octet protocol limit applies to, as against the 253 printable limit
  checked at construction — the gap being one length prefix per label plus the
  root.
- **`FQDN.decode(data) -> FQDN`** — a buffer holding exactly one name in wire
  form; **`FQDN.decode_at(data, offset) -> (FQDN, end)`** — a name inside a DNS
  message, following compression pointers with loop detection. `end` is the
  first byte after the name *in the record* (just past the two-byte pointer when
  the name was compressed), so parsing carries on from it. Both raise
  `DNSDecodeError` for a malformed name, a loop, a label over 63 or a name over
  255 octets, a label holding a byte an `FQDN` label cannot (a dot, a control or
  non-ASCII byte), or the root alone; `decode` also for trailing bytes. Wire
  names are absolute, so `FQDN.decode(v.encode()) == v` holds for a fully
  qualified `v`, and for a relative one the result is `v.fully_qualified()`.
- **`.is_hostname()`** — whether every label is legal RFC 1123 LDH (letters,
  digits, hyphens; no leading or trailing hyphen). **Narrower than what the type
  accepts, on purpose**: `_dmarc.example.com`, `_sip._tcp.example.com` and
  `_acme-challenge.example.com` are all real DNS names, so rejecting underscores
  at construction would make this useless for SRV, DMARC and ACME work. The
  constructor takes the broad DNS rule; this reports the narrow host rule.
- **`.is_wildcard`** — whether the leftmost label is `*`. A predicate only:
  there is deliberately **no `matches()`**, because DNS (RFC 4592) and TLS
  certificate matching (RFC 6125) disagree about whether `*.example.com` covers
  `a.b.example.com`, and choosing one silently would be wrong for half of
  callers. Build the rule you need from `.is_subdomain_of()` and `len()`.
- **`.common_ancestor(other)`** — the deepest domain enclosing both names, or
  `None` when they share no label. `FQDN("a.example.com")
  .common_ancestor("b.example.com")` is `FQDN('example.com')`.
- Other members: `.tld`, `len()` (label count, not characters), iteration and
  indexing over labels (a *slice* gives a plain tuple, since an arbitrary slice
  of a name usually is not one), `.child(*labels)` as the spelled-out `/`,
  `.is_subdomain_of()` (a name is **not** a subdomain of itself; qualification
  ignored), `.relative_to()` (raises `ValueError` if not under, and the result is
  never qualified), `.reverse()` (flips label order — **not** a reverse DNS
  pointer, which is built from an address; `netimps._dns._dnswire.reverse_name()` is
  that), and `parse`/`try_parse`/`is_valid` classmethods matching
  `MACAddress`'s: `FQDN.parse(text)` raises `NetimpsValueError` for bad text and
  `TypeError` for a non-`str`; `FQDN.try_parse(text, default=None)` answers
  `default` for bad text only.
- **Network methods are named as actions and can block.**
  **`.resolve(*, check=False, ipv6=None, ns=None, timeout=5.0, port=53,
  tcp=False, search=True, backends=None, source=None, cache=False, deadline=None) -> (FQDN, IPAddress | None)`**
  answers `(self, ip)`, the same pair `Host.resolve()` gives, so the two types
  interchangeable as `HostLike` answer `.resolve()` alike; `.ip(...)` with the
  same options is the second element. `.ping(**kw)` → `ping()`. DNS records of
  any type come from `resolve(name, rdtype)`, not from here. The options are
  documented under `Host.ip()`; a trailing dot survives the delegation, so a
  fully-qualified name still bypasses the search list. Unlike `Host.ip()`,
  nothing is memoised: this type is immutable, and a cache on it would be a lie
  about freshness.
- **Validation**: 253 printable octets for the name (not the oft-quoted 255 —
  the wire form spends an octet per label length prefix and one on the root) and
  63 per label; an empty name or an empty inner label (`a..b`) raises. Non-ASCII
  is IDNA-encoded via the standard library, which is **IDNA 2003**, not the
  IDNA 2008 of the third-party `idna` package.

**`FQDNLike`** — `Union[FQDN, str]`, the accepted-input union wherever a method
takes "another name".

## Broadcast and payload sizing

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

**`max_udp_payload(mtu, *, ipv6=False)`** — the largest UDP payload that fits
without fragmenting: `mtu - ip_header - 8`, so `1472` for a 1500 MTU and `1452`
for v6. Pair it with `Interface.mtu` to size a datagram to the interface it leaves
by.

- It takes an **`int`, not an `Interface`**, on purpose. `Interface.mtu` is
  `Optional[int]` and **Windows reports no MTU for the loopback adapter**, so
  whether to fall back to 1500 or to refuse is the caller's decision — accepting
  an `Interface` would hide it. (It also means MTU logic cannot be exercised on
  Windows loopback.)
- The v4 figure uses the **minimum** 20-byte header, so a packet carrying IP
  options can still fragment; subtract more if you set any. IPv6 counts its
  extension headers as payload, so 40 is exact only without them.
- Returns `0` rather than a negative for an MTU too small to carry anything.

## Ancillary data: `recvmsg` / `sendmsg` on every platform

CPython ships no `recvmsg`/`sendmsg` on Windows — not a missing constant but a
missing feature, so probing `socket` for it cannot help. These provide them
there via `WSARecvMsg`/`WSASendMsg`, and delegate to CPython's own methods
everywhere else. **Both address families, and both directions.**

**`recvmsg(sock, bufsize, ancbufsize=0, flags=0)`** → `(data, ancdata,
msg_flags, address)`, exactly CPython's 4-tuple. `ancdata` is a list of
`(cmsg_level, cmsg_type, cmsg_data)`. `address` is `(host, port)` for `AF_INET`
and `(host, port, flowinfo, scope_id)` for `AF_INET6`. On a **stream** socket
it reads with `WSARecv` on Windows: no ancillary data, address `None`.

**`sendmsg(sock, buffers, ancdata=(), flags=0, address=None)`** → bytes sent.
`buffers` is a *sequence* of bytes-like objects, not a bare `bytes` (passing
one raises `TypeError`, as CPython does). A v6 `address` may be a 2-, 3- or
4-tuple, and a `%zone` suffix on the host is honoured when `scope_id` is absent.

**`CMSG_LEN(length)`** / **`CMSG_SPACE(length)`** — native where CPython has
them, computed from `WSACMSGHDR` and pointer alignment on Windows. Size an
`ancbufsize` with `CMSG_SPACE`, never `CMSG_LEN`: the difference is the pad that
lets a *following* header start aligned, and omitting it silently truncates the
second cmsg.

**`has_recvmsg()`** → whether the above can actually run here. Prefer it to
`hasattr(socket.socket, "recvmsg")`, which answers a different question once the
patch below is installed.

**`patch_socket_module(enable=True, *, iov_max=None)`** → list of names changed;
`ValueError` for an `iov_max` below 1 **before** anything is installed.
**`is_socket_patched()`** → whether anything is installed right now. Importing
the package a second time in one process (a reloader, a test runner) is
harmless: the second copy treats the first copy's installed functions as its
own, never as the platform's.

> **Installing this patch changes what *other* libraries infer.** It is additive
> in *names* and therefore not additive in *behaviour*: code that tests
> `hasattr(socket.socket, "recvmsg")` or `getattr(socket, "CMSG_SPACE", None)` to
> decide whether it is on POSIX gets the POSIX answer on Windows. The
> normalisation above is what keeps such code from misparsing the payload, but it
> cannot fix a caller that reads a field Windows does not report — `ipi_spec_dst`
> comes back `0.0.0.0`, exactly as it already does on macOS.
>
> Known affected: **pydhcp 0.6.1 and earlier**, which read `ipi_spec_dst` for
> their `SERVER_IDENTIFIER`. **Measured, they receive but allocate and reply to
> nothing** — a zero-filled `spec_dst` does not degrade a caller that resolves
> its interface from that field, it silences it. `UDPEndpoint` is the
> supported way to get that address correctly on every platform. Set
> `NETIMPS_SOCKET_PATCH=0` to opt out entirely.

- **The patch is installed by default, at `import netimps`.** It adds
  `recvmsg`/`sendmsg` to `socket.socket` and `CMSG_LEN`/`CMSG_SPACE` to the
  `socket` module, so POSIX-shaped code runs unchanged on Windows. Opt out with
  **`NETIMPS_SOCKET_PATCH=0`** before the first import, or
  `patch_socket_module(False)` after it. The env var exists because the choice
  has to be expressible *before* import.
- **It also installs `os.sysconf` where the platform has none**, because
  patching `sendmsg` breaks an invariant the stdlib relies on: `sendmsg` and
  `os.sysconf` are both POSIX and have always travelled together, so
  `hasattr(socket.socket, "sendmsg")` has been a sound POSIX proxy. CPython's
  `asyncio/selector_events` reads exactly that way at import time and guards only
  `except OSError`, so with `sendmsg` present and `os.sysconf` absent
  **`import asyncio` died with `AttributeError`**.

  The shim answers **per name**, because the three stdlib callers guard
  differently and no single behaviour satisfies them: `asyncio` catches
  `OSError`, `concurrent.futures` catches `(AttributeError, ValueError)`, and
  `multiprocessing` catches `Exception`. Measured — raising `OSError` for
  everything rescues asyncio and breaks `ProcessPoolExecutor`; raising
  `ValueError` does the reverse. So `SC_IOV_MAX` returns a value and every other
  name raises `ValueError`, which is what POSIX does for an unrecognised name.

  `SC_IOV_MAX` is **1024** by default, tunable with
  `patch_socket_module(iov_max=...)`. It is a batch size, not a ceiling, and a
  choice rather than a measurement: Windows reports no buffer-count limit
  anywhere (1048576 buffers in one `WSASend` were accepted), and the system limit
  is not settable on POSIX either — Linux's is `#define UIO_MAXIOV 1024` in
  `linux/uio.h`, with no sysctl and no `/proc` entry. 1024 matches Linux so a
  caller batching by it behaves the same on both.
- **It is strictly additive and never replaces a native name**, so on Linux and
  macOS it is a verified no-op (`is_socket_patched()` is `False` there). If CPython
  ever ships `recvmsg` on Windows, it stands down by itself.
- **It installs all four names, not just `recvmsg`.** Windows has no
  `CMSG_SPACE` either, and the usual idiom is detect → size → receive; patching
  only the method would let the detection succeed and fail on the next line.
- **`netimps.recvmsg()` reports the platform's own bytes; the *patched*
  `sock.recvmsg` normalises them to the POSIX layout.** The split is the point:
  our own API is honest about the platform, while a caller reaching for
  `sock.recvmsg` is reaching for a method that only exists on POSIX, so it gets
  what POSIX would have put there. Installing the name without the layout is a
  half-impersonation, and the missing half is the one that makes POSIX-shaped
  code misparse.

  On Windows the patched method rewrites a v4 `IP_PKTINFO` payload from
  `{addr, ifindex}` (8 bytes) into `{ifindex, spec_dst, addr}` (12 bytes), with
  **`spec_dst` zero-filled**. The result is byte-for-byte what **macOS**
  produces — measured, `01000000000000007f000001` for a unicast to `127.0.0.1`
  on interface 1 — so this is an existing platform's behaviour rather than a
  fourth one. `spec_dst` is *not* a copy of `addr`: measured on Linux, for a
  broadcast the two genuinely differ (`spec_dst` is the local interface address,
  `addr` is `255.255.255.255`), and code reads `spec_dst` precisely to get the
  local address — so copying `addr` there would silently corrupt the one field it
  wanted. Zero is visibly wrong; `255.255.255.255` is not.

  The patched `sendmsg` accepts **either** layout, chosen by length, so what the
  patched `recvmsg` hands you can go straight back out. `UDPEndpoint` is
  unaffected either way: it calls the backend directly and carries its own
  layout table.

  The `cmsg_type` is left alone — 19 on Windows, 8 on Linux, 26 on macOS — so a
  caller comparing against `socket.IP_PKTINFO` matches the local number. v6
  `in6_pktinfo` is never touched: `{addr, ifindex}`, 20 bytes, identical on all
  three.
- **Through `netimps.recvmsg()` the layouts genuinely differ.** Measured on CI
  runners, one loopback datagram each:

  | platform | `cmsg_type` | bytes | v4 `in_pktinfo` layout |
  | --- | --- | --- | --- |
  | Linux | 8 | 12 | `{ifindex; spec_dst; addr}` |
  | macOS | 26 | 12 | `{ifindex; spec_dst; addr}` (same as Linux) |
  | Windows | 19 | 8 | `{addr; ifindex}` — **no `spec_dst`** |

  Faking one as the other would make correct-looking code read a *plausible
  wrong address* rather than fail honestly. Use `UDPEndpoint` if you want the
  difference handled for you. The v6 `in6_pktinfo` layout the three do agree on
  (`{addr; ifindex}`, 20 bytes), though the cmsg type does not — 50 on Linux, 46
  on macOS, 19 on Windows.
- **Do not probe `socket` for these constants and conclude a platform cannot.**
  CPython 3.9 on Windows exports no `IP_PKTINFO` at all, though Winsock supports
  it perfectly well at the documented value 19. macOS *does* export
  `IP_PKTINFO` (26), contrary to the usual "BSD needs `IP_RECVDSTADDR`" advice.
  `UDPEndpoint` uses the literal where the value is documented and stable and
  lets `OSError` from `setsockopt` be the real "unsupported" signal.
- Errors are CPython's: `BlockingIOError` on an empty non-blocking socket,
  `socket.timeout` when the socket's own timeout runs out (both on Windows
  too, where the call waits for readiness itself), and `OSError(ENOTSUP)` only
  where neither backend can serve it.
- A datagram too large for `bufsize` sets `MSG_TRUNC` in `msg_flags` rather than
  raising, because Winsock reports that as an error where POSIX sets a flag.

## UDP with arrival interface

**`UDPEndpoint(sock, *, pktinfo=True)`** — wraps a bound UDP socket so each
datagram reports which interface it arrived on. Essential for broadcast
protocols, where a wildcard-bound server otherwise cannot tell which network a
request came from.

`recv(bufsize=65535, *, resolve_interface=True) -> Datagram`, a `NamedTuple` of
`.data`, `.sender`, `.destination`, `.interface_index`, `.interface`,
`.control_truncated` and `.truncated`, plus the property `.is_unicast`
(`is_unicast(destination, interface)`, or `None` when `destination` is unknown
because there was no pktinfo). `send(data, dst, port, *, src=None) -> int` pins the
outgoing interface; `dst` accepts `HostLike` and `src` the usual loose
interface spec (`Interface`, MAC, adapter name or address). `close()` closes
the wrapped socket, and the endpoint is a **context manager**
(`with UDPEndpoint(bind("", 67)) as endpoint:`) and an **async context
manager** (`async with UDPEndpoint(bind("", 67)) as endpoint:`).

**`close()` and `await aclose()` are each complete on return** — the reader
thread, if `arecv` started one, has left and the socket is closed — **and
harmless when called again**, in either order. From a coroutine use `aclose()`:
`close()` joins the thread on the calling thread and so holds up every other
task on the loop until it has gone, while `aclose()` waits for it with the loop
running.

`recv` and `send` raise the builtin `TimeoutError` when a timeout set on the
wrapped socket expires, on every supported Python (before 3.10
`socket.timeout` is only an `OSError`, so it is translated).

- **One option per address family, and they are not spellings of each other.**
  `IP_PKTINFO` is the IPv4 option; setting it on an `AF_INET6` socket
  *succeeds* on Linux and then no cmsg ever arrives. The family selects the
  option to set (`IP_PKTINFO` / `IPV6_RECVPKTINFO`), the cmsg type to match
  (`IP_PKTINFO` / `IPV6_PKTINFO` — on Linux the v6 pair are distinct constants,
  49 and 50) **and** the struct layout (`in_pktinfo` is index-then-addresses,
  `in6_pktinfo` is the 16-byte address **first**, then the index). An IPv6
  endpoint therefore reports a real `interface_index`, `interface` and
  `destination`; reporting `0`/`None`/`None` while claiming `has_pktinfo`
  would be the failure of reading the v4 option on a v6 socket.
- **Two honest flags, decided once at construction from the socket's own
  family.** `has_pktinfo` — `recv` will report the arrival interface;
  `False`, never an optimistic `True`, whenever the option for *this* family is
  missing or refused. `has_src_pinning` — `send(src=)` can be honoured;
  `False` where there is no pktinfo cmsg for the family, or the socket cannot
  use it (see **FreeBSD** below).
- **FreeBSD, IPv4: no `IP_PKTINFO`, other options.** The arrival address and
  interface come from `IP_RECVDSTADDR` (7) and `IP_RECVIF` (20), so
  `has_pktinfo` is `True` there and `destination` and `interface_index` are
  filled. The source is pinned with a control message of number 7
  (`IP_SENDSRCADDR`), which the kernel accepts **only on an unconnected socket
  bound to the wildcard address** (errno 22 otherwise): `has_src_pinning` is
  `True` for such an endpoint and `False` for one bound to an address, where
  `send(src=)` sends unpinned. IPv4 has no pin by interface index there, so an
  `Interface` (or name or MAC) given as `src` pins that interface's IPv4 address,
  and a `src` naming no IPv4 address raises `ValueError`. A `src` of `0.0.0.0`
  is sent unpinned: the kernel refuses a zero source there (errno 22), and
  unpinned is what Linux and macOS make of one. IPv6 on FreeBSD works as on
  macOS.
- **Windows is supported, through `WSARecvMsg`/`WSASendMsg`.** Both flags are `True`
  there for v4, v6 **and** dual-stack `::`, on 3.9 through 3.14 — see
  **Ancillary data** above. `UDPEndpoint` calls
  that backend *directly* rather than the patched stdlib method, so
  `NETIMPS_SOCKET_PATCH=0` does not cost it pktinfo. The per-platform
  `in_pktinfo` layout difference is handled internally; this is the wrapper that
  exists so callers need not know it.
- **A v4 arrival on an `AF_INET6` endpoint always reports the v4-mapped form**
  (`::ffff:127.0.0.1`), on every platform. That takes work, because the
  platforms disagree: Linux and macOS carry the mapped address in the v6 cmsg,
  while Windows reports a *plain* v4 address at level `IPPROTO_IP` and is the
  only one that reports it at all — its v6 option delivers no cmsg for a v4
  arrival. On Windows the same datagram's `sender` is already mapped while its
  cmsg is not, so the two halves contradict each other until normalised.
- **One thing Windows cannot do: pin by interface index alone.** It sends a zero
  source address *literally* — measured, a pin of `0.0.0.0` arrives from
  `0.0.0.0` — where Linux reads zero as "kernel chooses". An index-only `src`,
  or a `src` of `0.0.0.0` or `::`, therefore raises `ValueError` there in either
  family, rather than sending from the wrong address. Pass an address-bearing
  `src`.
- **A dual-stack `AF_INET6` endpoint pins an IPv4 source** (plain or
  `::ffff:`-mapped) on Windows, Linux and, unmeasured, elsewhere; on Windows it
  is sent as an `IPPROTO_IP` control message.
- **`send` to a host name works pinned or not**, on Windows too: the name is
  resolved for the socket's family.
- **Degrades rather than failing**, where a platform still cannot serve it:
  `recv` falls back to `recvfrom` with empty interface fields, and `send` sends
  unpinned. Check the two flags rather than inferring from an empty result.
- **`pktinfo=False` governs receiving only.** Sending needs no socket option,
  so `send(src=)` is still honoured on an endpoint built with it.
- **`send(src=)` pins the interface index as well as the source address.** The
  A fixed `ipi_ifindex=0` would only ever pin an address. It
  raises `ValueError` for a `src` that names no local address or interface
  (silently sending from another adapter is the failure mode `src` exists to
  prevent) and for an IPv6 `src` on an `AF_INET` endpoint — Linux *accepts and
  ignores* a v6 cmsg on a v4 socket, so there is no correct silent behaviour
  available. An `OSError` from the kernel, meaning a source this host cannot
  send from, propagates; only platform incapability degrades to `sendto`.
- **`async arecv(bufsize=65535, *, resolve_interface=True)`**,
  **`async asend(data, dst, port, *, src=None) -> int`** and
  **`datagrams(bufsize=65535, *, resolve_interface=True, on_error=None) ->
  AsyncIterator[Datagram]`** — `recv()` and `send()` awaited, and an `async for`
  over arrivals:

  ```python
  async for packet in endpoint.datagrams():
      with endpoint.reply_socket(packet) as reply:
          reply.sendto(answer(packet), packet.reply_address)
  ```

  `datagrams()` stops at the first receive error, closing the loop's `async for`
  with that exception: a loop that swallows errors is how a dead server looks
  healthy. `on_error` opts out per error: it is called with the exception and
  returns true to carry on with the next datagram, false to stop with that error.
  The caller decides, so log or count inside it. The error a `close()` causes
  ends the loop quietly and does not reach it.

  **Closing ends a pending wait.** `close()` or `aclose()` from another task
  wakes a task in `arecv` with `RuntimeError` and finishes a `datagrams()` loop,
  with the reader unregistered, on every loop type. **The socket's timeout is
  never changed**: `arecv` and `asend` make one call non-blocking and restore
  the timeout afterwards, so `gettimeout()` is the same before and after and a
  later `recv()` waits as it always did. `asend` waits for writability, with the
  loop free, when the kernel's send buffer is full.

  **Pktinfo survives on every loop type**, which is not free. The Windows default
  `ProactorEventLoop` raises `NotImplementedError` from `add_reader`, and its own
  `recvfrom` discards ancillary data; `_overlapped` exposes no `WSARecvMsg`, so
  there is no IOCP route without private API, and
  `DatagramProtocol.datagram_received(data, addr)` has no slot for cmsgs. So on
  such a loop a thread waits — and it **reports readability only, never reads**.
  The `recv` stays on the loop, so `bufsize` is still per call and
  `.truncated` still means what it says.

  One waiter at a time: this is a receive loop's method, and two coroutines
  awaiting one endpoint would race for the same datagram however the waiting were
  arranged. The thread, where there is one, is created on the first `await` and
  joined by `close()` or `aclose()`. `recv()` is unaffected — the synchronous path is untouched.

  **Cancelling the awaiting task is a clean shutdown**, which is the ordinary
  server one: cancel the receive task, then close the endpoint. A cancelled
  `arecv` unregisters its reader, so the loop is not left watching a socket that
  is about to close. Closing first and cancelling after is just as clean: the
  reader is removed by the descriptor it was registered under.

  **A second loop rebinds.** Serving one endpoint from a new loop —
  `asyncio.run(serve())` twice, or a server stopped and started again — retires
  its thread and starts another. A thread keeps the loop it started with, so
  without the rebind the second run would receive nothing and the thread would
  die posting to a closed loop, with the traceback going to stderr where no
  caller could see it.

  **`asyncio` is imported lazily**, never by `import netimps`. A caller using
  only the value types pays nothing for it.
- **`has_pktinfo(family=AF_INET) -> bool`** — whether a UDP socket of that
  family (`4`/`AF_INET` or `6`/`AF_INET6`; anything else raises `ValueError`) can report each datagram's arrival interface *on this host*. The
  question to ask **before** choosing how to bind: with it, one wildcard socket
  serves every address and still knows which one a datagram reached; without
  it, the wildcard has to be expanded into a socket per address — and on Linux
  that per-address socket receives no broadcasts at all.

  ```python
  socks = [bind("", 67)] if has_pktinfo() else [bind(str(a), 67) for a in addrs]
  ```

  **Decided by asking a socket, never by testing a constant's name.**
  `getattr(socket, "IP_PKTINFO", None)` is `None` on CPython 3.9–3.11 on *every*
  platform — the constant arrived in 3.12 — while the kernel supported it
  throughout, so a name test answers "no" on a platform that works. Cached per
  family for the process, since it is a property of the platform and the
  interpreter rather than of any socket. `False` rather than an exception when a
  socket of that family cannot be created, so IPv6 being disabled is an answer
  and not an error.
- **`reply_socket(datagram, port=0, *, connreset=False)`** — a socket bound so
  replies leave from the address the client addressed. The point of pktinfo, in
  one call:

  ```python
  packet = endpoint.recv()
  with endpoint.reply_socket(packet) as reply:
      reply.sendto(answer, packet.reply_address)
  ```

  A wildcard-bound server answering from a fresh socket sends from whatever the
  routing table prefers; DHCP and TFTP clients both check and drop a reply from an
  address they never addressed. Measured contrast: a plain wildcard reply to a
  client that addressed `127.0.0.2` comes from `127.0.0.1`.

  Three traps it absorbs:
  - **A v4 arrival on a dual-stack listener is `::ffff:a.b.c.d`.** Binding that
    needs an `AF_INET6` socket with `IPV6_V6ONLY` off, which Windows does not
    default to — so it is unmapped and answered from a plain `AF_INET` socket.
  - **A broadcast, multicast or unspecified destination must not be answered
    *from*.** These are **classified and skipped**, not discovered by a failed
    bind, because the platforms disagree: Linux binds `255.255.255.255` and
    `239.1.2.3` happily while Windows refuses both, so relying on the refusal
    would mean replying *from* the broadcast address on Linux. The subnet case
    needs interface prefixes, which is what `is_broadcast` supplies.
  - **An IPv6 link-local destination needs a scope id**, taken from
    `datagram.interface_index` and carried as a `%zone` suffix, or the bind is
    refused — the same address can exist on several interfaces and the kernel will
    not guess.

  > **The *sender's* family decides the reply socket's, not the listener's**, and
  > `datagram.reply_address` is what you pass to `sendto`. A dual-stack
  > `AF_INET6` listener sees a v4 client as `::ffff:a.b.c.d`, and deciding
  > from anything else goes wrong in both halves. With pktinfo the `AF_INET`
  > socket is right but `datagram.sender` is still the v6 4-tuple, so the
  > `sendto` shown above raises `TypeError: AF_INET address must be a pair
  > (host, port)`. Without pktinfo there is no `destination`; falling back to
  > the *listener's* family gives an `AF_INET6` socket with `IPV6_V6ONLY=1` on
  > Windows (the platform default, which `bind()` does not clear) — so `sendto`
  > to a mapped address fails with `WinError 10049` and the exchange silently
  > never starts. Deciding from the sender makes the answer the same with or
  > without pktinfo, and `reply_address` gives the peer in the family that was
  > chosen.

  Falls back to the endpoint's own bound address, then the wildcard: a reply from
  the wrong address still beats no reply. The own-address fallback is skipped
  when it is in the wrong family, so a v6 wildcard listener answering a v4 client
  goes to the v4 wildcard rather than offering `::` to an `AF_INET` socket. `connreset=False` by default, as `bind()` does for a datagram socket,
  because a server loop must not die when an earlier answer draws an ICMP
  port-unreachable from a client that has gone.

  **`port` also takes any iterable of ports**, tried in order, for a server that
  pins transfer ports to a range a firewall can allow (`tftp-hpa -R`,
  `dnsmasq --tftp-port-range`). The iterable is materialised once, so a generator
  is safe but must be finite; empty raises `ValueError`.

  > **A held port and an unusable address are different failures, and they move
  > in different directions.** An address that cannot be bound at all advances to
  > the next *address*; a port that is merely held advances to the next *port* on
  > the same address. Conflating them is a silent correctness bug: if every
  > `OSError` advanced the address, a taken `port=` would fall through to the
  > endpoint's own address **with the same port**, and where that bind
  > succeeded the reply would leave from an address the client never
  > addressed — the one failure this method exists to prevent. Measured on
  > Windows 11 ARM64: holding `10.6.0.223:57014`
  > and replying to a datagram that arrived there returned a socket on
  > `127.0.0.1:57014`. So when the ports run out on an otherwise bindable
  > address, this raises **`AddressInUseError`** and binds nothing, rather than
  > answering from somewhere else.
- **The arrival interface is cached per endpoint**, so the default path is not
  the slow one. Calling `get_interfaces()` and scanning it for *every*
  datagram costs 1.07 ms per packet against 0.015 with
  `resolve_interface=False`, a 70x cost, and 35–42 ms per enumeration on a host
  with many adapters. So `recv()` keeps an `index -> Interface` cache refreshed
  on a miss and on a 30-second TTL — 0.017 ms per packet, one enumeration for
  ten datagrams.
  A miss triggers a refresh because an unseen index means the adapter set
  changed; negative results are cached so a vanished index does not re-enumerate
  forever. `resolve_interface=False` still skips it entirely and never
  enumerates.
- **`reply_address`** — `sender`, in the family `reply_socket` will use. **Pass
  this to `sendto`, not `sender`.** A v4-mapped sender becomes the plain
  `(host, port)` pair, dropping the flowinfo and scope id that an `AF_INET`
  `sendto` rejects outright; everything else is returned unchanged, including a
  link-local peer's scope id, so it is also the right thing to pass on a
  single-family listener.
- **`truncated`** reports `MSG_TRUNC`: the **payload** did not fit `bufsize`
  and `.data` is the leading part of a longer datagram. A different question
  from `control_truncated`, and the one that silently corrupts a decode — a
  protocol parser handed a message cut mid-field reports a malformed packet
  rather than a short read. Measured on Linux with `bufsize=576`: a 1102-octet
  datagram arrived with the flag set and the flag discarded, leaving the caller
  nothing to check. **Reported, not raised**: deciding that a short datagram is
  fatal belongs to the protocol, not here. It is reported on the no-pktinfo path
  too, which goes through `recvmsg` with a zero-length control buffer rather than
  `recvfrom` precisely because `recvfrom` cannot report it — losing the interface
  is a documented degrade, losing this is silent data loss. **Windows included**:
  a bare `sock.recvfrom(576)` of a larger datagram raises `WinError 10040`
  (`WSAEMSGSIZE`), while `recv()` returns the first 576 octets with
  `truncated=True`, so no `WSAEMSGSIZE` handling is needed around it.
- **`control_truncated`** reports `MSG_CTRUNC`: the kernel had more ancillary
  data than the buffer held. When it is `True` and the interface fields are
  empty, they are empty because something was dropped. The buffer is sized for
  four cmsgs rather than one, so an unrelated option on the raw socket
  (`SO_TIMESTAMP`, `IPV6_RECVHOPLIMIT`) does not silently swallow the
  pktinfo — measured on Linux, where a one-slot buffer kept the timestamp and
  discarded the pktinfo.
- **A dual-stack `AF_INET6` socket needs only its own option.** An IPv4 arrival
  then reports the v4-mapped form (`::ffff:10.0.0.1`) in both `.sender` and
  `.destination`.
- `.destination` for a broadcast is the **broadcast** address, not the
  interface's own — use `.interface` to identify the adapter.
- Pass `resolve_interface=False` in a hot loop and use `.interface_index` —
  enumeration is a syscall. Resolving a MAC or an adapter name in `send(src=)`
  enumerates too; pass an `Interface` in a send loop to avoid it. A `src` that is
  an **address** is used as given and enumerates nothing — the kernel then picks
  the adapter (a `%zone` still names one), so pass an `Interface` when the adapter
  must be pinned as well.
- Wraps rather than subclasses the socket; the raw one stays on `.socket`.

## Retry

**`retry(func: Callable[[], T], attempts=3, *, delay=0.5, multiplier=2.0, max_delay=30.0, jitter=0.1, retryable=(OSError,), on_retry=None, jitter_seconds=None, symmetric=False) -> T`**

Calls `func()`, retrying transient failures with exponential backoff. Returns
whatever `func` returns (the return type is `func`'s); if every attempt fails **the last exception is
re-raised unwrapped**, so the traceback still points at the real problem.

- **Only `OSError` is retried by default** — that covers the socket family and
  so `ResolutionError`, an outage. A `ValueError` means the call is malformed and
  will fail identically, so it propagates immediately. `NoAnswerError` (a name
  that does not exist) is an `OSError` as well; to leave it out, name the types
  to retry instead of `OSError` itself, e.g.
  `retryable=(ConnectionError, TimeoutError)`.
- `attempts` counts *total* calls: `attempts=1` calls once and never sleeps.
- **Arguments are checked when `retry`, `backoff_delays` or `Backoff` is called**,
  by one rule set, and raise `ValueError`: `attempts` below 1 (not for
  `Backoff`, which has none), a negative `delay`, a `multiplier` below 1, a
  `max_delay` below `delay`, a `jitter` outside 0 to 1, a negative
  `jitter_seconds`. `backoff_delays` does not defer them to the first `next()`.
- `jitter` spreads retries so simultaneous failures do not resynchronise into a
  thundering herd. Applied **after** the cap and only ever shortens, so
  `max_delay` is a real ceiling.
- `on_retry(attempt, exc, next_delay)` is the logging hook; this logs nothing
  itself.
- Synchronous — it blocks. For async, drive **`backoff_delays(...)`** from your
  own loop; it yields the same schedule, `attempts - 1` values.

**`backoff_delays(attempts=3, delay=0.5, *, multiplier=2.0, max_delay=30.0, jitter=0.1, jitter_seconds=None, symmetric=False)`**

Two **opt-in symmetric modes** sit alongside the default, because a protocol's
own specification can require what the default forbids — it only ever *shortens*
a delay, so neither DHCP standard can be expressed with it:

- **`jitter_seconds=`** — absolute and symmetric, uniform in
  `[-jitter_seconds, +jitter_seconds]`. **RFC 2131 §4.1** (DHCPv4) asks for the
  delay to be "randomized by the value of a uniform random number chosen from
  the range -1 to +1" — seconds, not a fraction. Overrides `jitter`. The
  amplitude is capped at the current delay so the value cannot go negative
  before clamping; uncapped, a sub-second delay would have most of its
  distribution piled on a single clamped value, which is neither uniform nor
  symmetric. At RFC 2131's own 4 s floor against a 1 s amplitude the cap never
  engages.
- **`symmetric=True`** — spreads the fractional `jitter` both ways,
  `delay * (1 ± jitter)`. **RFC 8415 §15** (DHCPv6) specifies
  `RT = 2*RTprev + RAND*RTprev` with `RAND` uniform in `[-0.1, +0.1]`.

> **In the symmetric modes `max_delay` caps the *base*, not the final value**,
> so a delay may exceed it by up to the jitter amplitude. Both RFCs require
> that: RFC 8415 applies its jitter *after* the cap (`if RT > MRT: RT = MRT +
> RAND*MRT`) and RFC 2131 randomises ±1 s around its 64 s maximum. Clamping is
> the obvious reading and is wrong invisibly — measured, the spread *at the cap*
> became entirely negative with a mean of −0.024 instead of ~0, because every
> positive excursion was trimmed back. A backed-off client spends nearly all of
> its time at the cap, so that is exactly where the symmetry has to survive.
> **No mode ever returns a negative delay**, and the default mode's hard ceiling
> is unchanged.

**`Backoff(delay=0.5, *, multiplier=2.0, max_delay=30.0, jitter=0.0, jitter_seconds=None, symmetric=False)`**

A **retransmission timer**: grows on loss, **resets on progress**. This is the
shape `backoff_delays` cannot express, and the one every protocol client in this
family had hand-rolled:

```python
timer = Backoff(delay=timeout, max_delay=timeout * 8)
while not done:
    deadline = now() + timer.delay
    if replied:
        timer.reset()        # progress: back to the base
    elif timer.attempt >= retries:
        raise TransferTimeout(...)
    else:
        timer.advance()      # loss: back off
```

`backoff_delays` is a one-shot schedule for "retry this call a few times"; a
long-lived session instead needs a current delay that advances on silence and
returns to the base the moment the peer moves the transfer forward.

- **`.delay`** is **stable between `advance()`/`reset()` calls**, so arming a
  deadline, logging it and comparing against it all see one value. A property
  that re-jittered on each read would be a trap for exactly the code this
  exists for.
- **`.advance()`** backs off one step and returns the new delay; **`.reset()`**
  returns to the base; **`.attempt`** counts advances since the last reset.
- **Jitter is off by default here**, the opposite of `backoff_delays`. Jitter
  desynchronises many clients retrying together, and a point-to-point session
  retransmitting to one peer has no herd to avoid — TFTP and TCP both specify
  plain doubling. The symmetric modes are there for the protocols that do ask.
- Two guard rails a hand-rolled version tends to miss, both refused with
  `ValueError` when the timer is built: a `multiplier` below `1`, which would
  *shrink* the wait on repeated loss, and a `max_delay` below `delay`, which
  would truncate the first wait. `backoff_delays` and `retry` refuse the same.

## Host

**`Host(value)`** — a host named by either an address or a hostname. `value`
is `HostLike` or `None`: an interface is reduced to its address as every `dst`
parameter does (`Host(IPv4Interface("127.0.0.1/8"))` is `Host('127.0.0.1')`), and
a network raises `TypeError`.

`str(host)` is **always the original text**, so a URL can still be rebuilt when
resolution fails: a failed lookup returns `None` for the address and the
`Host` keeps the name.

Which call looks anything up:

| Call | host is a name | host is an address |
| --- | --- | --- |
| `.ip()` | forward lookup | the literal, no lookup |
| `.fqdn()` | the name as written, no lookup | reverse lookup |
| `.resolve()` | `(name, forward lookup)` | `(reverse lookup, literal)` |

- `Host.parse(text)` / `Host.try_parse(text, default=None)` — text only
  (`TypeError` otherwise); the one text refused is empty or blank, with
  `NetimpsValueError`. The constructor is the lenient entry: it takes `None`,
  `""` and any object, and keeps its text.
- `.is_address` — already a literal, no DNS needed.
- **`.fqdn(*, check=False, <resolver options>) -> FQDN | None`** —
  this host as an **`FQDN`**: the name itself, or the name an address reverses
  to (without its root dot). The bridge between the two types: `Host` is the
  union "address *or* name", while `FQDN` is the name algebra that refuses an
  address outright. `Host("www.example.com").fqdn().domain` →
  `FQDN('example.com')` with no I/O. A name is returned **as written**, not as
  the canonical name after search-list expansion. `None` when no name was found
  or the text is not a possible name; `check=True` raises `NoAnswerError` for
  the first (a reverse lookup that completed with no name; an outage is a plain
  `ResolutionError`) and `NetimpsValueError` for the second. `ipv6` is accepted and
  unused, so one options dict serves all three methods. Not memoised.
- **`.ip(*, check=False, ipv6=None, ns=None, timeout=5.0, port=53, tcp=False,
  search=True, backends=None, source=None, cache=False, deadline=None, refresh=False) -> IPAddress | None`**
  — a literal as parsed, a name looked up. `ipv6=True` asks for AAAA, `False`
  for A, `None` for either in one lookup, in the OS's own order. `check=True`
  raises instead of returning `None`: `NoAnswerError` for an empty answer, a
  plain `ResolutionError` (or `ResolutionTimeoutError`) for a resolver outage or
  an empty host (`resolve(strict=True)` alone re-raises only the outage). **With none of `ns`, `port`, `tcp`, `source` or `backends`, the
  OS resolver alone answers**, as the standard library's lookups do: a missed
  name costs milliseconds, where the full chain behind `netimps.resolve` costs
  seconds. Naming any of them selects `resolve()`'s own chain rules. `timeout`
  and `search` apply either way. Every option is keyword-only.
- **A call that passes no option memoises its answer, a miss included**, since
  the common use is several lookups on one object. A call that passes any
  option neither reads nor writes the memo; `refresh=True` asks again and
  replaces it, since a name that failed once may resolve later.
- **`.resolve(*, check=False, ipv6=None, <resolver options>) -> (FQDN | None,
  IPAddress | None)`** — the pair `(fqdn, ip)`, always a pair, so
  `fqdn, ip = host.resolve()` never fails to unpack; a half that was not found
  is `None`, or raises with `check=True`.
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
  of its two), `mtu`, `scan`, `addr` and `split`, so `netimps ping` is not an
  answer about the empty string; a missing one is argparse's usage error on
  stderr with exit 2. `route` and `source` default to `8.8.8.8`.
- **Three exit statuses, one meaning each, as `grep`**: `0` found or yes,
  `1` nothing found or the answer was no (unreachable, closed, no records, no
  such interface, no route, no mapping, no open port or host), `2` an error:
  bad input (a bad argument, a missing positional, `--method tcp` with no
  `--port`, a scheme with no port, a port outside `0-65535`), a missing
  program, an outage the command could not answer through. A `ValueError` or
  `ResolutionError` out of the library becomes `error: <message>` on stderr
  with status 2, never a traceback; a usage error from the parser is status 2
  too. `route`, `addr` and `split` always answer or fail: they have no "no".
- **`-q` is for scripts: no result line, the status alone**, as `grep -q`.
  Errors (status 2) still go to stderr; the diagnostic that goes with a "no"
  (`no interface named ...`, `no route to ...`) is dropped. `--json` output is
  not affected by `-q`. `-q` also lowers the log level as `duho`'s `-q` does,
  and `-v` still raises it; `-q` given at all is what silences the line.
- **JSON shapes** (a contract; keys do not change):
  - `interfaces`: a list of `{name, index, mac, mtu, is_loopback, addresses,
    is_up, raw}` (`raw` is `null` without `--raw`).
  - `ping`: `{ok, host, rtt_ms, ttl, attempts, method}`; `rtt_ms` is
    milliseconds (the library's `PingResult.rtt` is seconds).
  - `resolve`: a list of record strings.
  - `check`: `{ok, host, port}`.
  - `route`: `{dst, src, gateway, interface_index, on_link}` plus `hops` with
    `--hops`; `on_link` is `true`, `false` or `null`.
  - `mtu`: `{dst, mtu, method}` plus `mss` for `--method tcp`; `mtu` is `null`
    for no answer.
  - `scan`: a host target gives `{host, ports}`; a network target gives a list
    of `{host, ports}`.
  - `addr`: `{kind, value, ...}` with `kind` `mac` (`oui`, `is_multicast`,
    `is_local`), `network` (`network_address`, `netmask`, `num_addresses`,
    `version`; an address with a prefix is shown as its network) or `address`
    (`version`, `is_private`, `is_global`, `is_loopback`, `is_multicast`,
    `is_link_scoped`, `reverse_pointer`).
  - `source`: `{dst, src}`.
  - `port`: `{free_port}` with no argument, `{port, scheme}` for a number,
    `{scheme, port}` for a name; the missing half is `null`.
  - `split`: `{host, port}`; `port` is `null` without one.
- **`netimps port <unknown>` exits 1**: a lookup that found no mapping is an
  *answer*, the way an empty `resolve` is, and a valid port with no
  registered scheme is no caller mistake. Which ports have one depends on the
  host's services database: `9999` has none on Linux and Windows and is
  `distinct` on macOS. A port outside
  `0-65535` exits 2. `netimps check <host> <unknown-scheme>` exits 2, because
  there is then no port to connect to and nothing was tested.
- `netimps route` prints an `on-link  <True|False|unknown>` line and renders a
  missing next-hop lookup as `gateway  (unknown)` rather than
  `(on-link, no router)`; `--json` accordingly has `"on_link": null` as a third
  possible value.
- The entry point is `netimps.cli.main(argv=None) -> int` (the console script
  and `python -m netimps` call it; it never returns `None`). `netimps.cli` is
  the one public submodule and is not part of the root `__all__`.

## Constants

- **`get_hostname(*, fqdn=False)`** — a function, not a constant: this
  machine's name from `platform.node()`, asked for when called and never at
  import. `fqdn=True` returns `socket.getfqdn()`, which may consult the
  resolver.
- **`PORT_RANGES`** — `{"well-known", "common", "all"}` port tuples;
  `"common"` holds 36 ports.
- **`LINK_LOCAL_V4`** (`169.254.0.0/16`), **`LOOPBACK_V4`** (`127.0.0.0/8`),
  **`LOOPBACK_V6`** (`::1/128`), **`LINK_LOCAL_V6`** (`fe80::/10`) — named
  networks, so callers stop spelling the literals out.
