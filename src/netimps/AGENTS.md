# `netimps` — public API header

Header-file-style reference for the `netimps` package: every public export with
its signature, arguments, contract and gotchas, so the package can be used
without reading its source. It ships inside the package and is self-contained,
with `README.md` beside it as the overview (read either with
`importlib.resources.files("netimps")`). Development documentation lives with
the source at <https://github.com/jose-pr/netimps>.

Everything is imported from `netimps` directly. Every other module and package
under `netimps` (each name starting with `_`) is implementation detail —
**do not import them**. The one public submodule is `netimps.cli`, whose entry
point is `netimps.cli.main`; it is not part of the root `__all__`.

Install with `pip install netimps`, which has no hard dependencies. The `dns`
extra (`pip install "netimps[dns]"`) adds `dnspython`, the backend that serves
every record type and takes `ns=`/`search=` control; the `cli` extra
(`pip install "netimps[cli]"`) adds `duho`, which the `netimps` command needs.
Importing `netimps` never requires either. Python 3.9 or newer.

`netimps.__version__` — the package version string, the same value the
installed distribution's metadata carries.

A large topic keeps its public names here, each with its signature and one
sentence, and its detail in the `AGENTS.md` beside the code that implements it.
Those headers are part of the installed package; read one with
`importlib.resources.files("netimps")` and the path below.

| Header | Covers |
| --- | --- |
| `netimps/AGENTS.md` | this file: conventions, types, parsing, `MACAddress`, the scheme registry, scanning, multicast, retry, the exceptions, the command line's contract, the environment variables |
| `netimps/_dns/AGENTS.md` | `resolve` and its five backends, the answer cache |
| `netimps/_ping/AGENTS.md` | `ping` and `PingResult` |
| `netimps/_sockets/AGENTS.md` | `bind`, socket options, source IP, free port, TCP checks, routing, hops, path MTU, payload sizing |
| `netimps/_ifaddrs/AGENTS.md` | `Interface`, `get_interfaces` and its cache, interface lookups, broadcast and unicast tests |
| `netimps/_ip/AGENTS.md` | address and network helpers, host and zone splitting, `Host` |
| `netimps/_fqdn/AGENTS.md` | `FQDN`, the domain-name value type |
| `netimps/_msg/AGENTS.md` | `recvmsg` and `sendmsg` on every platform, the `socket` patch |
| `netimps/_udp/AGENTS.md` | `UDPEndpoint`, `Datagram`, arrival interface, source pinning, reply sockets |
| `netimps/_listen/AGENTS.md` | `parse_listen`, `ListenAddress`, `ListenLike`: the grammar of where a service listens |
| `netimps/cli/AGENTS.md` | the commands, their JSON shapes and their diagnostics |

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
| `ListenLike` | nothing, one binding or a sequence of them (text, an address, an `Interface`, a `MACAddress`, a `ListenAddress`, a `(host, ports)` pair) -- where a service listens: `parse_listen(listen=)` |
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

Adapter names, MACs, MTU and real prefix lengths through `getifaddrs(3)` or
`GetAdaptersAddresses`, with no third-party dependency, and an opt-in cache for
a per-packet lookup. Detail: `netimps/_ifaddrs/AGENTS.md`.

- **`get_interfaces(*, raw=False, cache=False) -> List[Interface]`**
  — every adapter, as a list of `Interface`.
- **`Interface`** — one adapter, read-only and hashable: `.name`, `.index`,
  `.mac`, `.ips`, `.ipv4`, `.ipv6`, `.mtu`, `.is_up`, `.is_multicast`, `.is_point_to_point`, `.is_loopback`, `.raw` and
  **`Interface.primary_ip(ipv6=False, *, loopback_ok=True)`**, which picks one
  address from `.ips`.
- **`iter_addresses(interfaces=None, *, family=None, cache=False)`**
  — the flattened `(interface, address)` view, one entry per address.
- **`get_interface(query=None, *, index=None, strict=True, cache=False) -> Interface | None`**
  — the first adapter matching an address, network, MAC, adapter name or index.
  Several adapters can share a MAC (teamed or virtual ones): this returns the
  first in enumeration order, and `iter_interfaces(mac)` yields them all.
- **`iter_interfaces(query=None, *, index=None, cache=False) -> Iterator[Interface]`**
  — every match for the same queries.
- **`is_local_address(address, *, cache=False) -> bool`** — true only for
  loopback or an address assigned to a local adapter.
- **`is_local_host(host, *, resolve=False, cache=False) -> bool`**
  — whether a host string names this machine.
- **`is_broadcast(address: IPAddressLike, interface: Interface | None = None, *, cache=False)`**
  — whether an address is an IPv4 broadcast, limited or subnet.
- **`is_unicast(address: IPAddressLike, interface: Interface | None = None, *, cache=False) -> bool`**
  — whether a datagram sent to an address was meant for one host.
- **`clear_interface_cache()`**, **`interface_enumerations() -> int`** and
  **`INTERFACE_CACHE_TTL`** — drop the cache, count the real enumerations, and
  the default one-second lifetime that `cache=True` selects; a number for
  `cache=` is that many seconds.

## Address and network helpers

CIDR maths, address classification and `host:port` handling. Detail:
`netimps/_ip/AGENTS.md`.

- **`is_link_scoped(ip: IPAddressLike) -> bool`**
  — loopback or link-local; not "is private".
- **`collapse(networks) -> List[IPNetwork]`**
  — merge adjacent and overlapping networks.
- **`subtract(networks, remove) -> List[IPNetwork]`**
  — set difference, which `ipaddress` omits.
- **`join_host(host: HostLike, port=None) -> str`**
  — `host:port`, with an IPv6 literal bracketed.
- **`split_host(text, *, default_port=None) -> (host, port)`**
  — the inverse, with IPv6 brackets and `(host, port)` pairs handled.
- **`split_zone(text) -> (host, zone | None)`**
  — an IPv6 `%zone` suffix off a host.
- **`unmap(value) -> IPAddress`** — an IPv4-mapped IPv6 address as plain IPv4.
- **`format_address(address: IPAddress | IPInterface) -> str`** — an address as
  text, the same on every Python: a v4-mapped IPv6 address in the mixed form
  (`::ffff:1.2.3.4`), anything else as `str()` writes it.
- **`is_wildcard(value: IPAddressLike | HostLike | None) -> bool`**
  — whether a value means "every local address"; a host name is `False`.
- **`Host(value)`** — a host named by an address or a hostname:
  `Host.parse(text)`, `Host.try_parse(text, default=None)`, `.is_address`, and
  the lookups `.ip(...)`, `.fqdn(...)` and `.resolve(...)`, which return an
  address, an `FQDN` and the pair. With `check=True` each is typed as never
  returning `None` (an `FQDN`, an `IPAddress`, a pair of both), since it raises
  instead; `FQDN.ip` and `FQDN.resolve` likewise.
- **`get_hostname(*, fqdn=False)`**
  — this machine's name, asked for when called.

## Scheme ↔ port registry

- **`get_default_port(scheme) -> int | None`** — text made of ASCII digits is
  a port and comes back as an `int` (`"443"` → `443`; outside `0-65535` raises
  `NetimpsValueError`). Any other spelling of a number (`"+80"`, `"8_0"`,
  `" 80 "`) is looked up as a name and is `None`; a `scheme` that is not text
  raises `TypeError`. Otherwise the built-in table (35 entries,
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

Four independently callable backends, one DNS-over-HTTPS endpoint, and a chain
of the four share one contract: a `list` of native types (`ipaddress` objects
for `A`/`AAAA`, `str` otherwise), `[]` for "no such name or record", and an
exception when the resolver could not be asked. Detail:
`netimps/_dns/AGENTS.md`.

- **`resolve(query, rdtype=None, *, ns=None, timeout=5.0, port=53, tcp=False, search=True, backends=None, strict=False, source=None, cache=False, deadline=None)`**
  — tries `dnspython`, the standard-library wire client (for an explicit `ns=`
or `source=`), the OS resolver and `nslookup`, in that order; `strict=True`
re-raises an outage instead of returning `[]`.
- **`resolve_dnspython(query, rdtype=None, *, ns=None, timeout=5.0, port=53, tcp=False, search=True, source=None)`**
  — structured records, every record type.
- **`resolve_system(query, rdtype=None, *, timeout=5.0, search=True)`**
  — the OS resolver: hosts file, NSS and DNS, in the order the OS applies them.
- **`resolve_nslookup(query, rdtype=None, *, ns=None, timeout=5.0, search=True)`**
  — the `nslookup` binary, as a last resort.
- **`resolve_wire(query, rdtype=None, *, ns=None, timeout=5.0, port=53, tcp=False, search=True, source=None)`**
  — the DNS protocol itself over UDP and TCP, standard library only.
- **`resolve_doh(query, url, *, rdtype=None, timeout=5.0, fetch=None, allow_http=False)`**
  — DNS over HTTPS (RFC 8484) to one endpoint, outside the chain.
- **`has_dns() -> bool`** — whether the `dns` extra is installed.
- **`clear_resolution_cache()`** and **`RESOLUTION_CACHE_TTL`** — drop the
  `cache=` answers, and their default 30-second lifetime.

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

Detail: `netimps/_ping/AGENTS.md`.

- **`ping(dst, *, tries=1, timeout=1.0, ipv6=None, src=None, size=None, ttl=None, dont_fragment=False, method="icmp", port=None, cache=False) -> PingResult`**
  — is the host up, by ICMP echo, a TCP handshake or a UDP probe. A failure
never raises; a caller's mistake does.
- **`PingResult`** — truthy on success and equal to `bool`, with `.ok`, `.dst`,
  `.rtt` (seconds), `.ttl`, `.src` and `.attempts`.

## Socket helpers

Detail: `netimps/_sockets/AGENTS.md`.

- **`bind(address="", port=0, *, family=None, kind=SOCK_DGRAM, reuse_address=True, allow_address_takeover=False, reuse_port=False, broadcast=False, connreset=None, interface=None, device=None, cache=False, options=(), listen=None)`**
  — create, configure and bind a socket in one call.
- **`AddressInUseError(NetimpsError, OSError)`** — what `bind()` raises when the
  address is taken, the same on every platform.
- **`has_device_binding() -> bool`** — whether `bind(device=...)` can restrict a
  socket to one device on this host (Linux only; Windows, macOS and FreeBSD were
  measured and have none); see the socket header.
- **`DeviceBindingUnsupportedError(NetimpsError, OSError)`** — what
  `bind(device=...)` raises where there is no such option.
- **`SocketOption(level, name, value)`** — a named triple for `bind`'s
  `options=`.
- **`disable_connreset(sock) -> bool`**
  — stop Windows reporting an ICMP port-unreachable as `ConnectionResetError` on
a later receive.
- **`set_buffer_size(sock, *, receive=None, send=None) -> (receive, send)`**
  — grow `SO_RCVBUF` and `SO_SNDBUF`, reporting what was granted.
- **`bind_error_hint(exc, port=None) -> str | None`**
  — an actionable sentence for a bind failure, or `None`.
- **`get_source_ip(dst="8.8.8.8", port=80, *, ipv6=None) -> IPAddress | None`**
  — the local address the kernel would use to reach a destination; sends
nothing.
- **`get_free_port(src="127.0.0.1", *, family=None) -> int`**
  — bind port 0 and read the port back.
- **`tcp_check(dst, port, *, timeout=3.0) -> bool`**
  — whether a TCP handshake completes.
- **`wait_for_port(dst, port, *, deadline=30.0, interval=0.1, timeout=None)`**
  — poll until a TCP port answers or a deadline passes.
- **`await_for_port(dst, port, *, deadline=30.0, interval=0.1, timeout=None)`**
  — `wait_for_port` as a coroutine, on the running loop.

## Routing, hops and MTU

Detail: `netimps/_sockets/AGENTS.md`.

- **`get_route(dst="8.8.8.8", *, ipv6=None) -> Route`**
  — the first hop to a destination, without privileges; unknown pieces are
`None` or `0`.
- **`Route`** — the answer: `.dst`, `.src`, `.gateway`, `.interface_index`,
  `.on_link`.
- **`count_hops(dst, *, max_hops=30, timeout=1.0, allow_traceroute=True, ipv6=None)`**
  — the number of hops, by raw sockets or the system `traceroute`.
- **`discover_mtu(dst, *, low=576, high=9000, timeout=1.0, src=None, port=80, probe=True, method="icmp", tries=1, ipv6=None, ttl=None)`**
  — the path MTU, measured by probes that really traverse the path.
- **`get_tcp_mss(dst, port, *, timeout=3.0, ipv6=None) -> int | None`**
  — the negotiated TCP maximum segment size.
- **`get_pmtu(dst, port=80, *, ipv6=None) -> int | None`**
  — the path MTU the kernel has already learned; sends nothing.
- **`max_udp_payload(mtu, *, ipv6=False)`**
  — the largest UDP payload that fits an MTU without fragmenting.

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

- **`multicast_socket(group=None, port=0, *, interface=None, ttl=1, loop=True, bind=True, reuse=True, ipv6=None, cache=False)`**
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
- **`join_group(sock, group, *, interface=None, cache=False)`** / **`leave_group(...)`** —
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

A domain name with label algebra, **inverted from `pathlib`**: `.name` and
`.parent` work on the leftmost label and `/` prepends. Detail:
`netimps/_fqdn/AGENTS.md`.

- **`FQDN(*parts)`** — immutable, hashable and ordered; refuses an address
  literal. Members: `.labels`, `.hostname`, `.domain`, `.domains`, `.tld`,
  `.child(*labels)`, `.is_subdomain_of()`, `.relative_to()`, `.reverse()`,
  `.to_unicode()`, `.encode()`, `.wire_length`, `FQDN.decode(data)`,
  `FQDN.decode_at(data, offset)`, `.is_hostname()`, `.is_wildcard`,
  `.common_ancestor()`, `FQDN.parse(text)`, `FQDN.try_parse(text,
  default=None)`, `FQDN.is_valid(value)`, and the lookups `.ip(...)`,
  `.resolve(...)` and `.ping(**kwargs)`.
- **`FQDNLike`** — `Union[FQDN, str]`, the accepted-input union wherever a
  method takes a name.

## Ancillary data and the `socket` patch

`recvmsg` and `sendmsg` on every platform, Windows included. Detail:
`netimps/_msg/AGENTS.md`.

- **`recvmsg(sock, bufsize, ancbufsize=0, flags=0)`** and **`sendmsg(sock,
  buffers, ancdata=(), flags=0, address=None)`** — CPython's own shapes, through
  `WSARecvMsg` and `WSASendMsg` on Windows.
- **`CMSG_LEN(length)`** and **`CMSG_SPACE(length)`** — control-message sizes;
  size a buffer with `CMSG_SPACE`.
- **`has_recvmsg()`** — whether `recvmsg` can run here.
- **`patch_socket_module(enable=True, *, iov_max=None)`**
  — install or remove the names on `socket` that CPython lacks on Windows.
- **`is_socket_patched()`** — whether anything is installed right now. The patch
  is installed at import unless `NETIMPS_SOCKET_PATCH` says otherwise (see
  "Environment variables").

## UDP with arrival interface

A wildcard-bound server learns which interface and address each datagram
reached, and answers from the address the client used. Detail:
`netimps/_udp/AGENTS.md`.

- **`UDPEndpoint(sock, *, pktinfo=True)`**
  — wraps a bound UDP socket: `recv(bufsize=65535, *, resolve_interface=True) ->
Datagram`, `send(data, dst, port, *, src=None) -> int`, the awaitable `arecv`,
`asend`, `datagrams(...)` and `aclose()`, `reply_socket(datagram, port=0, *,
connreset=False)`, `close()`, and the flags `.has_pktinfo` and
`.has_src_pinning`.
- **`Datagram`** — a `NamedTuple` of `.data`, `.sender`, `.destination`,
  `.interface_index`, `.interface`, `.control_truncated` and `.truncated`, plus
  `.is_unicast` and `.reply_address`.
- **`has_pktinfo(family=AF_INET) -> bool`**
  — whether a UDP socket of that family can report the arrival interface on this
host.

## Listening

What a user writes to say where a service listens, read once for every library
that listens. The grammar, with a table of examples, is in
`netimps/_listen/AGENTS.md`.

- **`parse_listen(listen=None, default_ports=0, *, family=None) -> Tuple[ListenAddress, ...]`**
  — reads a `listen` argument into the sockets it names, each address and port
once, in the order first written. No I/O: no name is resolved and no interface
is looked up. `TypeError` for a type the grammar does not take,
`NetimpsValueError` for anything else it refuses.
- **`ListenAddress`** — a `NamedTuple` of `.address` (an `IPv4Address` or
  `IPv6Address`), `.port` (`int`) and `.interfaces` (what limits the socket:
`Interface`, `MACAddress` or adapter-name text; empty when it is not limited).
It is itself an accepted binding.

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
- Synchronous — it blocks. **`aretry`** is the coroutine form (below); or drive
  **`backoff_delays(...)`** from your own loop, which yields the same schedule,
  `attempts - 1` values.

**`aretry(func: Callable[[], Awaitable[T]], attempts=3, *, delay=0.5, multiplier=2.0, max_delay=30.0, jitter=0.1, retryable=(OSError,), on_retry=None, jitter_seconds=None, symmetric=False) -> T`**

`retry` for a coroutine: `await aretry(lambda: client.fetch(url))`. The
arguments, the checks and the exceptions are `retry`'s; `func` must return an
awaitable (`TypeError` otherwise) and `on_retry` stays a plain function. Waits
are `asyncio.sleep` on the running loop, so no thread; cancelling it propagates
`CancelledError` at once.

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

## Asyncio

**Awaited with no thread:** `UDPEndpoint.arecv`, `UDPEndpoint.asend`,
`UDPEndpoint.datagrams` and `UDPEndpoint.aclose` (and `async with
UDPEndpoint(...)`), **`aretry`** and **`await_for_port`**, which wait with
`asyncio.sleep` and connect on the loop (`await_for_port` looks a name up with
`loop.getaddrinfo`, the loop's executor; an address needs none). The value
types, the parsing and classifying functions, `backoff_delays` and `Backoff` do
no I/O and are called directly.

**Blocking, so they need a thread** (`asyncio.to_thread`, or
`loop.run_in_executor` with `functools.partial`, since the options are
keyword-only: `loop.run_in_executor(None, functools.partial(ping, host,
timeout=2))`): the resolvers, the lookups of `Host` and `FQDN`, `ping`,
`tcp_check`, `wait_for_port`, `retry`, `scan_ports`, `scan_hosts`, `count_hops`,
`discover_mtu`, `get_tcp_mss`, `get_pmtu`, `get_route` and `get_source_ip`.
`import netimps` does not import asyncio; the two coroutines do when they run.

## Exceptions

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
| `DeviceBindingUnsupportedError` | `NetimpsError`, `OSError` | `bind(device=...)` on a platform with no device binding |

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

## Command line

Installed by the ``cli`` extra (``pip install netimps[cli]``), which adds
`duho`. **Importing `netimps` never requires it** -- the library half has no
dependency on the CLI half. The `netimps` console script is installed either
way; without the extra it prints
`netimps: the CLI needs the 'cli' extra -- pip install 'netimps[cli]'` and
exits 1, instead of dying in an `ImportError` traceback.

Commands, `--json` shapes and diagnostics: `netimps/cli/AGENTS.md`.

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
- The entry point is `netimps.cli.main(argv=None) -> int` (the console script
  and `python -m netimps` call it; it never returns `None`). `netimps.cli` is
  the one public submodule and is not part of the root `__all__`.

## Environment variables

The `NETIMPS_` variables are read when `import netimps` runs or when the `netimps` command starts, never by a library call after that.

- **`NETIMPS_SOCKET_PATCH`** — whether `import netimps` installs `recvmsg`, `sendmsg`, `CMSG_LEN` and `CMSG_SPACE` on the `socket` module (see `netimps/_msg/AGENTS.md`). Read once, at import, so a value set afterwards has no effect: call `patch_socket_module(False)` to remove the patch or `patch_socket_module()` to install it. Unset or empty means yes. `1`, `true`, `yes` and `on` mean yes, `0`, `false`, `no` and `off` mean no, in any case and ignoring surrounding whitespace. Any other value makes `import netimps` raise `ValueError` naming the variable, so a typo is never read as a choice. Default: installed. The patch changes nothing on Linux and macOS, which already have the names.
- **`NETIMPS_NO_SOCKET_PATCH`** — has the opposite sense of the variable above, so it is rejected, never honoured. Set to anything, an empty string included, it makes `import netimps` raise `ValueError` naming `NETIMPS_SOCKET_PATCH=0`. The `netimps` command and `python -m netimps` fail the same way, with a traceback.
- **`NETIMPS_MCP`** — read by the `netimps` command (the `cli` extra) before it parses its arguments. `stdio` serves every command as a tool over the Model Context Protocol on stdio instead of running one. Any other non-empty value exits with status 2 and a message naming the supported transport. The variable is removed from the process environment the moment it is seen, so a command's child processes do not inherit it. Default: unset; an empty value is the same, and the commands run normally.
- **`AGENT_HELP`** and **`AGENTS_HELP`** — read by the `netimps` command (the `cli` extra). Either one true makes `--help` print machine-readable JSON instead of text. False: empty, `0`, `false`, `no`, `off`, `n` and `f`, in any case; any other value is true. Default: unset, text help.
- **`PATH`** and, on Windows, **`PATHEXT`** — read on each call that starts `ping`, `nslookup`, `route` or `traceroute`, which searches only the absolute entries of `PATH` (see "Programs the library runs"). `LC_ALL=C` is set for the child process; it is not read.
- **`SystemRoot`** — Windows only: where `taskkill.exe` is found when a deadline kills a program and its children. Default: `C:\Windows`.

## Gotchas

Cross-cutting only; each topic's own gotchas are in its header.

- **A resolver outage and "no such record" are both `[]`** from `resolve()` unless `strict=True`, which re-raises the outage and nothing else. The backends and `Host` and `FQDN` with `check=True` tell them apart.
- **`ping` asks "is the host up", `tcp_check` asks "is the service up".** A TCP refusal counts as an answer for `ping(method="tcp")` and as a failure for `tcp_check`. ICMP echo is dropped by most cloud firewalls, so prefer `tcp_check` there.
- **A `dst` is never a network.** Every destination parameter takes `HostLike` and raises `TypeError` for an `IPv4Network` or `IPv6Network`; an interface object is read as its address.
- **`MACAddress` equals only another `MACAddress`.** `mac == "aa:bb:cc:dd:ee:ff"` is `False`; parse the text first.
- **Importing `netimps` installs `recvmsg` and `sendmsg` on `socket` on Windows**, which changes what other code infers from `hasattr(socket.socket, "recvmsg")`. `NETIMPS_SOCKET_PATCH=0` before the first import opts out.
- **An enumeration of the adapters is a system call.** Pass `cache=` where a lookup runs per packet, and an existing list of `Interface` objects in a loop.
- **Options are keyword-only**, so `ping("h", 3)` is a `TypeError`; wrap a call in `functools.partial` before handing it to an executor.
