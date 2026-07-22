# `netimps` — public API header

Header-file-style reference for the `netimps` package: every `__all__` export
with its signature, arguments, contract, and gotchas, so this module can be
consumed without reading its source. The public surface lives in
`__init__.py`; `_ifaddrs.py` is private (its two public names are re-exported).
For the project overview and install instructions, see the repo-root
`AGENTS.md`.

`netimps.__version__` — the package version string (currently `"0.2.0"`).

## Types vs factories — read this first

The naming split is deliberate and easy to get backwards:

| | Names | What they are |
| --- | --- | --- |
| **Types** | `IPAddress`, `IPInterface`, `IPNetwork` | `Union` aliases you **annotate** with |
| **Factories** | `IPAddr()`, `IPIface()`, `IPNet()` | **callables** that parse and build values |

```python
def route(dst: netimps.IPAddress, via: netimps.IPNetwork) -> None: ...   # types
addr = netimps.IPAddr("10.0.0.5")                                        # factory
```

The noun-shaped names read like `ipaddress.IPv4Address`, so they are the types;
the factories mirror the stdlib's `ip_address()` in being callables. Calling a
type alias (`IPAddress("...")`) is a `TypeError`.

> **Renamed in 0.2.0.** In 0.1.0 `IPAddress`/`IPInterface`/`IPNetwork` were the
> factory *functions*. They are now the type aliases, and the factories took the
> short names. Nothing was published under 0.1.0, so there is no deprecation
> shim — call sites must be updated.

## Type aliases

- **`IPAddress`** — `Union[IPv4Address, IPv6Address]`.
- **`IPInterface`** — `Union[IPv4Interface, IPv6Interface]` (address + prefix).
- **`IPNetwork`** — `Union[IPv4Network, IPv6Network]`.
- **`IPAddressLike`** — anything `IPAddr()` accepts: `str | int | IPv4Address | IPv6Address`.
- **`IPNetworkLike`** — anything `IPNet()` accepts (adds the network and address types).
- **`MACLike`** — anything `MACAddress()` accepts: `str | int | bytes | MACAddress`.
- Concrete stdlib re-exports: `IPv4Address`, `IPv4Interface`, `IPv4Network`,
  `IPv6Address`, `IPv6Interface`, `IPv6Network` — so callers need not import
  `ipaddress` alongside this package.

## IP factories

- **`IPAddr(value) -> IPAddress`** — `value` is a `str` (`"10.0.0.5"`), `int`,
  packed bytes, or an existing address object (returned as-is). Delegates to
  `ipaddress.ip_address`. Raises `ValueError` on malformed input.
- **`IPIface(value) -> IPInterface`** — delegates to `ipaddress.ip_interface`.
  Carries a host address *and* its network: `.ip`, `.netmask`, `.network`.
- **`IPNet(value, strict=False) -> IPNetwork`** — delegates to
  `ipaddress.ip_network`. **`strict=False` by default** (the stdlib defaults to
  `True`): `"10.0.0.5/24"` is accepted and normalised to `10.0.0.0/24` rather
  than raising. Pass `strict=True` for stdlib behaviour.

## Parsing and validation

- **`try_parse(value, parser) -> T | None`** — returns `parser(value)`, or
  `None` if it rejects the input. The generic non-raising parse; works with any
  factory here or any callable that signals bad input with
  `ValueError`/`TypeError`. **Prefer this over `is_valid` + parse** — that does
  the work twice and leaves a window where the two disagree.
- **`is_valid(value, parser) -> bool`** — `True` if `parser(value)` succeeds.
- **`is_valid_ip(value)`**, **`is_valid_network(value)`**,
  **`is_valid_mac(value)`** — named shorthands for the above. Never raise; any
  input (wrong type, empty string, `None`) yields `False`.

> **Removed in 0.2.0.** `parse_ip` / `parse_network` are gone. They mapped only
> empty strings to `None` while still raising on malformed input — a special
> case that hid nothing useful and confused the two behaviours. Use
> `try_parse(value, IPAddr)` / `try_parse(value, IPNet)`, which treat every
> rejection uniformly.

**Exception policy** (both combinators): only `ValueError` and `TypeError` are
swallowed — the two that mean "bad input". Anything else (e.g. `OSError` from a
parser that touches the network) propagates, rather than being disguised as a
rejected value.

## `MACAddress`

**`MACAddress(value)`** — an IEEE 802 MAC address. `value` is a `str` in colon
(`AA:BB:CC:DD:EE:FF`), hyphen, dot/Cisco (`aabb.ccdd.eeff`) or bare
(`AABBCCDDEEFF`) form, a 48-bit `int`, 6 raw `bytes`, or another `MACAddress`.
Raises `ValueError` on a malformed value, `TypeError` on an unsupported type.

Normalised to lowercase and compared/hashed by its canonical bytes, so
instances work as dict keys and set members, and two values that differ only in
parsed case are equal.

- **`.as_str(sep=":", upper=False) -> str`** — render with any separator;
  `sep=""` gives the bare form, `upper=True` the uppercase form Windows tooling
  favours. Case is presentational only — it never affects equality or hashing.
- **`.packed -> bytes`** — the 6 raw bytes. The escape hatch for wire formats,
  mirroring `IPv4Address.packed`. **`MACAddress` is not a `bytes` subclass** —
  deliberately, matching how `ipaddress` models addresses.
- **`.oui -> bytes`** — the 3-byte vendor prefix.
- **`.is_multicast -> bool`** — group bit (low bit of octet 0).
- **`.is_local` / `.is_universal -> bool`** — the U/L bit. Locally administered
  addresses come from VMs, containers and MAC randomisation, so they are **not
  stable identifiers**.
- **`int(mac)`**, **`str(mac)`** (colon form), ordering (`<`, `<=`, `>`, `>=`)
  so MACs sort, and `_VALID_MAC` — the compiled pattern, for pre-screening text.

Ordering against a non-`MACAddress` returns `NotImplemented` (so Python raises
`TypeError`) rather than coercing. Equality against a non-MAC, non-`str` object
returns `NotImplemented` too, so `mac == 42` is `False` rather than raising.

## Interface discovery

**`get_interfaces(raw=False) -> List[Interface]`** — the host's interfaces,
with adapter names, MACs and **real prefix lengths**. Uses `getifaddrs(3)` on
POSIX and `GetAdaptersAddresses` on Windows via `ctypes` — **no third-party
dependency** (`ifaddr` is not used).

**`Interface`** — normalised identically across platforms:

- `.name: str` — human-usable name (`eth0`, `en0`, or the Windows *friendly*
  name — never the GUID).
- `.index: int` — `if_nametoindex` value, `0` when unknown.
- `.mac: MACAddress | None` — `None` for interfaces without one.
- `.ips: List[IPv4Interface | IPv6Interface]` — each with its real prefix.
- `.ipv4` / `.ipv6` — the split views.
- `.is_loopback: bool` — **computed from the addresses, not the name.** `lo`,
  `lo0` and `Loopback Pseudo-Interface 1` share no spelling; `127.0.0.0/8` and
  `::1` do.
- `.raw: dict | None` — `None` unless `raw=True`. Platform-specific leftovers
  (Linux/BSD `flags`; Windows `guid`, `if_type`, `mtu`, …). **Not portable and
  outside the stability guarantee** — the escape hatch for correlating with
  WMI/registry or reading `IFF_*` flags.

**Never raises for enumeration failure.** If the native call is unavailable it
degrades to hostname resolution, where **prefixes are fiction** — every address
becomes a `/32` or `/128` under an interface named `"<unknown>"`. Check
`iface.name == "<unknown>"` to detect it.

*Implementation note (`_ifaddrs.py`):* macOS/BSD `sockaddr` carries a leading
`sa_len` byte that Linux does not, so the struct header is defined per-platform.
Reading a BSD `sockaddr` with the Linux layout decodes `AF_INET` as `512`, which
silently drops every address rather than raising — do not "simplify" that split.

## DNS

**`resolve(query, rdtype="a", ns=None, timeout=5.0, port=53, tcp=False)`** —
the record type comes second, where callers actually vary it.

Returns a `List[str]` — **`[]` on any genuine lookup failure** (NXDOMAIN,
no answer, all nameservers failed, timeout), never `None`, so `if result:` and
`result[0]` are safe.

**Gotcha:** a malformed query or unknown record type raises `ValueError` — that
is a caller bug, not a DNS result, and silently returning `[]` hid typos. (In
0.1.0 a bare `except Exception` swallowed everything into `[]`.)

`timeout` bounds the **whole resolution including retries**, not one query, so
a list of dead nameservers cannot run past it. Requires `dnspython`.

## Reachability

**`ping(hostname, tries=1, timeout=1.0, ipv6=None) -> bool`** — shells out to
the platform `ping`, returning on the first success. `ipv6=True`/`False` forces
`-6`/`-4`; `None` lets the resolver choose. Never raises: a missing binary, a
hung subprocess, or a non-zero exit all yield `False`. Empty `hostname` is
`False`.

- POSIX `-W` takes whole seconds, so sub-second timeouts **round up, never to
  0** (some implementations read `0` as "wait forever").
- The subprocess also gets a wall-clock cap, since `-W` bounds the reply wait
  but not a hung name resolution.
- **This measures whether ICMP echo is answered, not whether a host is up** —
  most cloud firewalls drop echo while serving traffic. Prefer a TCP connect to
  the port you care about.

## Address classification / resolution

- **`get_ip(address) -> IPAddress | None`** — literal-or-hostname to an address,
  `None` on failure. **May block on DNS**, unlike `parse_ip`, which never
  touches the network. Use `parse_ip` to validate input; `get_ip` to resolve.
- **`is_link_scoped(ip) -> bool`** — loopback (`127/8`, `::1`) or
  link-local (`169.254/16`, `fe80::/10`); neither can usefully route off the
  local host or link.
- **`get_default_port(scheme) -> int | None`** — built-in table (including the
  socks variants, absent from `/etc/services`), then `getservbyname`.

## Legacy NIC helpers

Superseded by `get_interfaces()`, kept for compatibility:

- **`active_nic_addresses() -> List[IPv4Address]`** — the first non-loopback
  IPv4 address from hostname resolution, as a 0- or 1-element list.
- **`get_ip_address(nic_name) -> str`** — `SIOCGIFADDR` ioctl. **POSIX only**;
  raises `NotImplementedError` where `fcntl` is missing (Windows). `nic_name` is
  truncated to 15 chars (the `ifreq` struct limit).
- **`nic_info() -> List[tuple]`** — `[(name, ipv4), ...]` via
  `socket.if_nameindex`. **POSIX only.**

Guard call sites that must run cross-platform, or use `get_interfaces()`, which
works everywhere.

## Constants

- **`HOST_DN`** — `platform.node()`, captured **at import time** (a later
  hostname change is not reflected).
