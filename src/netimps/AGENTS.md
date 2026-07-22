# `netimps` — public API header

Header-file-style reference for the `netimps` package: every `__all__` export
with its signature, arguments, contract, and gotchas, so this module can be
consumed without reading its source. The entire public surface lives in one
file, `__init__.py`; there are no submodules to import separately. For the
project overview and install instructions, see the repo-root `AGENTS.md`.

`netimps.__version__` — the package version string (currently `"0.1.0"`).

## IP address / interface / network factories

- **`IPAddress(value) -> IPv4Address | IPv6Address`** — `value` is a `str`
  (`"10.0.0.5"`), `int`, packed bytes, or an existing `ipaddress` address
  object (returned as-is). Delegates to `ipaddress.ip_address`. **Not a
  class** — it's a factory function, so `isinstance(x, IPAddress)` is
  meaningless; test against `IPv4Address`/`IPv6Address` instead. Raises
  `ValueError` on malformed input.
- **`IPInterface(value) -> IPv4Interface | IPv6Interface`** — delegates to
  `ipaddress.ip_interface`. Carries both a host address and its network:
  `.ip`, `.netmask`, `.network` (which itself has `.network_address`,
  `.exploded`, etc.). Raises `ValueError` on malformed input.
- **`IPNetwork(value, strict=False) -> IPv4Network | IPv6Network`** —
  delegates to `ipaddress.ip_network`. Defaults to `strict=False`, so a host
  address with a prefix (e.g. `"10.0.0.5/24"`) is accepted and normalised to
  its network instead of raising. Supports `.network_address`, `.netmask`,
  and `addr in network` membership tests. Raises `ValueError` on malformed
  input (even non-strict mode rejects genuinely invalid text).
- **`IPv4Address`, `IPv4Interface`, `IPv4Network`, `IPv6Address`,
  `IPv6Interface`, `IPv6Network`** — re-exported unchanged from the stdlib
  `ipaddress` module, for type annotations and `isinstance` checks.
- **`parse_ip(value) -> IPv4Address | IPv6Address | None`** — tolerant
  coercion. `value` may be `None`, a `str`/`int`, or an existing address.
  Returns `None` for `None` or an empty/whitespace-only string (the common
  "unresolved `ip` field" case); anything else is passed to `IPAddress`,
  which still raises `ValueError` on genuinely malformed non-empty input.
- **`parse_network(value) -> IPv4Network | IPv6Network | None`** — mirrors
  `parse_ip`: `None`/empty string → `None`; anything else delegates to
  `IPNetwork` (non-strict).
- **`is_valid_ip(value) -> bool`** — never raises. Returns `True` iff
  `ipaddress.ip_address(value)` would succeed; any `ValueError`/`TypeError`
  (including non-string types and empty strings) yields `False`.

## `MACAddress`

`MACAddress(value)` where `value` is a `str`, `int`, `bytes`/`bytearray`, or
another `MACAddress`.

- **String forms accepted**: colon (`AA:BB:CC:DD:EE:FF`), hyphen
  (`AA-BB-CC-DD-EE-FF`), dot/Cisco (`aabb.ccdd.eeff`), or bare
  (`AABBCCDDEEFF`) — case-insensitive. Anything else raises `ValueError`.
- **`int` form**: must be in `[0, 0xFFFFFFFFFFFF]` or raises `ValueError`.
- **`bytes`/`bytearray` form**: must be exactly 6 bytes or raises
  `ValueError`.
- Any other type raises `TypeError`.
- Internally normalised and stored as 6 raw bytes (`__slots__ = ("_octets",)`)
  — instances are immutable in practice (no setters).
- **`.as_str(sep=":") -> str`** — lowercase string with `sep` between octets;
  `sep=""` gives the bare 12-hex-digit form.
- **`.packed -> bytes`** — the 6 raw bytes.
- **`__int__`** — integer value (big-endian).
- **`__str__`** — same as `.as_str(":")`. **`__repr__`** —
  `MACAddress('aa:bb:cc:dd:ee:ff')`.
- **`__eq__`** — equal to another `MACAddress` with the same bytes, or to a
  `str` that parses to the same bytes (invalid string comparands compare
  unequal via `NotImplemented`, not an exception).
- **`__hash__`** — hashable by canonical bytes; safe as a dict key / set
  member.
- **`MACAddress._VALID_MAC`** — the compiled pattern used to validate
  incoming text, exposed as a class attribute so callers can pre-screen with
  `MACAddress._VALID_MAC.match(text)` before constructing.

## DNS / reachability

- **`nslookup(query, ns=None, type="a") -> list[str]`** — resolves `query`
  via DNS (uses `dnspython`'s `dns.resolver.Resolver`, imported lazily inside
  the function). `ns` is an optional nameserver or list of nameservers to
  query instead of the system resolver; `type` is the DNS record type
  (`"a"`, `"aaaa"`, `"mx"`, ...). **Contract**: always returns a `list` of
  string records, and an **empty list** on any resolution failure or DNS
  error — never `None` and never raises. Callers can safely write
  `if result:` / `result[0]`.
- **`ping(hostname, tries=1) -> bool`** — `True` if `hostname` answers a
  single ICMP echo within `tries` attempts. Shells out to the platform
  `ping` binary (`subprocess.run`, `capture_output=True`) with a 1-second
  timeout per attempt (Windows `-n 1 -w 1000`, POSIX `-c 1 -W 1 -n`), and
  returns on the first success. An empty `hostname` short-circuits to
  `False`. `tries <= 0` is treated as `1`.

## Local NIC discovery

- **`active_nic_addresses() -> list[IPv4Address]`** — cross-platform.
  Resolves the local hostname via `socket.gethostbyname_ex` and returns the
  first non-loopback (`127.*`-excluded) IPv4 address as a 1-element list;
  `[]` if only loopback addresses are found or the lookup raises `OSError`.
- **`get_ip_address(nic_name) -> str`** — **POSIX only**. Returns the IPv4
  address bound to interface `nic_name` via an `SIOCGIFADDR` ioctl (needs the
  POSIX-only `fcntl` module). Raises `NotImplementedError` on platforms
  without `fcntl` (e.g. Windows); `nic_name` is truncated to 15 bytes
  (`ifreq` struct limit).
- **`nic_info() -> list[tuple[str, str]]`** — **POSIX only**. `[(name,
  ipv4_str), ...]` for every interface via `socket.if_nameindex()`, each
  paired with `get_ip_address`. Raises `NotImplementedError` on platforms
  without `socket.if_nameindex` (e.g. Windows).

## Module-level data

- **`HOST_DN: str`** — `platform.node()`, captured once at import time (not
  re-evaluated per call).

## Gotchas

- `IPAddress`/`IPInterface`/`IPNetwork` are **factory functions**, not
  classes — don't `isinstance()` against them.
- `get_ip_address` and `nic_info` raise `NotImplementedError` on Windows;
  guard call sites that must run cross-platform, or use
  `active_nic_addresses()` instead.
- `nslookup` swallows *all* exceptions from resolution (broad `except
  Exception`) and returns `[]` — a misconfigured `ns` or a genuine network
  error looks identical to "no such record" from the caller's side.
- `MACAddress` equality against a non-`MACAddress`, non-`str` object (or an
  unparsable string) returns `NotImplemented`, so `mac == 42` is `False`
  rather than raising — normal Python fallback behaviour, but easy to
  forget.
