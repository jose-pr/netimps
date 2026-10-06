# `netimps` address helpers — public API header

Header-file-style reference for the address, network and host names of the
`netimps` package: every public export with its signature, arguments, contract
and gotchas, so it can be used without reading its source. It ships inside the
package and is self-contained; the top header is `netimps/AGENTS.md`.
Development documentation lives with the source at
<https://github.com/jose-pr/netimps>.

This directory (`netimps/_ip/`) is private and not an import path: every name
below is imported from `netimps`.

## Address and network helpers

- **`is_link_scoped(ip: IPAddressLike) -> bool`** — loopback (host scope) or
  link-local (link scope): confined to this host or link. **Not "is private"** —
  RFC 1918 ranges are globally scoped and return `False`. A v4-mapped address is
  judged as the v4 address inside, the same on every Python.
- **One rule for the classifiers** (`is_link_scoped`, `is_multicast`,
  `is_local_address`, `is_broadcast`, `is_unicast`, and `unmap`): each takes
  `IPAddressLike` (text, `int`, packed `bytes`, an address object; an interface
  is read as its `.ip`) and raises `NetimpsValueError` for text that is no
  address, and `TypeError` for a network or a value of another type (`None`,
  `float`, `bool`, `list`). Two take a host instead, because they are asked of
  one: `is_wildcard` takes what `bind` takes as its host (`None` and blank text
  mean "every address", and a name is `False`), and `is_local_host` takes a
  name, never raises, and answers `False` for anything that is not a host.
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
  used) or an `FQDN`; an address object is written with `format_address`, so a
  v4-mapped one is `[::ffff:1.2.3.4]:80` on every Python; an already-bracketed string is not double-bracketed.
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
- **`format_address(address: IPAddress | IPInterface) -> str`** — the text of
  an address object, the same on every Python. `str()` of a v4-mapped IPv6
  address is the hex form before 3.13 (`::ffff:102:304`) and the mixed form from
  it (`::ffff:1.2.3.4`, RFC 5952 section 5); this writes the mixed form on every
  interpreter and, for any other address, what `str()` writes, so a log line, a
  golden file or a key does not depend on the interpreter:

  ```python
  format_address(IPv6Address("::ffff:102:304"))   # '::ffff:1.2.3.4' on 3.9 and 3.14
  format_address(IPv6Address("fe80::1%eth0"))     # 'fe80::1%eth0'  -- zone kept
  format_address(IPv4Address("1.2.3.4"))          # '1.2.3.4'
  format_address(IPv6Interface("::ffff:1.2.3.4/96"))  # '::ffff:1.2.3.4/96'
  ```

  The family never changes (`unmap` is the function that does), a `%zone` is
  kept, and an interface keeps its `/prefix`. Takes address and interface
  objects only: text is parsed first, and `TypeError` is raised for text, a
  network or any other type. Where netimps writes an address object as text it
  goes through this: `join_host`, `str(Host(address))`, `split_host` and
  `split_zone` of an address object, `Route`'s repr and the command line's
  output. A `str` passed in is never re-rendered (`join_host("::ffff:102:304", 80)`
  keeps its text), the reprs of the standard library's types
  (`IPv6Address('...')`, which `Interface` and `Datagram` show) are the standard
  library's, and text read back from a platform tool is not touched.
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
- **`is_wildcard(value: IPAddressLike | HostLike | None) -> bool`** — whether a value
  means "every local address": `""`, `None`, `"0.0.0.0"`, `"::"`, the v4-mapped
  `::ffff:0.0.0.0`, and any other spelling whose address form is unspecified. A
  `%zone` is stripped first. Text that is no address is a host
  name and answers `False`: `bind` takes a name as its host, and a name is
  never the wildcard. A `Host` or an `FQDN` is read as its text. `TypeError` for a network or a value of another type.
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
  `ResolutionError`) and `NetimpsValueError` for the second. Not memoised. `fqdn()` takes no `ipv6=`.
- **`.ip(*, check=False, ipv6=None, ns=None, timeout=5.0, port=53, tcp=False,
  search=True, backends=None, source=None, cache=False, deadline=None, refresh=False) -> IPAddress | None`**
  — a literal as parsed, a name looked up. `ipv6=True` asks for AAAA, `False`
  for A, `None` for either in one lookup, in the OS's own order. `check=True`
  raises instead of returning `None`: `NoAnswerError` for an empty answer, a
  plain `ResolutionError` (or `ResolutionTimeoutError`) for a resolver outage or
  an empty host (`resolve(strict=True)` alone re-raises only the outage); the
  annotation is `IPAddress` then, by overloads on `check: Literal[True]`. **With none of `ns`, `port`, `tcp`, `source` or `backends`, the
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
  is `None`, or raises with `check=True` (annotated `(FQDN, IPAddress)` then).
  `.fqdn(check=True)` is annotated `FQDN`.
- Compares equal to a plain `str`, and hashes by its text.
