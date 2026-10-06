# `netimps` `FQDN` — public API header

Header-file-style reference for the `FQDN` domain-name value type of the
`netimps` package: every public export with its signature, arguments, contract
and gotchas, so it can be used without reading its source. It ships inside the
package and is self-contained; the top header is `netimps/AGENTS.md`.
Development documentation lives with the source at
<https://github.com/jose-pr/netimps>.

This directory (`netimps/_fqdn/`) is private and not an import path: every name
below is imported from `netimps`.

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
  pointer, which is built from an address; `resolve(address)` builds the
  reverse name itself), and `parse`/`try_parse`/`is_valid` classmethods matching
  `MACAddress`'s: `FQDN.parse(text)` raises `NetimpsValueError` for bad text and
  `TypeError` for a non-`str`; `FQDN.try_parse(text, default=None)` answers
  `default` for bad text only.
- **Network methods are named as actions and can block.**
  **`.resolve(*, check=False, ipv6=None, ns=None, timeout=5.0, port=53,
  tcp=False, search=True, backends=None, source=None, cache=False, deadline=None) -> (FQDN, IPAddress | None)`**
  answers `(self, ip)` (`IPAddress` rather than `IPAddress | None` under
  `check=True`, which raises), the same pair `Host.resolve()` gives, so the two types
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
