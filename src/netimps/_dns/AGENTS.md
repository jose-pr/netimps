# `netimps` DNS — public API header

Header-file-style reference for the DNS names of the `netimps` package: every
public export with its signature, arguments, contract and gotchas, so it can be
used without reading its source. It ships inside the package and is
self-contained; the top header is `netimps/AGENTS.md`. Development documentation
lives with the source at <https://github.com/jose-pr/netimps>.

This directory (`netimps/_dns/`) is private and not an import path: every name
below is imported from `netimps`.

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
- **`nslookup` is run as described under "Programs the library runs" in `netimps/AGENTS.md`**:
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
