# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`resolve(..., strict=True)`** -- raise the last backend's
  `ResolutionError` when no backend could *ask*, instead of returning `[]`.
  Off by default. It distinguishes a resolver outage from a name that does
  not exist; it does **not** turn an empty answer into an error, so a name
  that genuinely does not resolve still returns `[]` at any strictness.

### Fixed

- **`resolve()` returns `[]` on a resolver outage again**, restoring the
  pre-0.3.0 contract. 0.3.0 made the chain re-raise the last backend's
  `ResolutionError` when every applicable backend failed to attempt the
  query, which turned `if not resolve(host):` into an uncaught exception
  wherever DNS was unreachable. The documented contract -- "always a `list`,
  empty on a lookup failure, never `None`" -- stands, and callers that need
  the distinction opt in with `strict=True`.
- **`bind_error_hint` no longer reports a Windows `WSAEACCES` as a privilege
  problem.** Windows has no privileged ports -- any user may bind port 80 --
  and `WSAEACCES` (WinError 10013) on a bind means the address is held
  exclusively by another socket, or refused by a firewall or an excluded port
  range. Python maps it to `PermissionError`/`EACCES`, so the POSIX branch
  matched first and produced "permission denied binding port 64514" for an
  unprivileged port, plus the "ports below 1024 need root/Administrator" rider
  on a low port. The POSIX `EACCES` reading is unchanged, where that advice is
  correct.
- **A release publishes its documentation again.** `docs.yml` was triggered by
  `release: published`, which never fires: the release is created with
  `GITHUB_TOKEN`, and GitHub does not start workflow runs from token-created
  events. It now keys off the Release workflow completing successfully. The
  0.3.0 site was published anyway, by the push-to-main trigger.

## [0.3.0] - 2026-09-21

Entries marked **BREAKING** change a documented contract. See
`RELEASENOTES.md` for migration detail and validation evidence.

### Added

- **`ResolutionError` is exported** (`netimps.ResolutionError`, listed in
  `__all__`). It is the documented raised type of `resolve`, `resolve_system`
  and `resolve_nslookup`, and catching it by name previously meant importing
  the private `netimps._dns`.
- **`Interface.loopback`** -- the kernel's own answer, from `IFF_LOOPBACK`
  (POSIX) or `IfType == IF_TYPE_SOFTWARE_LOOPBACK` (Windows), and `None` when
  enumeration reported neither, plus a matching trailing `loopback=`
  constructor keyword. `Interface.is_loopback` consults it first and falls back
  to the address heuristic only when it is `None`.
- **`UdpEndpoint.supports_src_pinning`** -- whether `send(src=...)` can be
  honoured at all. `False` on Windows (no `sendmsg`) and wherever the socket's
  family has no pktinfo control message. `repr(UdpEndpoint)` gained a matching
  `src_pinning=` field.
- **`Datagram.control_truncated`** -- `MSG_CTRUNC`, i.e. the kernel had more
  ancillary data than the buffer held. Appended last with a `False` default, so
  positional construction and unpacking of the first five fields is unaffected.
- **`ipv6=` on `multicast_socket`** -- forces the address family. The family
  came from `any(":" in g for g in groups)`, and a send-only socket has no
  groups, so `any()` over an empty list made it IPv4 unconditionally: the
  documented `multicast_socket(ttl=32, bind=False)` sender could not be given
  an IPv6 hop limit or used to reach an IPv6 group. `None` (the default) still
  infers from `group`.
- **`ipv6=`** on `get_ip`, `get_source_ip`, `get_route`, `hop_count` and
  `get_pmtu`, matching `ping`'s, and **`allow_address_takeover=`** on `bind`
  (see the Windows entry under Changed).
- **Per-octet dot MAC text** -- `MACAddress("aa.bb.cc.dd.ee.ff")` parses. That
  spelling is exactly what `as_str(".")` emits, so the round trip through the
  package's own output format was broken. Cisco triplets (`aabb.ccdd.eeff`)
  remain accepted on input and are still never produced.
- `MACLike` includes `bytearray`, which the constructor already accepted. No
  runtime change; a type checker stops rejecting a valid call.

### Changed
- **`multicast_socket` rejects groups of mixed address families**, and an
  `ipv6=` that contradicts `group`. One socket has one family; picking either
  and letting the other join fail surfaced as an opaque `OSError` from inside
  `setsockopt` instead of naming the mistake.

- **BREAKING: `MACAddress.__eq__` no longer coerces a `str`.**
  `MACAddress("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"` is now `False` --
  in both directions -- and `mac != text` is `True`; anything that is not a
  `MACAddress` yields `NotImplemented`.
  **Migration: `MACAddress.try_parse(text) == mac`.**
  Every spelling of the text compared equal, while `str.__hash__` -- not ours
  to change -- hashes each of them differently, so equality and hashing
  disagreed. That is what broke containers, and it is what this buys:
  `mac in {MACAddress(other_spelling)}` and
  `{mac: v}[MACAddress(other_spelling)]` both work now and did not before.
- **BREAKING (narrow): mixed MAC separators are rejected.**
  `MACAddress("00-11:22-33:44-55")` raises `ValueError`; a separator form has
  to be used consistently.
- **BREAKING (narrow): `MACAddress(True)` / `MACAddress(False)` raise
  `TypeError`** instead of building `00:00:00:00:00:01` / `...:00` -- `bool` is
  an `int` subclass, and an unguarded int branch took it. `is_valid(True)` is
  now `False` and `try_parse(True)` is `None`.
- **BREAKING: `resolve()` no longer stops on an empty answer.** Only a
  non-empty answer stops the chain, and `[]` comes back only when every
  applicable backend was empty. `resolve("localhost")` returns `127.0.0.1` in
  0.011s where it returned `[]`; the same held for hosts-file, `.local` and
  NSS-only names on Windows and macOS, where `dnspython` raises NXDOMAIN for
  them and so stopped the chain before the OS resolver was ever asked. (Linux
  answered, because systemd-resolved replies -- which is why Linux-only CI
  never saw this.) The cost: a genuinely non-existent name now takes two or
  three backend calls instead of one, the last of which may spawn `nslookup`.
  Pass `backends="dnspython"` for the old single call.
- **BREAKING: `resolve_nslookup` raises `ResolutionError` on a non-zero exit
  carrying no "no such name" marker** -- an unreachable server, a refused
  connection, a usage error. It used to return `[]`, which made a transport
  failure indistinguishable from NXDOMAIN and, inside `resolve()`'s chain,
  stopped the chain on it. An exit-1 NXDOMAIN with the marker text is still
  `[]`.
- **BREAKING: `resolve_nslookup` validates its query before spawning
  anything** -- `ValueError` for a query starting with `-` (`nslookup` has no
  `--` separator to escape one with), for an empty or whitespace-only query,
  and for one containing whitespace or control characters. Such a query used to
  reach the binary, which went interactive and drained the **caller's** stdin,
  sending each line to the nameserver as a query name.
- **BREAKING in effect: `resolve_system(addr, "ptr", timeout=T)` honours `T`.**
  The PTR branch called `gethostbyaddr` on the calling thread, bypassing the
  bounded daemon thread 0.2.2 added for the address path: measured **4.627s
  against a 0.1s deadline**, and 0.106s now. It raises `ResolutionError` at the
  deadline rather than blocking and then returning `[]`.
- `resolve()` also skips the `system` backend for an explicit non-53 `port=` or
  `tcp=True`, not only for `ns=` -- which is what its docstring already
  promised. With `backends=["system"]` plus one of those, the resulting
  `ValueError` now names the reason.
- **BREAKING: a port outside 0-65535 raises.** `tcp_check`, `wait_for_port`,
  `scan_ports`, `scan_hosts`, `get_pmtu`, `discover_mtu`, `get_tcp_mss` and
  `register_port` raise `ValueError("port out of range: 65536 (must be
  0-65535)")`, and a non-`int` port raises `TypeError`. Ports were masked to 16
  bits, so `tcp_check(host, p + 65536)` confidently answered about `p`. A
  service-name string (`tcp_check(host, "http")`) used to reach `getaddrinfo`
  and now raises; the scanners resolve scheme names to numbers first, so they
  are unaffected.
- **BREAKING: a negative `timeout` raises** from `scan_ports` / `scan_hosts`;
  it used to be swallowed, and every port then read as closed. A `timeout` of
  `0` is floored rather than taken literally -- 1 ms in the scanners, 0.05s in
  `tcp_check` -- because `settimeout(0)` means *non-blocking*, so
  `tcp_check(open_port, timeout=0)` returned `False` for an open port and now
  returns `True`.
- **BREAKING: `scan_hosts(network, ports=[])` scans nothing** and returns `[]`.
  An explicitly empty list used to fall through to the 36-port "common" set --
  the opposite of what it says.
- **BREAKING: `register_port(scheme, new_port)` moves the scheme** instead of
  leaving the old reverse entry behind, so `get_default_scheme(old_port)` no
  longer names it. The registry used to contradict itself: the scheme's port
  had changed and the old port still mapped back to that scheme.
- **BREAKING (Windows): `bind(reuse_address=True)` sets `SO_EXCLUSIVEADDRUSE`,
  not `SO_REUSEADDR`.** On Windows `SO_REUSEADDR` lets an unrelated process
  take over a live listener's port; the hijack was reproduced and is now a
  regression test in which the thief socket is refused with errno 13. Code that
  relied on rebinding a live Windows port must pass the new
  `allow_address_takeover=True`. POSIX behaviour is unchanged.
- **BREAKING: `Route.on_link` is `Optional[bool]`** -- `True` when no router is
  involved, `False` when one is, and `None` when no next-hop lookup could be
  made at all. It used to be `gateway is None`, which turned "we never looked"
  into a confident `True`: on macOS, `get_route("1.1.1.1")` reported
  `on_link=True` from a `192.168.64.3/24` host. `None` is falsy, so
  `if route.on_link:` still takes the safe branch; `route.on_link is True` and
  `== True` are what change. `Route.__eq__` now also compares `on_link`, and
  `Route` is hashable -- defining `__eq__` with no `__hash__` had set
  `__hash__` to `None`, so `hash(get_route("127.0.0.1"))` raised.
- **BREAKING: `normalize_host` raises `ValueError`** for an unbracketed string
  with two or more colons that is not an IPv6 address. It used to return the
  whole string as the host.
- **BREAKING (narrow): `UdpEndpoint.send(src=...)` raises `ValueError`** for a
  spec naming no local address or interface -- it used to fall back to an
  unpinned `sendto` and report success, which is the exact failure `src` exists
  to prevent -- and for an IPv6 source on an `AF_INET` endpoint, which used to
  raise an uncaught `OSError` from `inet_aton` on Linux. A v6 control message
  on a v4 socket is accepted-and-ignored by the kernel, so there is no correct
  silent behaviour to fall back to.
- **BREAKING (CLI): the positional argument is required** for `ping`,
  `resolve`, `check` (both of them), `mtu`, `scan`, `addr` and `split`. It used
  to default to `""`, so `netimps ping` answered about the empty string and
  printed ` did not answer (icmp)`. It is now argparse's usage error on stderr,
  exit 2.
- **BREAKING (CLI): every diagnostic moved to stderr** -- `error: ...`,
  `no interface named ...`, `no route to ...`. stdout carries the answer alone,
  so `--json` output stays parseable on failure (it is empty, and the exit code
  carries the verdict). A `ValueError` out of the library became a usage error
  at the command boundary -- `error: <message>` on stderr with exit 2, never a
  traceback -- as in `netimps ping <host> -m tcp` with no `--port`. Exit codes
  are otherwise unchanged, including the deliberate split between
  `port <unknown>` = 1 (a lookup that found no mapping, like an empty
  `resolve`) and `check <host> <unknown>` = 2 (a caller error).
- `MACAddress.is_valid` is annotated `bool` rather than
  `TypeGuard[MACAddress]`. No runtime change; the narrowing was unsound -- the
  object is still a `str` -- so code that relied on it now gets checker errors,
  correctly.
- `get_source_ip` is annotated `Optional[IPAddress]` instead of
  `Optional[Any]`; `tcp_check`'s `timeout` is `Optional[float]` (`None` blocks,
  which already worked); and `Datagram.sender`, `.local_address` and
  `.interface` are really typed rather than `Any`, so consumers of this
  `py.typed` package get checking on them.
- `get_default_port` / `get_default_scheme` query the system services database
  with an explicit protocol, **TCP first then UDP**, instead of letting the
  platform choose. Answers are now identical across platforms; where a name or
  port differs between TCP and UDP the TCP entry wins. Nothing in the built-in
  table changes.
- `scan_ports` resolves its host **once per scan** rather than once per port,
  so a rate-limited resolver can no longer turn open ports into "closed", and
  an unresolvable name costs one lookup rather than one per port. A name with
  several addresses is still probed on each.
- A port spec holding a Unicode digit that `int()` rejects (`U+00B2`, say)
  falls through to scheme lookup and raises the intended "unknown port range or
  scheme" rather than `invalid literal for int()`. The CLI decides "is this a
  number?" with `int()` rather than `str.isdigit()` for the same reason.
- `Interface.mac` reports an all-zero hardware address as `None`, so Linux `lo`
  matches macOS and Windows instead of reporting
  `MACAddress("00:00:00:00:00:00")`. `Interface` is hashable too, so
  `set(get_interfaces())` works instead of raising.
- `iter_addresses(family=)` validates eagerly, at the call rather than at the
  first `next()`, and its message names the `4`/`6` short form it wants.
- `UdpEndpoint(pktinfo=False)` governs **receiving** only. `send(src=...)` is
  honoured on such an endpoint, since pinning a source needs no socket option;
  the parameter used to disable both. An `OSError` from the kernel on a pinned
  send (a source address this host cannot send from) now propagates instead of
  being read as an unsupported platform -- genuine platform incapability still
  degrades to `sendto`.
- `get_route` on macOS/BSD spawns a short-lived `route -n get`
  (`stdin=DEVNULL`, 5s timeout) to learn the next hop; loopback short-circuits
  without spawning anything. It was subprocess-free there before and returned
  nothing useful.
- `netimps route`'s text output gained an `on-link  <True|False|unknown>` line
  and prints `(unknown)` rather than `(on-link, no router)` for the new `None`.
  `--json`'s `on_link` can now be `null`; the JSON keys are unchanged.
- Packaging: `*.local.*` is excluded from **both** the sdist and the wheel --
  the sdist's existing `/.*` covers dotfiles only, and
  `fnmatch("AGENTS.local.md", ".*")` is `False` -- and the published metadata
  now carries an author email, `jose-pr <jose-pr@coqui.dev>`.

### Removed

- **The claim that `ping(ttl=...)` "behaves the same on every OS" is
  withdrawn** from the README and the docs landing page. It was never true on
  BSD, where `-t` is an overall deadline and `-m` is the hop limit -- the other
  way round from Linux, whose `-m` is a firewall mark. What the sentence was
  really justified by is kept and now stands on its own terms: `ping()` decides
  success from the reply, not the exit code, because Windows `ping` exits `0`
  for "TTL expired in transit".
- **The docs site's "the only runtime dependency is `dnspython`" is
  withdrawn.** It has been false since 0.2.0 made `dnspython` optional; the
  package declares `dependencies = []`. It outlived the release that made it
  wrong because the landing page could only be republished by cutting a
  version -- see the docs workflow note below.

### Fixed
- **`netimps.__version__` is read from the installed distribution metadata**
  rather than restated as a literal beside `pyproject.toml`. The literal
  drifted on the first version bump -- reporting `0.2.2` from a `0.3.0`
  package -- while the shipped header promised the two always carry the same
  value. A source tree with no installed metadata reports `0.0.0+unknown`.
- **Link-local IPv6 multicast joins work on macOS/BSD.** `ff02::/16` has no
  meaning without a scope, and those kernels will not pick one -- so
  `multicast_socket("ff02::fb")` raised `OSError 49 (EADDRNOTAVAIL)` there
  while joining fine on Linux and Windows, which both accept index `0` for
  "kernel's choice". An index is now supplied only on the platforms that
  refuse to choose, and only when the caller named no `interface=`, which
  still wins everywhere.

- **`ping` is no longer a Linux-only implementation.** Five of the six flags it
  emitted mean something different, or nothing at all, on BSD/macOS -- measured
  on a real runner, not inferred. `-W` is **milliseconds** there rather than
  seconds, so the Linux value gave macOS a 1 ms deadline and `timeout=` was
  inert; `-t` is an overall deadline rather than the TTL (`-m` is the TTL);
  `-I` is multicast-only and is *rejected* for a unicast destination (`-S` is
  the source flag); DF is `-D` rather than `-M do`; and `-4`/`-6` do not exist
  at all -- macOS `ping` exits 64 on them and cannot even take a v6 literal. A
  three-way `_PLATFORM` (`windows` / `linux` / `bsd`) emits each grammar, and
  an IPv6 destination selects the separate **`ping6`** binary, which disagrees
  again (`-h` for the hop limit, no `-W` at all). `ping("::1")`, `ipv6=`, `src=`
  and `timeout=` therefore work on macOS, where each was silently broken.
- **A BSD reply is matched despite different punctuation.** `ping6` prints
  `16 bytes from ::1, icmp_seq=0 hlim=64` -- a comma rather than a colon, and
  `hlim` rather than `ttl`, so a v6 reply there reported no TTL at all.
- **`ping("-?")` raises instead of reporting success.** Windows `ping -?`
  prints usage and exits `0`; nothing resolved, so the reply-address check was
  skipped entirely and the bare exit code was taken as proof of a reply --
  `ping("-?")` came back **truthy for a host that was never contacted**. A
  destination starting with `-` is a `ValueError` now, and success requires
  positive reply evidence rather than exit status alone. `ping("")` stays
  falsy, as it always has.
- **`PingResult.rtt_ms` is `0.0` for a sub-millisecond reply**, which is what
  its docstring has always said. Windows prints `time<1ms` and the pattern
  captured the `1`, so every sub-millisecond reply reported `1.0` -- up to 100%
  error, silently, and the documented caution about `0.0` being falsy guarded
  nothing.
- **`get_pmtu` returns a number.** It was unreachable code on every platform
  for the life of the project: `socket.IP_MTU` is **not exported by CPython
  anywhere** (re-measured on Windows and Linux), so the first guard returned
  `None` unconditionally and the rest of the body never ran. Linux now uses the
  documented literals and reads `IPV6_PATHMTU` as the `ip6_mtuinfo` struct it
  really returns, rather than as a bare int -- measured 65535 for `127.0.0.1`
  and 65536 for `::1`. Windows genuinely exposes no cached path MTU and still
  answers `None`. `discover_mtu(probe=False)` inherited the bug and the fix.
- **`discover_mtu(method="udp")` sets DF.** No DF option was set on any
  platform, so an oversized datagram was fragmented locally, reassembled by the
  peer and answered: every probe "survived" and the binary search returned its
  own ceiling -- `high`, 9000 by default -- on Linux and Windows as well as
  BSD. It sets the per-platform option now and returns `None` where it cannot,
  rather than a number it cannot stand behind. The probe socket was also
  hardcoded `AF_INET`, so every IPv6 destination failed inside `sendto` and
  read as "no reply".
- **An IPv6 `UdpEndpoint` reports the arrival interface.** It advertised
  `supports_pktinfo=True` and then returned `interface_index=0`,
  `interface=None` and `local_address=None` for every datagram, because only
  the IPv4 option was ever requested. `IPV6_RECVPKTINFO` and the `in6_pktinfo`
  layout are handled now, and `supports_pktinfo` is `False` -- rather than
  optimistically `True` -- whenever the option for *this socket's family* is
  missing or refused.
- **`send(src=...)` pins the interface as well as the address.** The pktinfo
  structure carried a hardcoded `ipi_ifindex=0` ("kernel's choice"), so it only
  ever pinned an address despite documenting otherwise. The ancillary buffer is
  also sized for four control messages rather than exactly one, so an unrelated
  option enabled on the raw socket no longer silently swallows the pktinfo.
- **`Interface.is_loopback` comes from the interface flags.** It was derived
  from the addresses, and WSL2 binds a routable `10.255.255.254/32` to `lo`, so
  **no** interface reported `is_loopback` there -- and two tests took a skip
  branch marked `# pragma: no cover` because the author believed it
  unreachable. `IFF_LOOPBACK` / `IfType` were already being read into `raw` and
  ignored. WSL2 now reports exactly one loopback interface where it reported
  none; the same applies to any keepalived/anycast/VIP host.
- **Zone-qualified IPv6 is recognised.** `is_local_address`, `interface_for`
  and `interfaces_for` answered falsy for the `%zone` spelling of an address
  they called local unscoped, and `interface_index()` failed for every scoped
  literal, because `ipaddress` keeps the zone and `fe80::1%12` matches no
  enumerated address. A numeric zone is taken as the index (that is the OS's
  own spelling) and a named one resolves through `get_interfaces()`. A zone
  naming a *different* adapter still does not match, which is the point.
- **The IPv4-only `gethostbyname` is gone from `get_ip`, `get_route` and
  `hop_count`**, replaced by `getaddrinfo` with an explicit family. `get_route`
  gained real IPv6 next-hop lookups: `GetBestRoute2` on Windows (both
  families), `/proc/net/ipv6_route` on Linux, `route -n get` on BSD. The Linux
  parser honours `RTF_UP` / `RTF_REJECT`, because WSL2 carries a `::/0` reject
  route on `lo` and matching it would have made every global IPv6 address
  "on-link via loopback".
- **`get_source_ip` no longer picks the address family with `":" in dst`.** A
  hostname never contains a colon, so every hostname was probed as IPv4: an
  IPv6-only name returned `None`, and a dual-stack name returned the v4 source
  even where traffic would leave over v6.
- **`tcp_check(timeout=T)` bounds the whole call.** `socket.create_connection`
  applies `timeout` *per resolved address*, so a name with N addresses cost up
  to N x T.
- **No subprocess inherits the caller's stdin.** All three call sites --
  `nslookup`, `ping` and `traceroute` -- pass `stdin=DEVNULL`.
  `capture_output` redirects stdout and stderr only, so the child kept the
  parent's stdin, and `nslookup` in particular *reads* it.
- **`is_multicast` accepts the interface objects its neighbours do.**
  `is_multicast(IPv4Interface("239.1.2.3/32"))` was `False`, and it is the
  gatekeeper `join_group` / `leave_group` consult, so a genuine group passed
  that way was rejected as "not a multicast group".
- **`pip install netimps` no longer ships a command that dies with a
  traceback.** The `netimps` console script installs unconditionally while
  `duho` lives in the `cli` extra, so the entry point raised `ImportError` at
  import time. The import moved inside `run()`: the command now prints
  `netimps: the CLI needs the 'cli' extra -- pip install 'netimps[cli]'` and
  exits 1, and `import netimps.cli` succeeds without duho installed.
- **A latent 34-byte over-read.** `_SockaddrDl` declared `sdl_data` at 46 bytes
  (54 in total) where the real BSD `struct sockaddr_dl` is 20; the read is
  bounded by `sdl_len` now. It did not fault in practice, because `getifaddrs`
  returns one contiguous arena, but it was undefined behaviour at a page
  boundary.

### Documentation

- The shipped API header (`src/netimps/AGENTS.md`), the README, the docs
  landing page and the repo-root `AGENTS.md` are back in line with the code;
  several of the contracts above had been documented as something else.
- **CI runs the gate the repo has always claimed.** A `lint` job runs
  `black --check src/ tests/`, `mypy src/netimps` (27 errors when this campaign
  started, 0 now) and `mypy tests/typing/api.py` -- the file that proves the
  shipped header's static-typing promises, and that until now was executed by
  nothing at all. Pull requests are gated too, which is the one moment the
  check is worth having.
- **Pages deploys moved out of `release.yml` into their own `docs.yml`.** The
  site could previously change only by cutting a PyPI release, so a wrong
  sentence on the landing page stayed wrong until the next version. A release
  now *gates* on a strict docs build and deploys on `release: published`, and a
  docs-only correction ships on its own. `publish-pypi` also passes
  `skip-existing: true`, so a release that fails after some files upload can be
  finished rather than being stuck.
- **"Tests must never hit the network" is enforced rather than trusted**
  (`tests/conftest.py`). A review measured eleven off-host lookups, and
  simulating a wildcard resolver -- the kind many ISP and corporate networks
  run -- turned the suite red, because several tests assert that a name does
  *not* resolve. The suite grew from 432 to 640 tests, including
  `tests/test_platform_smoke.py`, which runs the real platform binaries against
  loopback: every other ping test fakes `subprocess.run` and asserts the argv
  the library *builds*, which is exactly how the macOS defects above shipped
  while CI stayed green.
- A `benchmarks/` suite (run on demand, deliberately not in CI, results
  committed per platform) and two runnable `examples/` were added.

## [0.2.2] - 2026-08-16

### Fixed

- **`resolve_system(timeout=)` now bounds wall time.** The lookup ran inside a
  `with ThreadPoolExecutor(...)` block, whose `__exit__` joins the worker
  still blocked in `getaddrinfo` -- so the timeout changed *what* was raised
  but not *when*, and a 30s resolver hang still cost the caller 30s despite
  `timeout=5.0`. `resolve()`'s chain consequently never reached `nslookup` at
  the promised deadline either.
- **`interface=` is honoured for IPv6 multicast.** The spec was reduced to an
  address and then passed to `if_nametoindex()`, which always fails for an
  address string, so the `IPV6_JOIN_GROUP` index silently stayed `0` --
  "kernel's choice", the exact default `interface=` exists to override.
  `IPV6_MULTICAST_IF` was never set at all, so sends left by the default
  route while joins listened elsewhere. Both now resolve the adapter to its
  interface index. IPv4 behaviour is unchanged.
- **`ping(hostname, ipv6=True)` is no longer always false.** The reply address
  was resolved with the IPv4-only `gethostbyname`, so a v6 reply was checked
  against a v4 expectation and never matched. The expectation now comes from
  `getaddrinfo` honouring `ipv6=`, and a name resolving to several addresses
  counts as answered if the reply came from any of them.
- **`ping(..., method="tcp"/"udp")` reaches IPv6 destinations.** Both probes
  opened `AF_INET` sockets unconditionally, so a v6 destination failed inside
  `connect`/`sendto` and was reported as unreachable -- a wrong falsy answer
  rather than an error. `ipv6=` now applies to all three methods.
- **`ping(..., method="udp")` detects ICMP port-unreachable on POSIX.** The
  probe socket was never connected, and POSIX delivers asynchronous ICMP
  errors only to connected UDP sockets -- so the documented "host answered,
  nothing listening" signal worked on Windows alone and the probe just timed
  out on Linux/macOS. `ECONNREFUSED` and `ECONNRESET` both now count.

### Documentation

- The shipped API header named `PingResult.source` and `Route.source`; both
  attributes are spelled `.src` (and `PingResult.host` was unlisted).
- Recorded the per-family multicast interface selection, `ping`'s `ipv6=`
  reach across all three methods, and `resolve_system`'s real wall-time
  deadline in the shipped header.
- Added the known, still-unverified macOS/BSD `ping6` reply-shape gap
  (`from <addr>,` rather than `from <addr>:`) to the header rather than
  guessing a parser change without a macOS runner.

## [0.2.1] - 2026-07-30

### Added

- **`AddressLike`**, a new type alias (`str | IPv4Address | IPv6Address |
  IPv4Interface | IPv6Interface`) accepted by every `dst`-typed parameter:
  `ping`, `tcp_check`, `wait_for_port`, `get_route`, `hop_count`, `get_pmtu`,
  `discover_mtu`, `get_tcp_mss`, `scan_ports(host)`, `get_ip`,
  `UdpEndpoint.send`, and `resolve`'s (and its backends') `query`. An
  `IPv4Interface`/`IPv6Interface` unwraps to its `.ip` -- previously passing
  one stringified with its `/prefix` intact, which every consumer
  (subprocess argument, socket call, DNS query) read as garbage. A network
  (`IPv4Network`/`IPv6Network`) raises `TypeError`, since it has no single
  address to use.
- **`resolve()` (and all three backends) auto-select `rdtype`.** It now
  defaults to `None`, which picks `"ptr"` when `query` is an address literal
  and `"a"` otherwise -- `resolve("8.8.8.8")` now returns `['dns.google']`
  instead of attempting a nonsensical A lookup on a literal address. Pass an
  explicit `rdtype` to opt out. `resolve_system()` gains `"ptr"` support (via
  `socket.gethostbyaddr()`) to make this work across every backend.

### Fixed

- **`ping(src=...)` crashed with `NameError` instead of returning a falsy
  result** when `src` named an interface with no usable address (e.g. an
  unknown adapter name, or a MAC not currently present) -- a leftover
  reference to an undefined `hostname` variable instead of `dst`. Found via
  a `mypy` pass while auditing type annotations; a regression test now
  covers the path.

### Changed

- Public functions across the package now carry complete parameter and
  return type annotations (previously missing on, among others, `collapse`,
  `subtract`, `get_ip`, `PingResult`, `Route`, `scan_hosts`, `is_multicast`,
  `join_group`/`leave_group`, `multicast_socket`, `UdpEndpoint`, and `bind`).
  The recurring "loose interface spec" parameter (`ping(src=)`,
  `bind(interface=)`, `discover_mtu(src=)`, `multicast_socket(interface=)`,
  etc.) now shares one internal type alias instead of being unannotated at
  each call site.

## [0.2.0] - 2026-07-29

### Added

- **Three independently callable DNS backends**, plus `resolve()` chaining
  them: `resolve_dnspython()` (the original `dnspython`-backed
  implementation, every record type), `resolve_system()`
  (`socket.getaddrinfo()` -- hosts file, NSS, OS resolver cache, address
  records only), and `resolve_nslookup()` (shells out to `nslookup`, parses
  both BIND-style and Windows-style output, address records only). `resolve()`
  now tries `["dnspython", "system", "nslookup"]` in order by default and
  returns the first definitive answer, skipping/falling through backends that
  can't serve the request (non-address `rdtype`, missing binary, `dnspython`
  not installed). A custom order/subset is available via
  `resolve(..., backends=[...])` (or a single name as a plain string).
- `resolve()` (and all three backends) gain a `search` parameter for the
  system resolver's search list (`resolv.conf`'s `search`/`domain`
  directive, or the Windows per-adapter DNS suffix list). It defaults to
  `True`, so an unqualified name like `resolve("db1")` is expanded the way
  `ping db1` would be; `search=False` looks the name up literally (as a
  fully-qualified name, so the OS resolver's own search-list logic doesn't
  kick in either), and a list of domain names tries exactly those suffixes
  instead of the system list.
- `dnspython` is now an **optional** dependency (`pip install netimps[dns]`),
  since `resolve()` can fall back to `resolve_system()`/`resolve_nslookup()`
  without it. The CLI's `resolve` subcommand now reports a missing-backend
  failure as a clean CLI error rather than an uncaught exception.

### Changed

- **`resolve()`'s default behavior for unqualified names.** Previously an
  unqualified `query` was only ever looked up as-is; it now also tries the
  system resolver's search list first (see `search` above). Pass
  `search=False` to keep the old literal-only behavior. `ns=None` already
  used the system resolver's nameservers; an invalid `ns=` now raises before
  any query is attempted rather than silently falling back to the system
  default.
- **`resolve()` is no longer purely `dnspython`-backed.** Behavior should be
  unchanged for existing callers when `dnspython` is installed (it's still
  tried first), but a lookup that previously raised or returned `[]` because
  `dnspython` failed for a reason unrelated to the DNS answer itself (e.g. a
  malformed system resolver config) may now succeed via the `system` or
  `nslookup` fallback instead.

## [0.1.0] - 2026-07-25

### Added

- **Complete local-interface membership lookups.** `interfaces_for()` yields
  every adapter matching an interface, exact address/`IPInterface`, network,
  or `MACAddress`, while `interface_for()` keeps the first-match scalar
  contract. `is_local_address()` distinguishes an assigned or loopback address
  from one that is merely private, link-local, on-link or reachable.
- **Static parser contracts.** `TypeForm` overloads preserve union and concrete
  result types, callable builders, and explicit `try_parse(default=...)`
  fallbacks. `IPInterfaceLike` now complements the existing input aliases.

### Changed

- `interface_for()` accepts networks and MAC addresses, including MAC text and
  6-byte packed values. Integer MACs remain explicit `MACAddress` values. Its legacy
  `strict=False` synthetic fallback remains address-only because a missing
  network or MAC has no honest single-interface representation.
- The IP input aliases now include packed bytes plus the exact stdlib
  two-tuple and existing-interface forms accepted by the interface/network
  factories. `is_valid()` is documented as a boolean convertibility check
  rather than an unsound type guard for the original object.

## [0.0.2] - 2026-07-23

### Added

- **`ws`/`wss` in the built-in scheme→port table** (80/443). WebSocket schemes
  (RFC 6455) ride the HTTP/HTTPS ports but are absent from `/etc/services`, so
  `get_default_port("wss")` previously returned `None` and every websocket
  consumer had to `register_port` them. `http`/`https` remain canonical for
  80/443.

## [0.0.1] - 2026-07-22

### Added

- **Command-line interface** (`netimps ...` / `python -m netimps`), built on
  duho and installed by the new `cli` extra. Eleven subcommands cover the
  diagnostic surface: `interfaces`, `ping`, `resolve`, `check`, `route`, `mtu`,
  `scan`, `addr`, `source`, `port`, `split`. Every one takes `--json`, and exit
  codes distinguish success from "the answer was no" from a caller error.
  `duho` is CLI-only -- importing the library does not require it.

## [0.0.0] - 2026-07-22

Initial release.

Earlier version numbers appear in this project's git history but were never
tagged or published, so there is no upgrade path to describe -- everything
below is simply what the package contains.

### Added

- **Interface discovery** -- `get_interfaces()` reports adapter names, MACs,
  MTU and *real* prefix lengths on Linux, macOS/BSD and Windows, via `ctypes`
  bindings to `getifaddrs(3)` and `GetAdaptersAddresses`. No third-party
  dependency. `Interface.is_loopback` is derived from the addresses rather than
  the name, since `lo`, `lo0` and `Loopback Pseudo-Interface 1` share no
  spelling. `Interface.primary_ip()` picks one entry; `iter_addresses()` is the
  flattened per-address view.
- **Types and parsing** -- `IPAddress`/`IPInterface`/`IPNetwork` union aliases
  to annotate with, and one `parse(value, type, **kwargs)` entry point with
  non-raising `try_parse` and boolean `is_valid` siblings. Concrete types are
  strict about family; networks are non-strict about host bits by default.
- **`MACAddress`** -- colon/hyphen/dot/bare plus `int`/`bytes`, hashable and
  ordered, with `.packed`, `.oui`, `.is_multicast`, `.is_local` and
  case-selectable rendering. A value type exposing `.packed`, not a `bytes`
  subclass, matching how `ipaddress` models addresses.
- **Socket helpers** -- `bind()`, `bind_error_hint()`, `interface_for()`,
  `get_source_ip()`, `get_free_port()`, `tcp_check()`, `wait_for_port()`.
- **`UdpEndpoint`** -- UDP receive reporting which interface a datagram arrived
  on via `IP_PKTINFO`, degrading where `recvmsg` does not exist.
- **Routing and MTU** -- `get_route()` (first hop, unprivileged), `hop_count()`
  (raw sockets or a traceroute fallback, so it works without elevation),
  `discover_mtu()` (measures the real path -- `method="icmp"` with DF-flagged
  pings, `"udp"` with datagrams, or `"tcp"` deriving from the negotiated MSS
  since TCP cannot be probed), `get_pmtu()` (the kernel's cached answer, usually
  `None`), `get_tcp_mss()`, and `Interface.mtu`. Header arithmetic is
  family-aware: IPv6 adds 20 bytes over IPv4, and assuming v4 on a v6 path
  under-reports by exactly that.
- **CIDR maths and host parsing** -- `collapse()`, `subtract()` (absent from
  `ipaddress`), and `normalize_host()`, which keeps `"::1"` an address rather
  than host `"::"` port `1`.
- **Scheme/port registry** -- `get_default_port()`, `get_default_scheme()`,
  `register_port()`.
- **DNS** -- `resolve()` returning native types (`A`/`AAAA` as `ipaddress`
  objects), `[]` on a genuine lookup failure, and `ValueError` for a malformed
  query rather than a silent empty result.
- **`ping()`** -- returns a `PingResult` with round-trip time and TTL that stays
  truthy. `method="icmp"|"tcp"|"udp"` reaches hosts through firewalls that drop
  echo; all three ask "is the *host* up?", so a TCP refusal or an ICMP
  port-unreachable counts as success. `tcp_check` remains the "is the *service*
  up?" question, where a refusal is a failure. `ttl=` behaves identically on every platform, because Windows `ping`
  exits 0 for "TTL expired in transit" and the reply address is verified
  instead of the exit code.
- **Scanning** -- concurrent `scan_ports()` / `scan_hosts()`, ports addressable
  by scheme name.
- **Multicast** -- `multicast_socket()`, `join_group()`, `leave_group()`,
  wrapping a setup whose failure modes are otherwise silent.
- **`Host`**, **`retry()`/`backoff_delays()`**, and the named networks `APIPA`,
  `LOOPBACK_V4`, `LOOPBACK_V6`, `LINK_LOCAL_V6`.

[Unreleased]: https://github.com/jose-pr/netimps/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jose-pr/netimps/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/jose-pr/netimps/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/jose-pr/netimps/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/jose-pr/netimps/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jose-pr/netimps/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/jose-pr/netimps/releases/tag/v0.0.2
[0.0.1]: https://github.com/jose-pr/netimps/releases/tag/v0.0.1
[0.0.0]: https://github.com/jose-pr/netimps/releases/tag/v0.0.0
