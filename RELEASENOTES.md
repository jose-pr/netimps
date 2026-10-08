# Release notes

The detailed companion to [`CHANGELOG.md`](CHANGELOG.md): migration detail,
benchmark figures and the validation evidence behind each release. The
changelog says *what changed*; this says *what it costs you and how it was
checked*.

## 0.4.0 — 2026-10-08

A breaking release: the public surface is renamed to one scheme, options are
keyword-only, the value types are read-only, input rules are stricter and the
exceptions form one hierarchy. The documented API broke, so it is a MINOR under
the pre-1.0 rule. No alias is kept: an old name fails at import or at the call,
not later.

### Know before upgrading

These change what running code does without failing at import:

- **`wait_for_port(timeout=)` means one attempt.** It was the whole wait; that
  is `deadline=` (default 30 seconds). A call that passed `timeout=5` to give
  up after five seconds waits thirty, with five-second attempts.
- **`PingResult.rtt` is seconds.** `rtt_ms` is gone, so code reading it fails;
  code that moved to `rtt` without dividing is off by a thousand.
- **`bind()` infers the family.** `family=None` (was `AF_INET`) reads it from
  the address, so `bind("::1")` is an IPv6 socket; the wildcard `""` stays
  IPv4. `connreset=None` (was `True`) is off for a datagram socket and
  untouched for any other.
- **A resolver that could not be asked raises.** `resolve_dnspython`,
  `resolve_system` and `resolve_nslookup` raise `ResolutionError` (or
  `ResolutionTimeoutError`) for an outage where they returned `[]`; a name
  that does not exist is still `[]`. `resolve()` without `strict=True` still
  answers `[]`. `ResolutionError` is an `OSError`, so `except OSError` round a
  connect catches it and `retry()` retries it; leave `NoAnswerError` out of
  `retryable` to stop at a name that has no record.
- **`FQDN.resolve()` and `Host.resolve()` return `(fqdn, ip)`**, not DNS
  records; those come from `netimps.resolve(name, rdtype)`.
- **`NETIMPS_NO_SOCKET_PATCH` set to anything is an error at import.** The
  variable is `NETIMPS_SOCKET_PATCH`, with `0`, `false`, `no` or `off` to opt
  out. A stale setting cannot silently re-enable the patch.
- **The command line's exit statuses are uniform**: `0` found or yes, `1`
  nothing found or no, `2` an error. `netimps scan` with no answer exits 1
  (was 0), a bad port exits 2 (was 1), and `-q` prints no result line. The
  `cli` extra needs `duho>=0.7.0,<0.8`.
- **Stricter input.** A destination of `None` is a `TypeError`, as is a value
  that is no host type given to `split_host`, `split_zone` or `join_host`.
  `MACAddress.try_parse` and `FQDN.try_parse` take text only and raise
  `TypeError` for anything else; the generic `netimps.try_parse(value, type)`
  still answers `default`. Malformed text raises `NetimpsValueError`, which is
  a `ValueError`. The address classifiers raise it for text that is no
  address; `is_wildcard` alone answers `False` for a name, since it takes what
  `bind` takes.

### Migrate

The whole table is in the changelog under *Renamed*. The ones most code meets:

| You wrote | Write |
| --- | --- |
| `UdpEndpoint`, `Fqdn`, `FqdnLike`, `MACLike`, `AddressLike` | `UDPEndpoint`, `FQDN`, `FQDNLike`, `MACAddressLike`, `HostLike` |
| `normalize_host(x)` | `split_host(x)` |
| `get_ip(x)` | `Host(x).ip()`; `Host(x).ip(check=True)` raises where `get_ip` returned `None` |
| `host.fqdn` | `host.fqdn()` |
| `host.ip(True)` | `host.ip(refresh=True)` |
| `interface_for(q)`, `interfaces_for(q)` | `get_interface(q)`, `iter_interfaces(q)` |
| `hop_count(dst)` | `count_hops(dst)` |
| `supports_pktinfo()`, `supports_recvmsg()`, `socket_patched()` | `has_pktinfo()`, `has_recvmsg()`, `is_socket_patched()` |
| `HOST_DN` | `get_hostname()` |
| `APIPA` | `LINK_LOCAL_V4` |
| `iface.loopback` | `iface.is_loopback` |
| `mac.as_str("-", True)` | `mac.format("-", upper=True)` or `format(mac, "-X")` |
| `name.wire`, `name.unicode`, `name.as_fully_qualified()` | `name.encode()`, `name.to_unicode()`, `name.fully_qualified()` |
| `endpoint.send(data, address=a, port=p)` | `endpoint.send(data, a, p)`, with `src=` by name |
| `datagram.local_address` | `datagram.destination` |
| `result.host`, `result.rtt_ms` | `result.dst`, `result.rtt * 1000` |
| `ping("h", 3)` | `ping("h", tries=3)`: every option after the operands is named |
| `strict=` on a `Host` or `FQDN` method | `check=` |
| `netimps.cli:run` | `netimps.cli:main` |

`Host`, `MACAddress`, `PingResult`, `Route` and `Interface` are read-only:
assigning to an attribute raises `AttributeError`, and `Interface.ips` is a
tuple. Build a new value.

`import netimps` no longer asks for the host name, which was a WMI query on
Windows. Code that imported netimps lazily to avoid that cost can import it at
the top.

### What was added

- Sockets: `bind(device=)` with `has_device_binding()` and
  `DeviceBindingUnsupportedError`; `cache=` on the lookups that resolve an
  adapter.
- Interfaces: `Interface.is_up`, `is_multicast` and `is_point_to_point`;
  `get_interface` and `iter_interfaces` by name and by `index=`.
- Addresses and hosts: `format_address`, `classify`, `split_zone`,
  `is_local_host`, `is_unicast`, `get_hostname`; `parse` on `MACAddress`,
  `FQDN` and `Host`; `FQDN.encode`, `decode` and `decode_at`.
- Resolution: `Host.resolve()` and `FQDN.resolve()`, the resolver options and
  `check=` on `Host.ip()`, `Host.fqdn()` and `FQDN.ip()`; `cache=` and
  `deadline=` on `resolve()`; `has_dns()`; `resolve_doh(allow_http=)`.
- asyncio: `aretry`, `await_for_port`, `UDPEndpoint.asend`, `aclose` and
  `async with`. `import netimps` does not import asyncio.
- Exceptions: `NetimpsError` as the base, `NetimpsValueError`,
  `NoAnswerError`, `ResolutionTimeoutError`, `DNSDecodeError`.
- Ports: the WS-Management schemes (`wsman`, `wsmans`, `winrm`, `winrms`,
  `psrp`), a comma-separated `PortsLike`, a port number as text for
  `get_default_port`.

### What was wrong

The changelog lists every fix. The ones that changed an answer on a real host:

- IPv4 on FreeBSD reports the arrival interface and pins the source.
- Windows lists no address it cannot bind, honours a socket timeout in
  `recvmsg` and `sendmsg`, and pays the same for a receive whatever `bufsize`.
- On Windows the `os.sysconf` stand-in the `socket` patch installs answers
  `SC_OPEN_MAX`. It raised for every name but `SC_IOV_MAX`, which broke a
  library that reads the limit after testing only `hasattr(os, "sysconf")`.
- A BSD netmask is read no further than its own length.
- Closing a `UDPEndpoint` ends a pending `arecv`.
- A DNS reply is bounded, and a name the IDNA codec refuses does not escape
  as a `UnicodeEncodeError`.

### How it was checked

Measured on the commit before the one that dates the changelog, which differs
from it in the changelog and in this file only.

- The CI matrix, 24 jobs, all passing: lint and the three-platform type
  check; the suite on Python 3.9 to 3.14 on ubuntu and on 3.9 and 3.14 on
  windows and macos; the declared dependency floors; and, on 3.9 and 3.14 on
  each of the three systems, an install with no extra and the built wheel
  with its console script.
- Hosts the matrix does not have: FreeBSD on Python 3.11 (2293 passed, 65
  skipped) and macOS 15.7 on Intel with Python 3.9 (2298 passed, 60 skipped).
  Windows 11 on ARM64: 2416 passed on 3.14 and 2415 on 3.9.
- The three libraries built on this release (pktcap, pytftp, pydhcp) run
  their own suites against it on the same platforms.
- pathlib-next 0.9.11, whose `uri` extra admits any netimps from 0.3.1 and so
  receives this release unasked: its suite against a wheel of this version,
  3404 passed, 41 skipped. It uses no name this release renames.
- The sdist and the wheel build and pass `twine check`; the release workflow
  installs the wheel into a fresh environment before anything is published.

## 0.3.4 — 2026-10-03

Two fixes, both in how an interface with more than one address is handled, and
both found by measuring on a real interface rather than by the test suite.

### Migrate if you relied on the order of `primary_ip()`

No documented contract changed. `Interface.primary_ip()` used to return the
first entry that was not loopback. It now ranks routable, then loopback, then
link-local, keeping the operating system's order within a rank. An interface
that lists a link-local address first and a routable one second therefore
answers with the routable one; a loopback adapter still answers `::1` and not
`fe80::1`; an interface holding only a link-local address still yields it, and
`loopback_ok=False` skips the loopback rank rather than returning `None`.

### What was wrong, and how each was found

- **`primary_ip()` preferred a link-local address over a routable one.** An
  interface commonly lists its link-local address first (`fe80::` is configured
  before SLAAC or DHCPv6 completes on Linux and macOS NICs), and the IPv4
  twin, a `169.254/16` address beside a DHCP lease, was real too. Measured on a
  macOS loopback adapter holding `127.0.0.1/8`, `::1/128` and `fe80::1/64`:
  `primary_ip(ipv6=True)` returned `fe80::1`, and `bind(interface=...,
  family=AF_INET6)` then failed with "Can't assign requested address".
- **`bind(interface=...)` dropped the scope of a link-local address**, so a
  link-local bind failed on every POSIX platform, not only macOS. Measured on
  Linux against a real NIC: `bind(("fe80::1", 0))`, `("fe80::1%2", 0)` and
  `("fe80::1%eth0", 0)` all raised `EINVAL`, and only the 4-tuple
  `("fe80::1", 0, 0, 2)` bound. `bind()` now turns a `%zone` suffix, name or
  index, into the numeric scope id, so `bind("fe80::1%eth0", ...)` written by
  hand works for the first time. `reply_socket`'s link-local path went through
  the same string form and is fixed by the same change.

Windows accepts all four spellings, which is why a Windows-only measurement
says nothing about this. The first attempt at the fix put `%index` in the
string, copying what `reply_socket` did; it passed locally and broke all six
Linux CI jobs and both macOS jobs.

## 0.3.3 — 2026-10-03

Server-side helpers and a Windows-complete UDP path. Additive API, so a PATCH
under the pre-1.0 rule, with one default that changes what `import netimps`
does on Windows.

### Know before upgrading

- **`import netimps` installs `recvmsg`, `sendmsg`, `CMSG_LEN` and `CMSG_SPACE`
  on the `socket` module on Windows**, unless `NETIMPS_NO_SOCKET_PATCH=1` is set
  before the first import (or `patch_socket_module(False)` is called after it).
  It is additive in *names* and so not in *behaviour*: code that tests
  `hasattr(socket.socket, "recvmsg")` to detect POSIX now gets the POSIX answer
  on Windows. A project that read `ipi_spec_dst` from such a socket for its
  server identifier (pydhcp 0.6.1 and earlier) was measured to receive but
  allocate and reply to nothing on Windows, because that field comes back
  zero-filled. `UdpEndpoint` is the supported way to obtain the local address
  correctly on every platform. The owner accepted this consequence, since the
  two projects are released together.
- **`bind()` is stricter about sharing a port.** `SO_REUSEADDR` is set on POSIX
  for stream sockets only, so a second live UDP socket no longer takes the port
  on Linux by default; share one with `reuse_port=True` or
  `allow_address_takeover=True`. On Windows `SO_EXCLUSIVEADDRUSE` is set for
  both values of `reuse_address` unless `allow_address_takeover` is true, and
  `reuse_address` governs POSIX `SO_REUSEADDR` only.
- **`bind()` and `normalize_host()` accept the package's usual loose union**
  (an address object, an interface, a `Host`, an `Fqdn`) where `bind()` used to
  leak a raw socket-layer `TypeError`. A network is still a `TypeError`, and
  `normalize_host` takes an allowlist, so `None` is no longer read as the
  hostname `"None"`.

### What was added

- Host and address helpers: `join_host`, `unmap`, `is_wildcard`,
  `MACAddress.hex`, `Fqdn` (a domain name as a value type, with label algebra),
  `Host.fqdn`.
- Socket helpers: `disable_connreset` and `bind(connreset=)`,
  `set_buffer_size`, `SocketOption`, `AddressInUseError`, `max_udp_payload`.
- Interface lookups: an opt-in `cache=` for the adapter enumeration,
  `interface_enumerations()` and `is_broadcast`; an unbounded `Interface.mtu`
  (the Windows loopback adapter) is now a number and no longer `None`.
- UDP servers: `supports_pktinfo`, `UdpEndpoint.reply_socket`, `arecv()` and
  `datagrams()`, `Datagram.truncated`, and arrival interface on Windows for v4,
  v6 and dual-stack sockets.
- `recvmsg()` and `sendmsg()`, public on every platform, with
  `patch_socket_module()` and `socket_patched()`.
- Timers: `Backoff` and the `jitter_seconds=` and `symmetric=` options of
  `backoff_delays` and `retry`.
- DNS: `resolve_wire()` (a standard-library client, used for an explicit `ns=`
  or `source=`), `source=` on the resolvers, and `resolve_doh()`.

### What was wrong, and how each was found

- **`import netimps` then `import asyncio` crashed on Windows.** The patch made
  `socket.socket.sendmsg` exist, and CPython's `asyncio/selector_events` reads
  that as a POSIX proxy and then calls `os.sysconf('SC_IOV_MAX')`. The patch now
  installs an `os.sysconf` shim answering per name, and the regression tests run
  in fresh interpreters, since an in-process test cannot see it.
- **`sendmsg()` failed on every connected stream socket on Windows**;
  `WSASendMsg` refuses `SOCK_STREAM` with `WSAEINVAL`, measured on Windows 11.
  The buffers-only path now uses `WSASend`.
- **`UdpEndpoint` reported nothing when a datagram was too large for `bufsize`.**
  `Datagram.truncated` now carries `MSG_TRUNC`.
- **A cancelled `arecv()` left its reader registered on the loop**, and the
  notifier stayed bound to the first loop.
- **`bind(options=[(SOL_SOCKET, SO_REUSEADDR, 1)])` failed with a bare
  `WSAEINVAL` on Windows**, a regression within the same cycle.
- **A v4 client of a dual-stack listener could not be replied to at all**,
  measured on Windows 11 ARM64.
- **`is_multicast` missed a v4-mapped group below Python 3.13**, because the
  standard library only began delegating a mapped address's `is_*` properties
  there; it unmaps first now.
- **`reply_socket` answered from the wrong address when the port was taken.**
- **`bind()`'s default let a second live UDP socket take the port on Linux**,
  measured on WSL: the datagram went to the second socket and the holder got
  no error. **`bind(reuse_address=False)` left a Windows wildcard bind open to
  hijack**: it set neither `SO_REUSEADDR` nor `SO_EXCLUSIVEADDRUSE`, and a thief
  binding `127.0.0.1` received the datagram.
- **`UdpEndpoint.recv()` enumerated every interface on every datagram**:
  measured on Windows loopback at 1.07 ms per packet against 0.015 ms with
  `resolve_interface=False`. It resolves through a per-endpoint index-to-
  interface cache, refreshed on a miss and on a 30-second TTL: 0.017 ms per
  packet afterwards.
- **IPv6 `UdpEndpoint` was silently degraded on Windows**, because
  `IPV6_RECVPKTINFO` is not exported there, and **v4 pktinfo was silently off on
  Python 3.9 for Windows**, which exports no `socket.IP_PKTINFO`: 3.9 skipped
  nine tests and still reported a green suite. The documented literals are used
  and `OSError` from `setsockopt` is the capability signal.

## 0.3.2 — 2026-09-28

A dependency-bound release. No source change.

### Nothing to migrate

No documented contract changed. `pip install netimps[cli]` now resolves to a
`duho` in `>=0.6.0,<0.7` instead of floating unbounded from `>=0.3.3`; an
existing install that already has a `duho` in range is unaffected.

### What changed, and why

- **The `cli` extra's `duho` dependency is bounded to `>=0.6.0,<0.7`.**
  Unbounded, a bare install would have floated onto duho 0.6.0 unverified.
  Every documented 0.6.0 change was checked against `src/netimps/cli.py`
  before setting the bound, and the full suite is unaffected: 663 passed, 6
  skipped, both before and after. duho 0.6.0 also adds an opt-in MCP launch
  feature (`NETIMPS_MCP=stdio`); netimps does not opt out and leaves it at
  duho's default.

### Benchmarks

Not re-run. Nothing here touches a hot path -- a dependency bound in
`pyproject.toml`, no source change. The 0.3.0 baseline below still stands.

**Next perf target:** none set. The figure worth watching is
`get_interfaces`, since every membership lookup pays it (see the table below).

## 0.3.1 — 2026-09-21

Three patch-level fixes, none found by the test suite. Two of the three were
**pinned as the requirement by a passing test** — the suite asserted the
defect. That is the pattern worth naming: a test written from the
implementation can only ever confirm the implementation.

### Nothing to migrate

No documented contract changed. The `resolve()` fix restores the contract
0.3.0 broke, so code written against 0.2.x is correct again without edits, and
code written against 0.3.0's raise keeps working if it passes `strict=True`.

### What was wrong, and how each was found

- **`resolve()` raised on a resolver outage** instead of returning `[]`,
  contradicting its own docstring in the same release. Reported by the
  maintainer within hours of 0.3.0. `if not resolve(host):` — the idiom the
  function exists for — became an uncaught `ResolutionError` anywhere DNS was
  unreachable, which is the one condition a caller most wants to survive.
  `strict=True` is the opt-in for callers that do need an outage told apart
  from a dead name.
- **`bind_error_hint` misdiagnosed Windows `WSAEACCES` as a privilege
  problem.** Found in `pydhcp`, which requires `netimps>=0.3.0` and had
  written its own replacement with the measurement in a comment. A consumer
  routing around our bug is a stronger signal than any test we had — ours
  asserted the wrong behaviour as the requirement.
- **`docs.yml`'s `release: published` trigger never fired**, because GitHub
  does not start workflow runs from `GITHUB_TOKEN`-created events. The 0.3.0
  site was correct only because the push-to-main trigger happened to cover it.
  This release is the first to exercise the `workflow_run` replacement.

### Benchmarks

Not re-run. Nothing here touches a hot path — two error-message branches, one
return statement and a workflow trigger. The 0.3.0 baseline below still
stands.

**Next perf target:** none set. The figure worth watching is
`get_interfaces`, since every membership lookup pays it (see the table below).

## 0.3.0 — 2026-09-21

A correctness release. Nothing here was a performance change.

### Benchmarks

**No previous→current table: 0.3.0 establishes the baseline.** `benchmarks/`
did not exist before this release, so there is nothing to compare against. The
committed baseline is `benchmarks/results/windows-py3.14.6-arm64.json`.

| metric | median ms | why it is the one to watch |
| --- | --- | --- |
| `get_interfaces` | 1.30 | full ctypes NIC enumeration; every membership lookup pays it |
| `is_local_address` | 0.0088 | re-enumerates, which is why it is not free |
| `collapse` (256 × /16) | 2.31 | the expensive pure-computation path |
| `parse` (IPv4 literal) | 0.0023 | the hot path for anything taking an address as text |
| `parse` × 1024 | 4.75 | per-call overhead against a realistic workload |

Read: `is_local_address` costing ~4× a single parse is not a parsing problem,
it is the enumeration behind it. Cache the enumeration before touching the
parser.

**Caveats.** These are **local** figures from one Windows 11 ARM64 laptop
(Snapdragon X2 Elite, CPython 3.14.6), 400 samples per metric, taken while
other work was running. Per this project's rules a performance claim in a
release comes from CI, not a local run — so treat the table as a shape and a
starting point, not as evidence. Syscall-bound metrics (`get_interfaces`,
`get_source_ip`, `get_free_port`) are far noisier than the pure-computation
ones; compare on the median and expect the max to be somebody else's
scheduler.

### Migration

Seven documented contracts changed. In rough order of how likely you are to
hit them:

**`MACAddress` no longer compares equal to a `str`.**

```python
mac == "aa:bb:cc:dd:ee:ff"                    # was True, now False
MACAddress.try_parse("aa:bb:cc:dd:ee:ff") == mac   # the replacement
```

This is the one change with no compatible middle ground. `__eq__` accepted any
spelling while `__hash__` hashed only the packed bytes, so `mac == text` was
`True` while `mac in {text}` was `False` and a dict lookup silently missed. No
hash can agree with every spelling of a string, so the coercion had to go. In
exchange, `==`, `in` and dict lookup now agree with each other.

Also narrower: mixed separators (`00-11:22-33:44-55`) and `MACAddress(True)`
now raise.

**`resolve()` no longer stops on an empty answer.** Only a non-empty answer
stops the chain. Names that only NSS can resolve — `localhost`, hosts-file
entries, `.local` — now resolve instead of returning `[]`. The cost: a
genuinely non-existent name costs two or three backend calls instead of one,
and the last may spawn `nslookup`. `backends="dnspython"` restores the single
call if you need it.

**`Route.on_link` is `Optional[bool]`.** `None` means no next-hop lookup could
be made, which previously came back as a confident `True`. `None` is falsy, so
`if route.on_link:` keeps the safe branch; `route.on_link is True` and
`== True` change meaning.

**`bind(reuse_address=True)` on Windows** now sets `SO_EXCLUSIVEADDRUSE`
instead of `SO_REUSEADDR`, because on Windows the latter lets *another
process* bind a port you are already listening on. Pass
`allow_address_takeover=True` if you were relying on that. POSIX is unchanged.

**Ports are validated.** `tcp_check`, `wait_for_port`, `scan_ports`,
`scan_hosts`, `get_pmtu`, `discover_mtu` and `get_tcp_mss` raise `ValueError`
outside `0-65535` and `TypeError` for a non-`int` — including a service-name
string, which must go through `get_default_port` first. Previously the socket
layer masked the value to 16 bits, so `port + 65536` answered about `port`.

**`resolve_nslookup` raises** for an option-shaped, empty or whitespace query
(rejected before any subprocess starts), and for a non-zero exit carrying no
"no such name" marker. An exit-1 NXDOMAIN is still `[]`.

**`netimps.__version__` is read, not restated.** It now comes from
`importlib.metadata.version("netimps")` rather than a literal in
`__init__.py`, so it cannot drift from the distribution metadata. A source
tree with no installed metadata reports `0.0.0+unknown` rather than a stale
number.

**CLI:** positional arguments are required rather than defaulting to `""`, and
every diagnostic moved from stdout to stderr so `--json` stays parseable on
error paths.

### Validation

| check | result |
| --- | --- |
| tests | 657 passed, 6 skipped (432 before this cycle), on **both** 3.14 and the 3.9 floor |
| tests, with the network guard active | 657 passed |
| tests, against a simulated wildcard resolver | 657 passed |
| `mypy src/netimps` | clean for `--platform linux`, `darwin` and `win32` (27 errors before) |
| `mypy tests/typing/api.py` | clean under `tests/typing/consumer.ini` (never executed before) |
| `black --check` | clean, 29 files |
| `mkdocs build --strict` | exit 0 |
| `python -m build` | wheel + sdist; `py.typed` and both shipped docs present; no `*.local.*` leakage; editable re-install intact |
| `leak_check.py` | PASS |

**CI:** run `35601208005`, all ten matrix entries (Python 3.9–3.14 on Ubuntu,
3.9 and 3.14 on Windows and macOS) plus the lint job, green. The probe
workflow was validated separately in run `35600571900`, green on all three
runners.

The macOS behaviour this release fixes cannot be checked on the development
machine, so it was validated on runners. Four earlier runs failed and are the
reason several of these fixes exist in their current form — notably
`IP_DONTFRAG` being 28 on Darwin where it is 67 on FreeBSD, and the multicast
scope living in the address rather than in `ipaddress.is_link_local`. Skip
reasons are printed (`pytest -rs`) so a skipped platform test cannot be
mistaken for a passing one; on macOS no smoke test skips, which is what makes
"IPv6 ping works there" a measurement rather than an inference.

### Publication state

Prepared, `main` pushed, tag awaiting the release workflow.
