# `netimps` reachability — public API header

Header-file-style reference for the reachability names of the `netimps` package:
every public export with its signature, arguments, contract and gotchas, so it
can be used without reading its source. It ships inside the package and is
self-contained; the top header is `netimps/AGENTS.md`. Development documentation
lives with the source at <https://github.com/jose-pr/netimps>.

This directory (`netimps/_ping/`) is private and not an import path: every name
below is imported from `netimps`.

## Reachability

**`ping(dst, *, tries=1, timeout=1.0, ipv6=None, src=None, size=None, ttl=None, dont_fragment=False, method="icmp", port=None, cache=False) -> PingResult`**

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
| `cache` | `get_interfaces`'s: `True` or a TTL in seconds reuses a recent enumeration while `src` is resolved; `False` (default) enumerates per call. |
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
