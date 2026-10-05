# `netimps` ancillary data — public API header

Header-file-style reference for the ancillary-data and `socket`-patch names of
the `netimps` package: every public export with its signature, arguments,
contract and gotchas, so it can be used without reading its source. It ships
inside the package and is self-contained; the top header is `netimps/AGENTS.md`.
Development documentation lives with the source at
<https://github.com/jose-pr/netimps>.

This directory (`netimps/_msg/`) is private and not an import path: every name
below is imported from `netimps`.

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
  `ValueError` does the reverse. So `SC_IOV_MAX` returns a value and a name the
  shim does not answer raises `ValueError`, which is what POSIX does for an
  unrecognised name.

  `SC_OPEN_MAX` is answered as well: **8192**, the size of the C runtime's file
  descriptor table (measured 2026-10-05 on Windows 11, CPython 3.9 and 3.14:
  `os.open` hands out descriptors 0 to 8191 and then fails with `EMFILE`;
  sockets are handles and are not counted). Code written for POSIX reads it
  behind `hasattr(os, "sysconf")` with no guard, and a `ValueError` there fails
  the caller. `SC_NPROCESSORS_ONLN`, `SC_PAGE_SIZE` and the rest still raise.

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
