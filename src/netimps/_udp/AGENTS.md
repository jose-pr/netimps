# `netimps` UDP — public API header

Header-file-style reference for the UDP names of the `netimps` package: every
public export with its signature, arguments, contract and gotchas, so it can be
used without reading its source. It ships inside the package and is
self-contained; the top header is `netimps/AGENTS.md`. Development documentation
lives with the source at <https://github.com/jose-pr/netimps>.

This directory (`netimps/_udp/`) is private and not an import path: every name
below is imported from `netimps`.

## UDP with arrival interface

**`UDPEndpoint(sock, *, pktinfo=True, interfaces=())`** — wraps a bound UDP socket so each
datagram reports which interface it arrived on. Essential for broadcast
protocols, where a wildcard-bound server otherwise cannot tell which network a
request came from.

`recv(bufsize=65535, *, resolve_interface=True) -> Datagram`, a `NamedTuple` of
`.data`, `.sender`, `.destination`, `.interface_index`, `.interface`,
`.control_truncated` and `.truncated`, plus the property `.is_unicast`
(`is_unicast(destination, interface)`, or `None` when `destination` is unknown
because there was no pktinfo). `send(data, dst, port, *, src=None) -> int` pins the
outgoing interface; `dst` accepts `HostLike` and `src` the usual loose
interface spec (`Interface`, MAC, adapter name or address). `close()` closes
the wrapped socket, and the endpoint is a **context manager**
(`with UDPEndpoint(bind("", 67)) as endpoint:`) and an **async context
manager** (`async with UDPEndpoint(bind("", 67)) as endpoint:`).

**`interfaces`** — the interfaces this endpoint serves, each an `Interface` with
an index, any iterable; kept as a tuple in `.interfaces`, empty (the default) for
an endpoint that serves all. A value that is not an iterable of `Interface` is
`TypeError`, and an `Interface` with no index is `NetimpsValueError`, both before
the socket is touched. **`admits(datagram: Datagram) -> bool`** is true when
`.interfaces` is empty, or when `datagram.interface_index` is the index of one of
them; a datagram with no arrival interface (index `0`, as on a socket that reports
no pktinfo) is not admitted by a limited endpoint. `recv`, `arecv` and `datagrams`
**do not filter**: the caller asks `admits`, so that it can count and report what
it drops. The limit travels with the endpoint, so code that is handed endpoints
cannot lose it.

**`close()` and `await aclose()` are each complete on return** — the reader
thread, if `arecv` started one, has left and the socket is closed — **and
harmless when called again**, in either order. From a coroutine use `aclose()`:
`close()` joins the thread on the calling thread and so holds up every other
task on the loop until it has gone, while `aclose()` waits for it with the loop
running.

`recv` and `send` raise the builtin `TimeoutError` when a timeout set on the
wrapped socket expires, on every supported Python (before 3.10
`socket.timeout` is only an `OSError`, so it is translated).

- **One option per address family, and they are not spellings of each other.**
  `IP_PKTINFO` is the IPv4 option; setting it on an `AF_INET6` socket
  *succeeds* on Linux and then no cmsg ever arrives. The family selects the
  option to set (`IP_PKTINFO` / `IPV6_RECVPKTINFO`), the cmsg type to match
  (`IP_PKTINFO` / `IPV6_PKTINFO` — on Linux the v6 pair are distinct constants,
  49 and 50) **and** the struct layout (`in_pktinfo` is index-then-addresses,
  `in6_pktinfo` is the 16-byte address **first**, then the index). An IPv6
  endpoint therefore reports a real `interface_index`, `interface` and
  `destination`; reporting `0`/`None`/`None` while claiming `has_pktinfo`
  would be the failure of reading the v4 option on a v6 socket.
- **Two honest flags, decided once at construction from the socket's own
  family.** `has_pktinfo` — `recv` will report the arrival interface;
  `False`, never an optimistic `True`, whenever the option for *this* family is
  missing or refused. `has_src_pinning` — `send(src=)` can be honoured;
  `False` where there is no pktinfo cmsg for the family, or the socket cannot
  use it (see **FreeBSD** below).
- **FreeBSD, IPv4: no `IP_PKTINFO`, other options.** The arrival address and
  interface come from `IP_RECVDSTADDR` (7) and `IP_RECVIF` (20), so
  `has_pktinfo` is `True` there and `destination` and `interface_index` are
  filled. The source is pinned with a control message of number 7
  (`IP_SENDSRCADDR`), which the kernel accepts **only on an unconnected socket
  bound to the wildcard address** (errno 22 otherwise): `has_src_pinning` is
  `True` for such an endpoint and `False` for one bound to an address, where
  `send(src=)` sends unpinned. IPv4 has no pin by interface index there, so an
  `Interface` (or name or MAC) given as `src` pins that interface's IPv4 address,
  and a `src` naming no IPv4 address raises `ValueError`. A `src` of `0.0.0.0`
  is sent unpinned: the kernel refuses a zero source there (errno 22), and
  unpinned is what Linux and macOS make of one. IPv6 on FreeBSD works as on
  macOS.
- **Windows is supported, through `WSARecvMsg`/`WSASendMsg`.** Both flags are `True`
  there for v4, v6 **and** dual-stack `::`, on 3.9 through 3.14 — see
  **Ancillary data** in `netimps/_msg/AGENTS.md`. `UDPEndpoint` calls
  that backend *directly* rather than the patched stdlib method, so
  `NETIMPS_SOCKET_PATCH=0` does not cost it pktinfo. The per-platform
  `in_pktinfo` layout difference is handled internally; this is the wrapper that
  exists so callers need not know it.
- **A v4 arrival on an `AF_INET6` endpoint always reports the v4-mapped form**
  (`::ffff:127.0.0.1`), on every platform. That takes work, because the
  platforms disagree: Linux and macOS carry the mapped address in the v6 cmsg,
  while Windows reports a *plain* v4 address at level `IPPROTO_IP` and is the
  only one that reports it at all — its v6 option delivers no cmsg for a v4
  arrival. On Windows the same datagram's `sender` is already mapped while its
  cmsg is not, so the two halves contradict each other until normalised.
- **One thing Windows cannot do: pin by interface index alone.** It sends a zero
  source address *literally* — measured, a pin of `0.0.0.0` arrives from
  `0.0.0.0` — where Linux reads zero as "kernel chooses". An index-only `src`,
  or a `src` of `0.0.0.0` or `::`, therefore raises `ValueError` there in either
  family, rather than sending from the wrong address. Pass an address-bearing
  `src`.
- **A dual-stack `AF_INET6` endpoint pins an IPv4 source** (plain or
  `::ffff:`-mapped) on Windows, Linux and, unmeasured, elsewhere; on Windows it
  is sent as an `IPPROTO_IP` control message.
- **`send` to a host name works pinned or not**, on Windows too: the name is
  resolved for the socket's family.
- **Degrades rather than failing**, where a platform still cannot serve it:
  `recv` falls back to `recvfrom` with empty interface fields, and `send` sends
  unpinned. Check the two flags rather than inferring from an empty result.
- **`pktinfo=False` governs receiving only.** Sending needs no socket option,
  so `send(src=)` is still honoured on an endpoint built with it.
- **`send(src=)` pins the interface index as well as the source address.** A
  fixed `ipi_ifindex=0` would only ever pin an address. It raises `ValueError` for a `src` that names no local address or interface
  (silently sending from another adapter is the failure mode `src` exists to
  prevent) and for an IPv6 `src` on an `AF_INET` endpoint — Linux *accepts and
  ignores* a v6 cmsg on a v4 socket, so there is no correct silent behaviour
  available. An `OSError` from the kernel, meaning a source this host cannot
  send from, propagates; only platform incapability degrades to `sendto`.
- **`async arecv(bufsize=65535, *, resolve_interface=True)`**,
  **`async asend(data, dst, port, *, src=None) -> int`** and
  **`datagrams(bufsize=65535, *, resolve_interface=True, on_error=None) ->
  AsyncIterator[Datagram]`** — `recv()` and `send()` awaited, and an `async for`
  over arrivals:

  ```python
  async for packet in endpoint.datagrams():
      with endpoint.reply_socket(packet) as reply:
          reply.sendto(answer(packet), packet.reply_address)
  ```

  `datagrams()` stops at the first receive error, closing the loop's `async for`
  with that exception: a loop that swallows errors is how a dead server looks
  healthy. `on_error` opts out per error: it is called with the exception and
  returns true to carry on with the next datagram, false to stop with that error.
  The caller decides, so log or count inside it. The error a `close()` causes
  ends the loop quietly and does not reach it.

  **Closing ends a pending wait.** `close()` or `aclose()` from another task
  wakes a task in `arecv` with `RuntimeError` and finishes a `datagrams()` loop,
  with the reader unregistered, on every loop type. **The socket's timeout is
  never changed**: `arecv` and `asend` make one call non-blocking and restore
  the timeout afterwards, so `gettimeout()` is the same before and after and a
  later `recv()` waits as it always did. `asend` waits for writability, with the
  loop free, when the kernel's send buffer is full.

  **Pktinfo survives on every loop type**, which is not free. The Windows default
  `ProactorEventLoop` raises `NotImplementedError` from `add_reader`, and its own
  `recvfrom` discards ancillary data; `_overlapped` exposes no `WSARecvMsg`, so
  there is no IOCP route without private API, and
  `DatagramProtocol.datagram_received(data, addr)` has no slot for cmsgs. So on
  such a loop a thread waits — and it **reports readability only, never reads**.
  The `recv` stays on the loop, so `bufsize` is still per call and
  `.truncated` still means what it says.

  One waiter at a time: this is a receive loop's method, and two coroutines
  awaiting one endpoint would race for the same datagram however the waiting were
  arranged. The thread, where there is one, is created on the first `await` and
  joined by `close()` or `aclose()`. `recv()` is unaffected — the synchronous path is untouched.

  **Cancelling the awaiting task is a clean shutdown**, which is the ordinary
  server one: cancel the receive task, then close the endpoint. A cancelled
  `arecv` unregisters its reader, so the loop is not left watching a socket that
  is about to close. Closing first and cancelling after is just as clean: the
  reader is removed by the descriptor it was registered under.

  **A second loop rebinds.** Serving one endpoint from a new loop —
  `asyncio.run(serve())` twice, or a server stopped and started again — retires
  its thread and starts another. A thread keeps the loop it started with, so
  without the rebind the second run would receive nothing and the thread would
  die posting to a closed loop, with the traceback going to stderr where no
  caller could see it.

  **`asyncio` is imported lazily**, never by `import netimps`. A caller using
  only the value types pays nothing for it.
- **`has_pktinfo(family=AF_INET) -> bool`** — whether a UDP socket of that
  family (`4`/`AF_INET` or `6`/`AF_INET6`; anything else raises `ValueError`) can report each datagram's arrival interface *on this host*. The
  question to ask **before** choosing how to bind: with it, one wildcard socket
  serves every address and still knows which one a datagram reached; without
  it, the wildcard has to be expanded into a socket per address — and on Linux
  that per-address socket receives no broadcasts at all.

  ```python
  socks = [bind("", 67)] if has_pktinfo() else [bind(str(a), 67) for a in addrs]
  ```

  **Decided by asking a socket, never by testing a constant's name.**
  `getattr(socket, "IP_PKTINFO", None)` is `None` on CPython 3.9–3.11 on *every*
  platform — the constant arrived in 3.12 — while the kernel supported it
  throughout, so a name test answers "no" on a platform that works. Cached per
  family for the process, since it is a property of the platform and the
  interpreter rather than of any socket. `False` rather than an exception when a
  socket of that family cannot be created, so IPv6 being disabled is an answer
  and not an error.
- **`reply_socket(datagram, port=0, *, connreset=False)`** — a socket bound so
  replies leave from the address the client addressed. The point of pktinfo, in
  one call:

  ```python
  packet = endpoint.recv()
  with endpoint.reply_socket(packet) as reply:
      reply.sendto(answer, packet.reply_address)
  ```

  A wildcard-bound server answering from a fresh socket sends from whatever the
  routing table prefers; DHCP and TFTP clients both check and drop a reply from an
  address they never addressed. Measured contrast: a plain wildcard reply to a
  client that addressed `127.0.0.2` comes from `127.0.0.1`.

  Three traps it absorbs:
  - **A v4 arrival on a dual-stack listener is `::ffff:a.b.c.d`.** Binding that
    needs an `AF_INET6` socket with `IPV6_V6ONLY` off, which Windows does not
    default to — so it is unmapped and answered from a plain `AF_INET` socket.
  - **A broadcast, multicast or unspecified destination must not be answered
    *from*.** These are **classified and skipped**, not discovered by a failed
    bind, because the platforms disagree: Linux binds `255.255.255.255` and
    `239.1.2.3` happily while Windows refuses both, so relying on the refusal
    would mean replying *from* the broadcast address on Linux. The subnet case
    needs interface prefixes, which is what `is_broadcast` supplies.
  - **An IPv6 link-local destination needs a scope id**, taken from
    `datagram.interface_index` and carried as a `%zone` suffix, or the bind is
    refused — the same address can exist on several interfaces and the kernel will
    not guess.

  > **The *sender's* family decides the reply socket's, not the listener's**, and
  > `datagram.reply_address` is what you pass to `sendto`. A dual-stack
  > `AF_INET6` listener sees a v4 client as `::ffff:a.b.c.d`, and deciding
  > from anything else goes wrong in both halves. With pktinfo the `AF_INET`
  > socket is right but `datagram.sender` is still the v6 4-tuple, so the
  > `sendto` shown above raises `TypeError: AF_INET address must be a pair
  > (host, port)`. Without pktinfo there is no `destination`; falling back to
  > the *listener's* family gives an `AF_INET6` socket with `IPV6_V6ONLY=1` on
  > Windows (the platform default, which `bind()` does not clear) — so `sendto`
  > to a mapped address fails with `WinError 10049` and the exchange silently
  > never starts. Deciding from the sender makes the answer the same with or
  > without pktinfo, and `reply_address` gives the peer in the family that was
  > chosen.

  Falls back to the endpoint's own bound address, then the wildcard: a reply from
  the wrong address still beats no reply. The own-address fallback is skipped
  when it is in the wrong family, so a v6 wildcard listener answering a v4 client
  goes to the v4 wildcard rather than offering `::` to an `AF_INET` socket. `connreset=False` by default, as `bind()` does for a datagram socket,
  because a server loop must not die when an earlier answer draws an ICMP
  port-unreachable from a client that has gone.

  **`port` also takes any iterable of ports**, tried in order, for a server that
  pins transfer ports to a range a firewall can allow (`tftp-hpa -R`,
  `dnsmasq --tftp-port-range`). The iterable is materialised once, so a generator
  is safe but must be finite; empty raises `ValueError`.

  > **A held port and an unusable address are different failures, and they move
  > in different directions.** An address that cannot be bound at all advances to
  > the next *address*; a port that is merely held advances to the next *port* on
  > the same address. Conflating them is a silent correctness bug: if every
  > `OSError` advanced the address, a taken `port=` would fall through to the
  > endpoint's own address **with the same port**, and where that bind
  > succeeded the reply would leave from an address the client never
  > addressed — the one failure this method exists to prevent. Measured on
  > Windows 11 ARM64: holding `10.6.0.223:57014`
  > and replying to a datagram that arrived there returned a socket on
  > `127.0.0.1:57014`. So when the ports run out on an otherwise bindable
  > address, this raises **`AddressInUseError`** and binds nothing, rather than
  > answering from somewhere else.
- **The arrival interface comes from an index each endpoint keeps over the
  shared enumeration**, so the default path is not the slow one. Calling
  `get_interfaces()` and scanning it for *every* datagram costs 1.07 ms per
  packet against 0.015 with `resolve_interface=False`, a 70x cost, and 35–42 ms
  per enumeration on a host with many adapters. So `recv()` keeps an
  `index -> Interface` map (0.017 ms per packet) built from the process-wide
  enumeration cache, the one `get_interfaces(cache=True)` reads, and trusts it
  for `INTERFACE_CACHE_TTL` (1 second) counted from that enumeration. Any
  number of endpoints, and the caller's own cached lookups, cost one
  enumeration per second between them.
  An index the map lacks enumerates anew at once, because an unseen index means
  the adapter set changed; negative results are cached so a vanished index does
  not re-enumerate forever. `resolve_interface=False` still skips it entirely
  and never enumerates.
- **`reply_address`** — `sender`, in the family `reply_socket` will use. **Pass
  this to `sendto`, not `sender`.** A v4-mapped sender becomes the plain
  `(host, port)` pair, dropping the flowinfo and scope id that an `AF_INET`
  `sendto` rejects outright; everything else is returned unchanged, including a
  link-local peer's scope id, so it is also the right thing to pass on a
  single-family listener.
- **`truncated`** reports `MSG_TRUNC`: the **payload** did not fit `bufsize`
  and `.data` is the leading part of a longer datagram. A different question
  from `control_truncated`, and the one that silently corrupts a decode — a
  protocol parser handed a message cut mid-field reports a malformed packet
  rather than a short read. Measured on Linux with `bufsize=576`: a 1102-octet
  datagram arrived with the flag set and the flag discarded, leaving the caller
  nothing to check. **Reported, not raised**: deciding that a short datagram is
  fatal belongs to the protocol, not here. It is reported on the no-pktinfo path
  too, which goes through `recvmsg` with a zero-length control buffer rather than
  `recvfrom` precisely because `recvfrom` cannot report it — losing the interface
  is a documented degrade, losing this is silent data loss. **Windows included**:
  a bare `sock.recvfrom(576)` of a larger datagram raises `WinError 10040`
  (`WSAEMSGSIZE`), while `recv()` returns the first 576 octets with
  `truncated=True`, so no `WSAEMSGSIZE` handling is needed around it.
- **`control_truncated`** reports `MSG_CTRUNC`: the kernel had more ancillary
  data than the buffer held. When it is `True` and the interface fields are
  empty, they are empty because something was dropped. The buffer is sized for
  four cmsgs rather than one, so an unrelated option on the raw socket
  (`SO_TIMESTAMP`, `IPV6_RECVHOPLIMIT`) does not silently swallow the
  pktinfo — measured on Linux, where a one-slot buffer kept the timestamp and
  discarded the pktinfo.
- **A dual-stack `AF_INET6` socket needs only its own option.** An IPv4 arrival
  then reports the v4-mapped form (`::ffff:10.0.0.1`) in both `.sender` and
  `.destination`.
- `.destination` for a broadcast is the **broadcast** address, not the
  interface's own — use `.interface` to identify the adapter.
- Pass `resolve_interface=False` in a hot loop and use `.interface_index` —
  enumeration is a syscall. Resolving a MAC or an adapter name in `send(src=)`
  enumerates too; pass an `Interface` in a send loop to avoid it. A `src` that is
  an **address** is used as given and enumerates nothing — the kernel then picks
  the adapter (a `%zone` still names one), so pass an `Interface` when the adapter
  must be pinned as well.
- Wraps rather than subclasses the socket; the raw one stays on `.socket`.
