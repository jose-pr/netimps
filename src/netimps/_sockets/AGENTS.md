# `netimps` socket helpers — public API header

Header-file-style reference for the socket-helper, routing and path-MTU names of
the `netimps` package: every public export with its signature, arguments,
contract and gotchas, so it can be used without reading its source. It ships
inside the package and is self-contained; the top header is `netimps/AGENTS.md`.
Development documentation lives with the source at
<https://github.com/jose-pr/netimps>.

This directory (`netimps/_sockets/`) is private and not an import path: every
name below is imported from `netimps`.

## Socket helpers

- **`bind(address="", port=0, *, family=None, kind=SOCK_DGRAM, reuse_address=True, allow_address_takeover=False, reuse_port=False, broadcast=False, connreset=None, interface=None, options=(), listen=None)`**
  — create, configure and bind in one call. `family=None` takes the family
  from the address (`family` is `4`/`AF_INET` or `6`/`AF_INET6`, anything else
  raises `ValueError`): an IPv6 literal (or an `interface=` whose address is
  IPv6) gives `AF_INET6`, an IPv4 literal `AF_INET`, and a name `AF_INET`
  when it has an IPv4 address, else `AF_INET6`. **The wildcard `""` is
  IPv4**; ask for `"::"` to listen on IPv6. `connreset=None` is `False` for a
  datagram socket (Windows: an ICMP port-unreachable does not surface as
  `ConnectionResetError` on a later receive) and leaves other sockets alone;
  `True` keeps the platform's reporting. `interface` accepts the usual union
  (`Interface`, MAC, adapter name, address) and **raises `ValueError`** if
  unresolvable rather than silently binding the wildcard. `options` is read
  once, so a generator is honoured. `reuse_port=True` shares the port with other
  sockets that ask: `SO_REUSEPORT` on POSIX, and on **Windows**, which has no such
  option, a datagram socket takes the address-sharing path (`SO_REUSEADDR`), so
  two sockets that both pass it bind one port and another process can take the
  port over; a stream socket there stays exclusive. `listen` is ignored for datagram sockets. The socket is closed before any
  exception propagates, so a failed call leaks nothing. A failed bind raises
  `OSError` whose message already leads with the `bind_error_hint` text where
  that recognises the failure; an address that is taken is always
  `AddressInUseError`, any other failure keeps its own `OSError` subclass and
  `errno`.

  > **`reuse_address=True` is not one socket option, and does nothing for UDP.**
  > On POSIX it sets `SO_REUSEADDR` **only for a stream socket**, where it
  > permits binding an address still in `TIME_WAIT`. `TIME_WAIT` is a TCP
  > concept: on a *datagram* socket the option's one remaining effect on Linux
  > is to permit duplicate bindings of **live** sockets, so it is not set for
  > datagram sockets. Measured on WSL with the option set — a second `bind()`
  > of the same live UDP `addr:port` succeeded and the datagram went to the
  > **second** socket, with the holder getting no error. `socket(7)` is explicit
  > that the exception is an active *listening* socket, and a UDP socket never
  > listens. Share a UDP port deliberately with `reuse_port=True`
  > (`SO_REUSEPORT`, the option designed for it) or `allow_address_takeover=True`;
  > `multicast_socket` sets what it needs itself. On
  > **Windows** `SO_REUSEADDR` means something else entirely: it lets **any
  > process** bind an `addr:port` another socket is already listening on, and
  > the later binder can win subsequent connections — reproduced on Windows 11,
  > where a plain second bind was refused with `EACCES` while one through this
  > function succeeded. So on Windows `reuse_address=True` sets
  > **`SO_EXCLUSIVEADDRUSE`** instead, the safe request with the same intent
  > and what a plain stdlib bind gets by default. The literal option remains
  > reachable, but only by asking for it by its consequence:
  > `allow_address_takeover=True`. On POSIX that flag adds nothing, since
  > `reuse_address` already sets exactly that option.

  > **An explicit `(SOL_SOCKET, SO_REUSEADDR, nonzero)` in `options=` counts as
  > `allow_address_takeover=True`.** It has to: Windows refuses `SO_REUSEADDR` on
  > a socket that already carries `SO_EXCLUSIVEADDRUSE`, reporting a bare
  > `WSAEINVAL` that names neither option — and this function sets
  > `SO_EXCLUSIVEADDRUSE` for both values of `reuse_address`, so without the
  > rule the stdlib-shaped spelling of "share this address" would not work. A
  > zero value is an explicit opt-*out* and is not read as a request.
  > `bind_error_hint` explains `WSAEINVAL`, since on its own it is
  > undiagnosable.
  > **On Windows `SO_EXCLUSIVEADDRUSE` is set for *both* values of
  > `reuse_address`.** Setting it only for `True` would leave
  > `reuse_address=False` setting *nothing* -- and nothing is the unsafe state
  > there: a *more specific* `SO_REUSEADDR` bind takes traffic from a
  > non-exclusive wildcard holder. Reproduced: a thief on `127.0.0.1` received
  > the datagram while the holder on `0.0.0.0` got nothing and no error. So the
  > flag that reads as "strictest" would be the least strict one available.
  > `reuse_address` governs POSIX `SO_REUSEADDR` only;
  > `allow_address_takeover=True` is the single way to opt into a takeover.
- **`AddressInUseError(NetimpsError, OSError)`** — what `bind()` raises when the address is
  taken, on every platform and interpreter. The platforms surface that
  situation three ways: `PermissionError`/errno 13 on Windows 3.14,
  `OSError`/errno 10013 on 3.9, `OSError`/errno 10048 without
  `allow_address_takeover`. The first is actively misleading — Windows has no
  privileged ports, so a `PermissionError` there describes a mechanism that
  does not exist.

  `errno` is `EADDRINUSE`, the message is `bind_error_hint()`'s text, and the
  original exception is chained as `__cause__` (so `winerror` is still
  reachable). Subclasses `OSError` (and `NetimpsError`) but **not** `PermissionError`, so
  `except OSError` is unaffected while `except PermissionError` stops catching
  this. A real POSIX `EACCES` on a port below 1024 is untouched.

  A duplicate UDP bind is refused on every platform under the defaults — see
  the `reuse_address` box above. Sharing is opt-in through `reuse_port=True` or
  `allow_address_takeover=True`, and only then does a second bind succeed.
- **`SocketOption(level, name, value)`** — a named triple for `bind`'s
  `options=`. A `NamedTuple`, so it *is* a tuple: bare `(level, name, value)`
  tuples keep working and code that unpacks these does too. Purely so a list of
  them reads as something better than `Iterable[Tuple[int, int, Any]]`.
- **`disable_connreset(sock) -> bool`** — stop Windows reporting an ICMP
  port-unreachable provoked by an earlier send as `ConnectionResetError` on a
  *later, unrelated* receive, which kills a server's receive loop over a packet
  some other host did not want. Returns whether anything changed (`False` off
  Windows). `bind()` already applies it to every datagram socket it makes.

  This is the inverse face of a rule documented under `discover_mtu`: POSIX
  delivers asynchronous ICMP errors only to *connected* sockets, so the surprise
  does not arise there.

  **There is no stdlib route to it**, which is why it lives here. Measured on
  3.14: CPython exports no `socket.SIO_UDP_CONNRESET` on any version, and even
  given the documented value (`0x9800000C`) `socket.ioctl` **whitelists**
  commands and answers `ValueError: invalid ioctl command`. So this goes through
  `WSAIoctl` by `ctypes`. A `getattr(socket, "SIO_UDP_CONNRESET", None)` version
  — the obvious one — is a silent no-op on every platform.

  **A call, not a hidden side effect on a socket you made elsewhere.** The report
  is sometimes wanted: a client talking to one peer learns the peer is gone, so
  `bind(..., connreset=True)` keeps it. A server loop almost always wants it off.
- **`set_buffer_size(sock, *, receive=None, send=None) -> (receive, send)`** — grow
  `SO_RCVBUF`/`SO_SNDBUF` and report what was **granted**, read back with
  `getsockopt` rather than echoed from the request. Default UDP buffers are small
  (64 KiB on Windows), so a burst of large datagrams overruns them and the tail
  is dropped, which at the protocol level looks like loss and costs a timeout.

  **The kernel is not obliged to agree and does not say so**: `setsockopt`
  succeeds and then grants less, capped by `net.core.rmem_max` on Linux — which
  also *doubles* what is asked, so a read-back above the request is normal there
  and not a bug. The silent partial grant is the failure mode, hence the return
  value. Only ever grows, so it cannot undo earlier tuning; `None` skips a
  direction, and both `None` is a pure query. A shortfall is logged once per
  socket at `WARNING` on `logging.getLogger("netimps._sockets")`; no handler is
  installed.

  > **A link-local `interface=` address is bound with its zone.** The same
  > `fe80::` address can exist on several adapters, so the kernel cannot tell
  > which is meant from the address alone: BSD refuses the bare form with
  > "Can't assign requested address", while Windows and Linux happen to accept
  > it — which is why this only ever failed on macOS. The interface's index goes
  > in as the scope id, the same rule `UDPEndpoint.reply_socket` applies to a
  > link-local destination.

- **`bind_error_hint(exc, port=None) -> str | None`** — an actionable sentence
  for a bind failure, recognising POSIX errnos *and* Windows `10013`/`10048`.
  Returns `None` for anything unrecognised, so the caller keeps the original
  error. **Does not raise** — what to do with a failure is the caller's call.
  `bind()` already puts this text in its own exception; call this for an
  `OSError` from elsewhere.

- **`get_source_ip(dst="8.8.8.8", port=80, *, ipv6=None) -> IPAddress | None`** —
  which local address the kernel would use to reach `dst`. `dst` accepts
  `HostLike`. **Sends no packets** — `connect()` on a UDP socket only
  consults the routing table. The answer depends on `dst`: with a VPN up, a
  public probe returns the tunnel address and a LAN probe the physical one.
  Correct where hostname resolution picks a VM adapter. `ipv6=` selects the
  family; it is not guessed from `":" in dst`, because **a hostname never
  contains a colon** and every name would be probed as IPv4, a v6-only one
  answering `None`. The returned address carries **no `%zone`** — the zone
  identifies the adapter, and `get_interface` is the way back to it.
- **`get_free_port(src="127.0.0.1", *, family=None) -> int`** — bind port 0 and
  read it back. `src` is any `HostLike` and `family` follows it as `bind`'s
  does (an IPv6 address gives `AF_INET6`). **Inherently racy** — the port frees the instant it returns; if
  you can, bind port 0 in the server itself instead. `SO_REUSEADDR` is
  deliberately *not* set (it would hand back a `TIME_WAIT` port).
- **`tcp_check(dst, port, *, timeout=3.0) -> bool`** — the honest reachability
  test. Proves the handshake completed, not that the service is healthy; a
  filtered port is indistinguishable from a closed one.

  Never raises for a reachability *outcome* — refused, timed out, unresolvable
  and unreachable are all `False` — but two argument bugs are raised rather
  than answered: a network as `dst` (`TypeError`), and a `port` outside
  `0-65535` (`ValueError`) or not an `int` (`TypeError`).

  **`timeout` bounds the whole call**, across every address `dst` resolves to.
  `socket.create_connection` would apply it once *per resolved address* after
  an unbounded `getaddrinfo`, so a name with N addresses could take
  N × `timeout`; here resolution happens once and the connects share one
  deadline. `timeout=0` is **floored** to 0.05s
  rather than taken literally: `settimeout(0)` means non-blocking, which
  reported every open port as closed. `timeout=None` blocks.
- **`wait_for_port(dst, port, *, deadline=30.0, interval=0.1, timeout=None)`**
  — poll until it answers. Backs off, growing by half each round, to the larger
  of 1s and `interval`, so an interval above a second is never shortened. `deadline` bounds the whole wait
  and is honoured even when individual connects block — it cannot overrun by
  more than one attempt, because `tcp_check` bounds *itself* overall rather
  than per resolved address. `timeout` is one attempt's connect timeout and
  defaults to `interval` raised to at least 1s. An out-of-range `port` raises
  from `tcp_check`.

## Routing, hops and MTU

- **`get_route(dst="8.8.8.8", *, ipv6=None) -> Route`** — `.dst`, `.src`,
  `.gateway`, `.interface_index`, `.on_link`. **First hop only, deliberately**
  — that is available unprivileged everywhere, unlike the full path. Never
  raises for an unknown route; unknown pieces are `None`/`0`. A network as
  `dst` still raises `TypeError`. A hostname goes through `getaddrinfo`, so
  `ipv6=` selects which of its records the route is computed for;
  `gethostbyname` is IPv4-only, so through it an AAAA-only name would reach no
  lookup at all.

  Both families are looked up on every supported platform: `GetBestRoute2` on
  Windows (it asks the kernel which route *it* would pick, so the
  longest-prefix matching is not reimplemented), `/proc/net/route` and
  `/proc/net/ipv6_route` on Linux, and `route -n get` on macOS/BSD — the one
  platform where this runs a short-lived program (`route`, 5s cap), because
  there is no `/proc` to read. A missing or hung `route` gives `on_link=None`.
  Loopback short-circuits without running anything.

  > **`Route.on_link` is `Optional[bool]`**: `True` when no gateway is needed,
  > `False` when one is, and **`None` when the next hop could not be looked up
  > at all**. `gateway is None` would turn "we never looked" into a confident
  > `True` — on macOS, where the lookup has no source to read,
  > `get_route("1.1.1.1")` from a `192.168.64.3/24` host would report
  > `on_link=True`. `None` is falsy, so `if route.on_link:` takes the safe
  > branch; `route.on_link is True` is a question with an answer, and
  > `route.on_link is False` really means "through a router". A present
  > `gateway` wins over the recorded flag, since it is proof on its own.
  >
  > **Test `on_link` itself**, not `.gateway is None`, which cannot tell
  > on-link from unknown. `Route` is **hashable**, and `__eq__` compares `dst`,
  > `src`, `gateway`, `interface_index` and `on_link`.
- **`count_hops(dst, *, max_hops=30, timeout=1.0, allow_traceroute=True, ipv6=None)`**
  — uses raw-socket probes when permitted, otherwise drives the system
  `traceroute`/`tracert`, so it **works unprivileged**. Only the hop number and
  destination address are parsed, never localised prose. A missing or hung
  program gives `None`.
  `allow_traceroute=False` requires the in-process path and raises
  `PermissionError` instead. `ipv6=` picks the family and the probes follow
  (ICMPv6 with `IPV6_UNICAST_HOPS`, and the platform's v6 traceroute);
  `gethostbyname` is IPv4-only, so through it a v6 destination would return
  `None`, read as "never answered" rather than "never asked". **`None` means
  "no answer", never
  "unreachable"** — firewalls routinely drop ICMP even for an elevated process.
- **`discover_mtu(dst, *, low=576, high=9000, timeout=1.0, src=None, port=80, probe=True, method="icmp", tries=1, ipv6=None, ttl=None)`**
  — **measures** the path MTU by binary-searching probes, so packets really
  traverse the path. Returns the MTU **including headers**, comparable with
  `Interface.mtu`. The name is **resolved once**: the target, the family and the
  header overhead (28 bytes for IPv4, 48 for IPv6) come from that one answer,
  and `ipv6=` picks it.

  **The answer is a measurement, not `high`.** A path cannot be wider than the
  link it leaves by, so a probe at `high` that is answered does not end the
  search: it goes on up to that link's MTU (`Interface.mtu` of the outgoing
  interface; the loopback interface for a destination on this host). A `high`
  above that MTU is lowered to it. Only when the MTU cannot be read is `high`
  the ceiling, and a result equal to it means **at least `high`**. The platform
  `ping` has a largest probe of its own: a 65500-byte payload on Windows, and
  `net.inet.raw.maxdgram` on macOS and the BSDs (8192 on macOS 15.7); a UDP
  socket there stops at `net.inet.udp.maxdgram` (a 9216-byte payload). A local
  destination the search takes that far is reported at the loopback MTU (65535
  on Windows, 65536 on Linux, 16384 on macOS); any other path that reaches the
  limit is retried with `"udp"` and otherwise reported at the limit, meaning
  "at least".

  | `method` | How |
  | --- | --- |
  | `"icmp"` | DF-flagged echo. Default; works anywhere `ping` does. |
  | `"udp"` | Datagrams of growing size to `port`, with DF set per platform (`IP_MTU_DISCOVER` on Linux, `IP_DONTFRAGMENT` on Windows, `IP_DONTFRAG` on BSD, plus the `IPV6_` counterparts). Needs something there that replies. Measures what a **UDP application** can actually push, which a middlebox may cap below the ICMP figure. |
  | `"tcp"` | **Does not probe** — TCP is a stream and the kernel segments it, so a large `send()` becomes many packets. Reads the negotiated MSS and adds the header back (40 for IPv4, 60 for IPv6). |

  **`None` has two meanings, both deliberate.** Either the destination never
  answered — indistinguishable from "every size was too big", and common since
  most cloud firewalls drop echo — **or the don't-fragment bit could not be
  set** for this destination on this platform (BSD's `ping6`, and any kernel
  that refuses the DF option on the `udp` path). Without DF the probe is
  fragmented and reassembled, every size survives, and the search would return
  `high` as though it had measured something.

  `tries=` and `ttl=` reach `ping` for the ICMP method; `ipv6=` applies to
  every method. `size` and `dont_fragment` are what the search varies, so they
  are not parameters and passing either raises `TypeError`. `probe=False` skips
  probing entirely and returns `get_pmtu` instead. `method` is
  `"icmp" | "tcp" | "udp"`.
- **`get_tcp_mss(dst, port, *, timeout=3.0, ipv6=None) -> int | None`** — the negotiated TCP
  maximum segment size. `ipv6=` picks the family a host name connects over, and a
  destination of the other family gives `None`. **Opens a real connection** to read it, then closes.
  MSS is normally the path MTU minus 40, so a reduced value signals a tunnel
  shrinking the path (measured: 1412 over a VPN on a 1500-MTU link, 32741 on
  loopback). `None` where `TCP_MAXSEG` is unavailable or the connection fails.
  This is what the two *kernels agreed*, not what a middlebox further along
  will pass.
- **`get_pmtu(dst, port=80, *, ipv6=None) -> int | None`** — a **lookup**, not a
  measurement: reads the path MTU the kernel has *already* learned, and sends
  nothing. `discover_mtu(..., probe=False)` is exactly this.

  - **Linux answers for both families**, via `IP_MTU` and `IPV6_PATHMTU`
    (measured: 65535 for `127.0.0.1`, 65536 for `::1`). It is still a weaker
    question than `discover_mtu`: the kernel only knows a path MTU once its own
    discovery has learned one, so `None` remains a common answer for a fresh
    destination, and a value it does have may be the **local link** MTU rather
    than the path minimum.
  - **Windows always returns `None`**, and there is no other route to the
    answer. It has no `IP_MTU`, `IP_MTU_DISCOVER` or `IPV6_PATHMTU`;
    `MIB_IPFORWARDROW.dwForwardMtu` reads **0** (verified via `GetBestRoute`;
    Microsoft lists it as unsupported), and the newer `MIB_IPFORWARD_ROW2`
    dropped the field entirely. Route MTU lives at the interface level there,
    which is `Interface.mtu`; probing with `discover_mtu` is the only way to
    learn a *path* MTU.
  - macOS/BSD expose no IPv4 equivalent either, so v4 there is `None` too.

  > **A `getattr(socket, "IP_MTU", None)` guard returns `None` everywhere**,
  > Linux included, because `IP_MTU`, `IP_MTU_DISCOVER` and `IP_PMTUDISC_DO`
  > are **not exported by CPython on any platform** (measured on 3.13 and
  > 3.14). The Linux numbers are named from `<linux/in.h>` instead.
  > `IPV6_PATHMTU` also returns a `struct ip6_mtuinfo` — a `sockaddr_in6`
  > followed by the MTU — not the bare int `IP_MTU` gives back, so reading it
  > as an int would decode the address family as the MTU.

> **These answer different questions.** On one real host the local link was
> 9000, `get_pmtu` returned `None`, and `discover_mtu` found the true 1500 — a
> bottleneck several hops away that nothing local could reveal. Use
> `Interface.mtu` for the local link, `discover_mtu` for the path.
>
> **Header sizes are family-aware.** IPv4 overhead is 20+8 (ICMP/UDP) or 20+20
> (TCP); IPv6 is 40+8 and 40+20. Assuming IPv4 on a v6 path under-reports by
> exactly 20 bytes.

## Payload sizing

**`max_udp_payload(mtu, *, ipv6=False)`** — the largest UDP payload that fits
without fragmenting: `mtu - ip_header - 8`, so `1472` for a 1500 MTU and `1452`
for v6. Pair it with `Interface.mtu` to size a datagram to the interface it leaves
by.

- It takes an **`int`, not an `Interface`**, on purpose. `Interface.mtu` is
  `Optional[int]` and **Windows reports no MTU for the loopback adapter**, so
  whether to fall back to 1500 or to refuse is the caller's decision — accepting
  an `Interface` would hide it. (It also means MTU logic cannot be exercised on
  Windows loopback.)
- The v4 figure uses the **minimum** 20-byte header, so a packet carrying IP
  options can still fragment; subtract more if you set any. IPv6 counts its
  extension headers as payload, so 40 is exact only without them.
- Returns `0` rather than a negative for an MTU too small to carry anything.
