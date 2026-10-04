# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`UDPEndpoint.asend(data, dst, port, *, src=None)`**: `send` awaited, on
  every loop type. It waits for writability, with the loop running, when the
  kernel's send buffer is full.

- **One exception base and four new exported classes.** `NetimpsError` is the
  base of everything netimps raises on its own account;
  `NetimpsValueError(NetimpsError, ValueError)` is for text that is not the
  value it was asked to become; `ResolutionTimeoutError(ResolutionError,
  TimeoutError)` is what the resolvers now raise when a deadline expires
  (`resolve_system`, `resolve_nslookup`, `resolve_wire`, `resolve_doh`);
  `DNSDecodeError(NetimpsValueError)` is the DNS codec's error, formerly the
  private `WireError(ValueError)`.

- **`UDPEndpoint.aclose()`, `async with UDPEndpoint(...)`.** `aclose()` is
  `close()` for a coroutine: it waits for the reader thread `arecv` may have
  started to leave, with the loop running, where `close()` joins it on the
  calling thread. `close()` and `aclose()` are each complete on return and
  harmless when called again, in either order.

- **`Host.resolve()` and `FQDN.resolve()` return the pair `(fqdn, ip)`**, and
  `Host.ip()`, `Host.fqdn()` and `FQDN.ip()` take the resolver options
  (`ns`, `timeout`, `port`, `tcp`, `search`, `backends`, `source`), `ipv6=` and
  `check=`. `check=True` raises `ResolutionError` where `None` would be
  returned: an empty answer, an outage or an empty host. `ip()` of a name looks
  it up and of an address does not; `fqdn()` of an address looks it up and of a
  name does not. With none of `ns`, `port`, `tcp`, `source` or `backends` the OS
  resolver alone answers, as `get_ip` did; naming one selects `resolve()`'s own
  chain. `resolve()` accepts `rdtype=("a", "aaaa")` for both families at once.

- **`MACAddress.__format__` and `__bytes__`**: `f"{mac:-X}"` is `mac.format("-", upper=True)` and `bytes(mac)` is the six octets.
  **`FQDN.encode()`, `bytes(name)`, `FQDN.decode(data)` and `FQDN.decode_at(data, offset)`**
  write and read the RFC 1035 wire form; `decode_at` follows compression
  pointers with loop detection and returns `(name, end)` for use inside a
  message. Malformed data raises `DNSDecodeError`. The package's own reply
  reader shares the same label reader, and now also refuses a label over 63
  octets and a name over 255.

- **`MACAddress.parse`, `FQDN.parse` and `Host.parse`** build the type from
  text, raising `NetimpsValueError` for bad text and `TypeError` for a
  non-`str`; `Host.try_parse(text, default=None)` joins the other two, whose
  `try_parse` gains `default=`. `Host.parse` refuses only empty or blank text.

- **`is_unicast(address, interface=None, *, cache=False)` and `Datagram.is_unicast`**: false for the wildcard, a multicast group and a broadcast (limited or subnet), true otherwise. `Datagram.is_unicast` is `None` when there was no pktinfo to say where the datagram went.

- **WS-Management schemes in the registry**: `wsman` 5985, `wsmans` 5986 (IANA), `winrm` 5985, `winrms` 5986 and `psrp` 5985, so `get_default_port("winrm")` is no longer `None`. `get_default_scheme(5985)` is `wsman` and `get_default_scheme(5986)` is `wsmans`.

- **`cache=` on `resolve()`, `Host.ip/fqdn/resolve` and `FQDN.ip/resolve`, with `clear_resolution_cache()` and `RESOLUTION_CACHE_TTL` (30 seconds).** `False` (the default) never reads or writes the cache, `True` uses the TTL, a number is the TTL, as on `get_interfaces`. Keyed on the name and every option; an empty answer is cached like any other, an outage is not. A call that passes `cache=` neither reads nor writes a `Host`'s memo.

- **`split_zone(text)`**, **`is_local_host(host, *, resolve=False, cache=False)`** and **`split_host` of a `(host, port)` pair**. `split_zone("fe80::1%eth0")` is `("fe80::1", "eth0")`; `is_local_host` is true for a loopback or locally assigned literal, `localhost`, and this machine's own name, and resolves any other name only when asked; `split_host(("h", None), default_port=69)` is `("h", 69)`.

- **`UDPEndpoint.datagrams(*, on_error=None)`**: a callable given the exception from a failed receive; return true to carry on with the next datagram. Without it the loop still stops at the first error.

- Four aliases that already appeared in public signatures are exported:
  `InterfaceLike` (what names a local interface), `InterfaceQuery` (what
  `get_interface` looks up), `PortsLike` and `SocketAddress`.

### Renamed

**Breaking.** No alias is kept: the old name is gone. Acronyms are spelled in
capitals, an input alias is named for the type it becomes, and a predicate or
probe says so in its prefix.

| Before | Now |
| --- | --- |
| `UdpEndpoint` | `UDPEndpoint` |
| `Fqdn` | `FQDN` |
| `FqdnLike` | `FQDNLike` |
| `MACLike` | `MACAddressLike` |
| `AddressLike` | `HostLike` |
| `normalize_host` | `split_host` |
| `interface_for` | `get_interface` |
| `interfaces_for` | `iter_interfaces` |
| `hop_count` | `count_hops` |
| `supports_pktinfo` | `has_pktinfo` |
| `supports_recvmsg` | `has_recvmsg` |
| `socket_patched` | `is_socket_patched` |
| `APIPA` | `LINK_LOCAL_V4` |
| `UdpEndpoint.supports_pktinfo` | `UDPEndpoint.has_pktinfo` |
| `UdpEndpoint.supports_src_pinning` | `UDPEndpoint.has_src_pinning` |
| `Interface.loopback`, `Interface(loopback=)` | `Interface.is_loopback`, `Interface(is_loopback=)` |
| `MACAddress.as_str(sep, upper)` | `MACAddress.format(sep, *, upper=)`, `format(mac, "-X")` |
| `Fqdn.wire` (property) | `FQDN.encode()`, `bytes(name)` |
| `Fqdn.unicode` (property) | `FQDN.to_unicode()` |
| `Fqdn.as_fully_qualified()` | `FQDN.fully_qualified()` |
| `get_ip(x)` | `Host(x).ip()` (removed; `check=True` raises where `get_ip` returned `None`) |
| `Host.fqdn` (property) | `Host.fqdn()` (method; reverse lookup for an address) |
| `Host.ip(refresh)` | `Host.ip(*, check, ipv6, refresh, <resolver options>)` |
| `Fqdn.resolve() -> records` | `FQDN.resolve() -> (fqdn, ip)`; records come from `netimps.resolve(name, rdtype)` |
| `wait_for_port(timeout=)` (whole wait) | `wait_for_port(deadline=)` |
| `wait_for_port(connect_timeout=)` (one attempt) | `wait_for_port(timeout=)` |
| `PingResult.rtt_ms` (milliseconds) | `PingResult.rtt` (seconds) |
| `PingResult.host`, `PingResult(host=)` | `PingResult.dst`, `PingResult(dst=)` |
| `Datagram.local_address`, `Datagram(local_address=)` | `Datagram.destination`, `Datagram(destination=)` (the address the datagram was sent *to*) |

### Changed

- **Method options are keyword-only, breaking.** `UDPEndpoint.recv`, `arecv`
  and `datagrams` take `bufsize` positionally and `resolve_interface` by name;
  `UDPEndpoint.send(data, dst, port, *, src=None)` names its destination `dst`
  (it was `address`) and takes `src` by name; `reply_socket(datagram, port=0,
  *, connreset=False)`; `Interface.primary_ip(ipv6=False, *, loopback_ok=True)`.
  `retry`, `backoff_delays` and `Backoff` no longer take `_sleep` and `_random`
  parameters; the test seams are the module-level `netimps._retry._sleep` and
  `netimps._retry._random`. `UDPEndpoint.datagrams()` is typed
  `AsyncIterator[Datagram]`.

- **`bind()` defaults, breaking.** `family=None` (was `AF_INET`) infers the
  family from the address, so `bind("::1")` is an IPv6 socket; the wildcard
  `""` stays IPv4, and a name is IPv4 when it has an IPv4 address.
  `connreset=None` (was `True`) means off for a datagram socket and
  untouched for any other; `True` and `False` still force it. On Windows an
  unconnected UDP socket from `bind()` no longer raises `ConnectionResetError`
  on a later receive after an ICMP port-unreachable. A failed `bind()` now
  carries the `bind_error_hint` text in the message of every failure that
  function recognises, keeping its `OSError` subclass and `errno`;
  `set_buffer_size` logs one `WARNING` per socket when the kernel grants less
  than was asked.
- **`MACAddress._VALID_MAC` is gone.** It was a private class attribute the class docstring invited callers to read; screen text with `MACAddress.is_valid(text)`.
- **`UDPEndpoint.send(src=<address>)` enumerates no interfaces.** An address `src` is used as given and the kernel picks the adapter (a `%zone` still names one); a MAC or an adapter name still resolves, and an `Interface` still pins the adapter as well.
- **`Host`, `MACAddress`, `PingResult`, `Route` and `Interface` are read-only.**
  Assigning to or deleting any attribute raises `AttributeError`; build a new
  value instead. All six value types (`FQDN` already was) copy and pickle.
  `Interface.ips` is a **tuple** rather than a list, so `iface.ips.append(...)`
  and the other list mutators raise; the constructor still takes any iterable.
  `Interface.loopback` is gone: read `is_loopback`. A cached
  `get_interfaces(cache=...)` call now hands back the stored `Interface`
  objects in a fresh list, copying only `raw`.
- **`Host.fqdn` is a method, and `Host.ip` takes keyword-only options.**
  `host.fqdn` becomes `host.fqdn()`; `host.ip(True)` becomes
  `host.ip(refresh=True)`, which asks again and replaces the memo as before.
  A call that passes any other option neither reads nor writes it. `FQDN.resolve()` no
  longer returns DNS records: call `netimps.resolve(name, rdtype)` for those.
- **Options are keyword-only.** 37 callables keep only their operands as
  positional parameters, and every option after them must be named:
  `ping("h", 3)` is now `ping("h", tries=3)`. Parameter names, order and
  defaults are unchanged. Positional parameters kept:
  none for `get_interfaces`; one for `Backoff`, `Route`, `UDPEndpoint`,
  `count_hops`, `discover_mtu`, `get_free_port`, `get_interface`, `get_route`,
  `iter_addresses`, `max_udp_payload`, `patch_socket_module`, `ping`,
  `set_buffer_size` and `split_host`; two for `Interface` (`name`, `index`),
  `PingResult` (`ok`, `dst`), `backoff_delays`, `get_pmtu`, `get_source_ip`,
  `get_tcp_mss`, `join_group`, `leave_group`, `multicast_socket`,
  `register_port`, `resolve`, `resolve_dnspython`, `resolve_doh`,
  `resolve_nslookup`, `resolve_system`, `resolve_wire`, `retry`, `scan_hosts`,
  `scan_ports`, `tcp_check`, `try_parse` and `wait_for_port`. `recvmsg`,
  `sendmsg`, `CMSG_LEN`, `CMSG_SPACE`, `Datagram` and `SocketOption` keep their
  shapes. `parse`, `try_parse` and `is_valid` name `strict` (the network
  builders' option) instead of an untyped `**kwargs`; `try_parse(value, type,
  default)` is now `try_parse(value, type, default=default)`.
- **`wait_for_port` and `PingResult` say which time they mean.** `timeout`
  is one attempt and `deadline` the whole operation, as everywhere else in the
  package; `PingResult.rtt` is a duration in seconds, where `rtt_ms` was
  milliseconds. A sub-millisecond reply is still `0.0`. The command line's
  `ping --json` keeps its `host` and `rtt_ms` keys, converting for display.
- **`discover_mtu` names the options it forwards.** `tries=`, `ipv6=` and
  `ttl=` replace `**ping_kwargs`; passing `size=` or `dont_fragment=`, which the
  search varies itself, is now Python's own `TypeError` for an unexpected
  keyword rather than a bespoke one.
- **Annotations say what the code accepts and returns.** `resolve`,
  `resolve_dnspython`, `resolve_system`, `resolve_nslookup`, `resolve_wire` and
  `resolve_doh` are overloaded on `rdtype`: `"a"` gives `List[IPv4Address]`,
  `"aaaa"` `List[IPv6Address]`, `"ptr"` `List[str]`, anything else
  `List[Any]`. `method=` on `ping` and `discover_mtu` is
  `Literal["icmp", "tcp", "udp"]`; `is_broadcast(address: IPAddressLike,
  interface: Optional[Interface])`; `join_host` and `split_host` take
  `HostLike`; `parse`, `try_parse` and `is_valid` take `strict` and typed
  `**options`. No parameter of a public callable is a bare `Any`.
- **`MACAddress.try_parse` and `FQDN.try_parse` take text only.** They answer
  `None` (or the new `default=`) for text that does not parse, and raise
  `TypeError` for anything that is not a `str` -- `MACAddress.try_parse(None)`,
  `FQDN.try_parse(3.5)` -- where they returned `None`. The generic
  `netimps.try_parse(value, type)` is unchanged and still answers `default`
  for any object. For `MACAddress`, `FQDN`, `Host` and subclasses it now
  builds a `str` through `Type.parse`; an `int`, `bytes` or built value still
  goes to the constructor.
- **`HOST_DN` is replaced by `get_hostname(*, fqdn=False)`.** A constant
  computed from `platform.node()` made every `import netimps` ask for the host
  name, a WMI query on Windows; the function asks when called. `fqdn=True`
  returns `socket.getfqdn()`.
- **`NETIMPS_NO_SOCKET_PATCH` is replaced by `NETIMPS_SOCKET_PATCH`**, with
  the sense turned round: `0`, `false`, `no` or `off` opts out of the
  import-time `socket` patch, and unset still means patched. A value that is
  none of the documented spellings, or the old variable set to anything,
  raises `ValueError` at import naming the variable, so that a stale setting
  cannot silently re-enable the patch.
- `HostLike` (formerly `AddressLike`) now includes `Host` and `FQDN`, which
  every destination parameter already accepted at run time.
- **Malformed text raises `NetimpsValueError`** from `parse`, `MACAddress`,
  `FQDN`, `split_host`, `join_host` and the query check of
  `resolve_nslookup`; message unchanged. It is a `ValueError`, so
  `except ValueError` still catches it. `parse` now also converts the
  `ipaddress` builders' own errors, chained as `__cause__`.
- `UDPEndpoint.recv` and `send` raise the builtin `TimeoutError` when the
  socket's timeout expires. From Python 3.10 that is what `socket.timeout`
  already is; on 3.9 it was only an `OSError`.
- `ResolutionError` and `AddressInUseError` now also derive from
  `NetimpsError`. Every existing `except` clause keeps matching.
- `resolve_wire` and `resolve_doh` chain an unreadable reply's
  `DNSDecodeError` as the `__cause__` of the `ResolutionError` they raise.

- **Every program netimps runs (`ping`, `nslookup`, `route`, `traceroute`,
  `tracert`) is started the same way.** It is found on `PATH` before anything
  runs, so a missing one is named in the error; standard input is closed;
  `LC_ALL=C` is added to the child's environment, so output no longer follows
  the user's locale; and output is decoded explicitly with
  `errors="replace"` (the OEM code page on Windows, UTF-8 elsewhere) instead of
  the locale's default, so a byte that does not decode no longer raises
  `UnicodeDecodeError` out of `count_hops` or `get_route`. A deadline now kills
  the program's children as well as the program. A program that resolves to a
  `.bat` or `.cmd` is refused. What each function reports for a missing or hung
  program is unchanged.

- **A resolver that could not be asked is no longer an empty answer.**
  `resolve_dnspython` raises `ResolutionTimeoutError` for a timeout and
  `ResolutionError` for every server failing (a SERVFAIL, a refused port) or no
  resolver configuration, where it returned `[]`; `resolve_system` raises
  `ResolutionError` for a temporary failure (`EAI_AGAIN`, `EAI_FAIL`, `herror`
  2 and 3) and keeps `[]` for `EAI_NONAME` and no data; `resolve_nslookup`
  reads the reason after the colon of "can't find <name>: <reason>", so
  Windows' `No response from server` (exit 0) and `SERVFAIL` raise while
  `Non-existent domain` stays `[]`. `resolve()` without `strict` still answers
  `[]`, `strict=True` now raises where it could not before, and `cache=` stores
  nothing for an outage. `resolve_dnspython` no longer turns every exception
  into `ValueError("invalid DNS query")`: only a malformed name or an unknown
  record type is a `ValueError`, an `OSError` is a `ResolutionError`, and
  anything else propagates; dnspython's missing-configuration error no longer
  escapes `resolve()` raw.

- **A missing `dns` extra is named.** `resolve_dnspython` raises
  `ResolutionError` saying `pip install "netimps[dns]"`, and `resolve()` raises
  the same for a request only `dnspython` could serve (a record type the other
  backends do not read) instead of returning `[]`. New `has_dns() -> bool`.

- **`resolve_doh(..., allow_http=False)`.** A URL that is not `https://` is a
  `ValueError` before a request is made; `allow_http=True` accepts plain
  `http://`. The default fetch follows no redirect (a 3xx is a
  `ResolutionError`), reads at most 65,536 bytes of a reply, and names the URL
  in messages without its credentials, query string or fragment.

- **`deadline=` on `resolve()`, `Host.ip/fqdn/resolve` and `FQDN.ip/resolve`.**
  `timeout` is one attempt and means different things per backend (the whole
  call for dnspython and the wire backend, each candidate name for the OS
  resolver and nslookup), so a backend chain, a record-type pair and a search
  list multiplied it. `deadline` is the total for the call, shared by all of
  them; the header states what each `timeout` bounds.

- **`ResolutionError` is an `OSError`, and `NoAnswerError` is new.**
  `ResolutionError(NetimpsError, OSError)`, as the standard library's own name
  failure `socket.gaierror` is, so `except OSError` around a connect catches it
  and `retry()` retries it by default. `NoAnswerError(ResolutionError)` is what
  `check=True` on `Host.ip/fqdn/resolve` and `FQDN.ip/resolve` raises when the
  lookup completed with no such name or record; an outage stays a plain
  `ResolutionError` or `ResolutionTimeoutError`. `retry`'s docstring and the
  header say how to leave `NoAnswerError` out.

### Removed

- **`get_ip(address, ipv6=None)`.** `Host(x).ip()` is the same
  operation with the name kept, and `Host(x).ip(check=True)` raises
  `ResolutionError` where `get_ip` returned `None`. `get_route` and the
  `addr` command use it; `Host(x).resolve()` gives `(fqdn, ip)`.

### Fixed

- **`scan_hosts` bounds the work, not one factor of it, and does not build it
  up front.** The guard counted hosts only and every host-port pair was built
  and queued before the first probe: a /22 with the common ports peaked at
  63 MiB (about 1.7 kB a pair), and a /16 over all ports was 4.3 billion
  tuples. A sweep of more than 4,194,304 probes now raises `ValueError` before
  any probe (a /16 with the common ports is still allowed), and `scan_hosts`
  and `scan_ports` feed their pool as they run: a /22 with the common ports
  peaks near 0.1 MiB.

- **A destination of `None` raises `TypeError`.** `tcp_check(None, 80)`,
  `get_source_ip(None)` and every other `dst` parameter asked the resolver for
  the host named `"None"` and answered `False` or `None`; `dst` takes the same
  allowlist as `split_host` (a string, an address, an interface, a `Host` or an
  `FQDN`), so an `int`, `bytes` or `None` raises. `Host(None)` is still the
  empty host.

- **`bind` reads `options` once, and `reuse_port=True` shares a UDP port on
  Windows.** A generator passed as `options` was used up by a scan for an
  address-takeover request, so none of its options were applied. On Windows the
  flag was a no-op and the second bind of a port raised `AddressInUseError`; a
  datagram socket now takes the address-sharing path, as on Linux and macOS two
  sockets that both pass it bind one port (another process can take the port
  over there too). A stream socket on Windows and every bind without the flag
  stay exclusive.

- **`get_free_port` infers the family as `bind` does** and takes any host:
  `get_free_port("::1")` raised `gaierror`.

- **`wait_for_port` no longer shortens an `interval` above one second**: it
  backed off to a flat second after the first wait, so `interval=5` polled
  sixteen times in twenty seconds instead of four. **`is_local_host` reads the
  `inet_aton` spellings** (`127.1`, `2130706433`, `0x7f.0.0.1`) as the address
  they spell. **One timeout floor:** the scanners floored to 1 ms and
  `tcp_check` again to 50 ms; the scanners now pass the timeout on and the
  floor is `tcp_check`'s 50 ms.

- **`discover_mtu` reports what it measured.** It resolved the name a second
  time for the header overhead and ignored `ipv6=`, so a 1480-byte IPv4 path
  was reported as 1500 when the name's first record was IPv6; the target, the
  family and the overhead now come from one resolution. `method="tcp"` ignored
  `ipv6=` (an IPv4-only listener gave 65555 for `ipv6=True`) and added the IPv6
  header to an IPv4 segment size; it now uses the family that connected, and
  `get_tcp_mss` gains `ipv6=`. A probe that was answered at `high` returned
  `high` (9000 on a loopback whose MTU is 65535); the search now continues to
  the outgoing interface's MTU, and `high` is only the ceiling when that MTU
  cannot be read, where the result means "at least". On macOS the answer
  stopped at 8192, `net.inet.raw.maxdgram`, and took 8.7 s; the limit is read,
  a local destination is reported at the loopback MTU, and another path that
  reaches it is retried with `method="udp"`. `discover_mtu("127.0.0.1")` is the
  loopback MTU (65535 on Windows).

- **The `socket` patch survives a second import of the package, a bad call and
  a stream socket.** A second copy of the package in one process captured the
  first copy's installed `recvmsg` as the native one, so on Windows
  `UDPEndpoint.recv().destination` came out as `1.0.0.0` with index 0 and
  `is_socket_patched()` said `False` while the method was installed; it now
  recognises and takes over what the first installed.
  `patch_socket_module(iov_max=0)` raised after installing the patch; it
  validates first. `recvmsg` on a Windows stream socket failed with
  `WinError 10022`; it uses `WSARecv`.

- **IPv4 on FreeBSD reports the arrival and pins the source.** `UDPEndpoint`
  there set `IP_PKTINFO`, which FreeBSD lacks, so `has_pktinfo` was false and
  `destination` was `None`, while `has_src_pinning` was true and
  `send(src=)` raised `OSError` 42. It now uses `IP_RECVDSTADDR` and
  `IP_RECVIF` to receive and an `IP_SENDSRCADDR` message to pin; the pin needs
  a wildcard-bound, unconnected socket, so `has_src_pinning` is false for an
  endpoint bound to an address. Measured on FreeBSD 16.0; IPv6 is unchanged.

- **Pinning a source on Windows.** A wildcard-bound IPv6 endpoint pinned by an
  interface with no IPv6 address, or by `::`, sent from `::`; both raise
  `ValueError` now, as the IPv4 twin did. A dual-stack endpoint pins an IPv4
  source (it failed with `WinError 10022`). A pinned `send` to a host name
  resolves it (it failed with `illegal IP address string passed to inet_pton`).

- **Closing a `UDPEndpoint` ends a pending `arecv`, and `arecv` leaves the
  socket's timeout alone.** `close()` and `aclose()` from another task now wake
  a task in `arecv` with `RuntimeError` and finish a `datagrams()` loop
  (both hung on the Windows Proactor loop and on Linux). The loop's reader is
  removed by the descriptor it was registered under, so closing the socket and
  then cancelling the task no longer leaves it registered: a Windows selector
  loop died with `WinError 10038` out of `run_until_complete`. One `arecv` used
  to leave a socket with `settimeout(5.0)` at `0.0`, so the next `recv()` raised
  `BlockingIOError` at once.

- **`ping` bounds its own name lookup by `timeout`** (2.5 s for `timeout=0.5`
  with a 2 s lookup before), and takes the family of `src` from the
  destination: `ping("::1", src=<loopback Interface>)` pinned the interface's
  IPv4 address on an IPv6 probe and was falsy on Windows, macOS and FreeBSD.
  The header and docstring now say that a TCP refusal takes about two seconds
  to arrive on Windows, so `ping(method="tcp")` needs a `timeout` of 3 there.

- **A DNS reply is bounded.** A short MX or SRV record is a `DNSDecodeError`
  (it escaped as `struct.error`); a name follows at most 32 compression
  pointers (one 65,000-byte reply cost 9.6 s of CPU); the UDP buffer is the
  1,232 bytes the query advertises; a datagram with another id or question is
  discarded instead of ending the query; the TCP read carries the whole
  deadline (a byte every 0.3 s held `timeout=0.5` for 12 s); a nameserver port
  outside 1-65535 is a `ValueError`; and bytes outside letters, digits, hyphen
  and underscore in a decoded name are written `\DDD`. `resolve_nslookup`
  refuses an `ns` or search domain that `nslookup` would read as an option.

- **The programs the library runs are looked up in the absolute `PATH`
  entries only.** On Windows `shutil.which` searched the working directory
  first, so `ping`, `nslookup`, `tracert` and `route` ran a same-named file
  next to the caller; a relative or empty `PATH` entry is now skipped on every
  platform. The runner refuses a call without a timeout:
  `resolve_nslookup(timeout=None)` allows 30 seconds instead of waiting
  forever. `count_hops` gives `None` when `traceroute` or `tracert` exits
  non-zero, and the header names the supported programs.

- **`recvmsg` and `sendmsg` honour a socket timeout on Windows.** A socket
  with a timeout is non-blocking underneath, and the Winsock calls returned
  at once: `UDPEndpoint.recv()` on a socket with `settimeout(0.3)` raised
  `BlockingIOError` after 0.000 s instead of waiting. Both now wait for
  readiness and raise `socket.timeout` when the time runs out, as the
  stdlib methods do on POSIX. A blocking socket and a non-blocking one
  behave as before.

- **`FQDN` compares by its case-folded key everywhere.** `is_subdomain_of`
  and `relative_to` were case-sensitive where `==` and `hash` were not
  (`FQDN("www.Example.com").is_subdomain_of("example.com")` was `False`), and
  `example.com` against `example.com.` answered `a > b` and `b > a` together.
  The four ordering operators now derive from one key, reversed folded labels
  then absoluteness.

- **`FQDN` validates after IDNA mapping, with one label rule shared by the
  text and the wire entries.** Fullwidth digits and the ideographic full stops
  mapped to `127.0.0.1` and constructed `FQDN('127.0.0.1')`; U+3002 became a
  dot inside one label. A label with a space, a control character or one of
  `: / ? # [ ] @` (`FQDN("http://example.com")`) constructed, then failed
  `FQDN.decode(v.encode())`. All now raise `NetimpsValueError`. `bytes` and an
  iterable item that is not a `str` or an `FQDN` (`FQDN(b"abc")` was
  `FQDN('97.98.99')`, `FQDN(["www", None])` was `www.None`) raise `TypeError`.
  `/`, `child` and `with_hostname` refuse a result over 253 octets, where
  `encode()` used to emit 259; `encode_name` refuses over 255 on the wire.

- **`split_host`, `split_zone` and `join_host` share one host rule and one
  port rule.** `join_host` accepted a network (`'10.0.0.0/24:80'`), `bytes`
  (`"b'h':80"`), a `float` port (`'h:80'`) and `True` (`'h:1'`), and
  `split_host` read `"h:8_0"`, `"h:+80"`, `"h: 80"` and Arabic-Indic digits as
  port 80; port text is now ASCII digits and every port goes through the one
  range gate. `split_host("[10.0.0.5]:80")` and `"[not an address]:80"` raise,
  as `join_host` already refused them. A value that is not a host type at all
  (`None`, an `int`, `bytes`) raises `TypeError` from all three, where
  `split_host`/`split_zone`/`join_host` raised `NetimpsValueError`; so does a
  non-`int` port. Text that does not parse stays `NetimpsValueError`.

- **`resolve(ns="host:port")` answers the same with and without dnspython.**
  The `host`, `host:port`, `[v6]` and `[v6]:port` spellings `resolve_wire`
  documents are read by one parser for every backend: `resolve_dnspython`
  hands dnspython each server's own port (it raised `ValueError` for
  `host:port`), and a malformed `ns` is a `NetimpsValueError` before any
  backend runs. `resolve_nslookup` takes `host`, `[v6]` or either with `:53`
  and raises `NetimpsValueError` naming `port=` for another port, which
  `nslookup` cannot use; the chain leaves it out for such an entry.

- **The classifiers answer the same on every Python and take one input rule.**
  `is_link_scoped` and `is_wildcard` answered `True` on 3.13 and later and
  `False` before for a v4-mapped address (`::ffff:127.0.0.1`,
  `::ffff:0.0.0.0`); they unmap first. `is_link_scoped`, `is_wildcard`,
  `is_multicast`, `is_local_address`, `is_broadcast`, `is_unicast` and `unmap`
  take `IPAddressLike` (`is_link_scoped("127.0.0.1")` raised `AttributeError`,
  `unmap(2130706433)` raised) and raise `NetimpsValueError` for text that is
  no address, where `is_multicast`, `is_broadcast`, `is_unicast` and
  `is_wildcard` answered `False`. A network or a value of another type is a
  `TypeError` (`is_multicast(None)` was `False`). `join_group` and `leave_group`
  still say "not a multicast group". `is_local_host` still never raises.

- **`try_parse` and `is_valid` raise `TypeError` for an option the builder
  does not take.** `try_parse("10.0.0.5", IPAddress, strict=True)` answered
  `None` while `parse` raised.

- **`Host(...)` reduces an interface to its address, as every `dst` parameter
  does.** `Host(IPv4Interface("127.0.0.1/8"))` kept the text `127.0.0.1/8`, so
  `.ip()` was `None` and the resolver was asked for it; a network is a
  `TypeError`.

- **Copy and pickle of a `MACAddress`, `Host` or `FQDN` subclass return the
  subclass** (they returned the base class), and the `parse`, `try_parse`,
  `FQDN.decode` and `FQDN.decode_at` classmethods are typed to return the class
  they were called on. The comparison methods of `MACAddress`, `FQDN.ping` and
  `FQDN.__getitem__` are annotated (`bool`, `PingResult`, `str` or a tuple of
  labels, where a checker saw `Any`), and the named networks are typed with their
  concrete classes, not `IPv4Network | IPv6Network`.

## [0.3.4] - 2026-10-03

### Fixed

- **`Interface.primary_ip()` preferred a link-local address over a routable
  one.** It returned the first entry that was not loopback, and an interface
  commonly lists its link-local address *first* -- `fe80::` is configured before
  SLAAC or DHCPv6 completes on Linux and macOS NICs -- so a NIC with both
  answered with an address that is useless as a bind target and unreachable
  off-link. The IPv4 twin was real too and is fixed by the same change: an
  interface holding an APIPA `169.254/16` address *and* a DHCP lease answered
  with the APIPA one.

  Now ranked **routable, then loopback, then link-local**, keeping OS order
  within a rank. Loopback outranks link-local deliberately: the only interface
  carrying both is the loopback adapter, where `::1` is what every caller means,
  and a real NIC has no loopback entry so the rank takes nothing from it. A NIC
  holding only a link-local address still yields it, and `loopback_ok=False`
  skips the loopback rank rather than returning `None`.

  Measured on a macOS loopback adapter (`127.0.0.1/8`, `::1/128`, `fe80::1/64`):
  `primary_ip(ipv6=True)` returned `fe80::1`, and `bind(interface=...,
  family=AF_INET6)` then failed with "Can't assign requested address".

- **`bind(interface=...)` dropped the scope of a link-local address**, and a
  link-local bind then failed on **every POSIX platform** -- not only macOS, as
  first reported. The same `fe80::` address can exist on several adapters, so
  the kernel cannot tell which is meant. Measured on Linux against a real NIC:

  | spelling | result |
  | --- | --- |
  | `bind(("fe80::1", 0))` | `EINVAL` |
  | `bind(("fe80::1%2", 0))` | `EINVAL` |
  | `bind(("fe80::1%eth0", 0))` | `EINVAL` |
  | `bind(("fe80::1", 0, 0, 2))` | **ok** |

  So **the zone has to become the sockaddr's numeric scope id; it cannot stay in
  the address string.** `bind()` now converts a `%zone` suffix -- name or index
  -- into the 4-tuple form, which also means a caller writing
  `bind("fe80::1%eth0", ...)` by hand gets a working bind for the first time.

  Windows accepts all four spellings, which is why a Windows-only measurement
  says nothing about this and why the first attempt at the fix -- putting
  `%index` in the string, copying what `UdpEndpoint.reply_socket` does -- passed
  locally and broke all six Linux CI jobs and both macOS jobs. `reply_socket`'s
  own link-local path went through the same string form and is fixed by the same
  change, since both now bind through one helper.


## [0.3.3] - 2026-10-03

### Added

- **`join_host(host, port=None)`** -- the inverse of `normalize_host`, and the
  direction everyone writes by hand and gets wrong on IPv6: `join_host("::1",
  8080)` is `'[::1]:8080'`, not `'::1:8080'`. Accepts a string, an address, an
  `IPv4Interface`/`IPv6Interface` or an `Fqdn`. **Only an IPv6 *literal* is
  bracketed** -- a hostname never is, because brackets in a URI authority assert
  that the inside is an address. A port-less v6 comes back bare, which is what
  makes `normalize_host(join_host(h, p)) == (h, p)` hold in every case. Three
  consuming projects were writing this themselves.
- **`unmap(value)`** -- collapse an IPv4-mapped IPv6 address (`::ffff:10.0.0.5`)
  to plain IPv4; anything else passes through. Built on
  `IPv6Address.ipv4_mapped`, **not** a `"::ffff:"` prefix test. Measured: all of
  `::FFFF:10.0.0.5`, `::ffff:0:1` and `0:0:0:0:0:ffff:0a00:0005` *are* mapped
  addresses that a `startswith("::ffff:") and "." in text` check leaves
  untouched. One address has many spellings; only the parsed form sees through
  them.
- **`is_wildcard(value)`** -- whether a value means "every local address":
  `""`, `None`, `"0.0.0.0"`, `"::"`, and any other unspecified spelling. Strips
  a `%zone`. Never raises, so it stays usable in a branch without a guard.
- **`disable_connreset(sock)`** and **`bind(..., connreset=False)`** -- stop
  Windows reporting an ICMP port-unreachable provoked by an earlier send as
  `ConnectionResetError` on a *later, unrelated* receive, which kills a server's
  receive loop over a packet some other host did not want.

  **There is no stdlib route to this**, which is why it belongs here. Measured on
  3.14: CPython exports no `socket.SIO_UDP_CONNRESET` on any version, and even
  given the documented value (`0x9800000C`) `socket.ioctl` whitelists commands
  and answers `ValueError: invalid ioctl command`. It goes through `WSAIoctl` by
  `ctypes` instead. The obvious `getattr(socket, "SIO_UDP_CONNRESET", None)`
  version is a silent no-op on every platform. Off by default, since the report
  is sometimes wanted -- a client talking to one peer learns the peer is gone.
- **`set_buffer_size(sock, receive=None, send=None)`** -- grow
  `SO_RCVBUF`/`SO_SNDBUF` and return what was **granted**, read back with
  `getsockopt` rather than echoed from the request. The kernel is not obliged to
  agree and does not say so: `setsockopt` succeeds and then grants less, capped
  by `net.core.rmem_max` on Linux -- which also *doubles* the request, so a
  read-back above it is normal there. The silent partial grant is the failure
  mode. Only grows, so it cannot undo earlier tuning.
- **`SocketOption(level, name, value)`** -- a named triple for `bind`'s
  `options=`. A `NamedTuple`, so bare tuples keep working; purely so a list of
  them reads better than `Iterable[Tuple[int, int, Any]]`.
- **`MACAddress.hex(sep=None, bytes_per_sep=1)`** -- exactly `bytes.hex`, as a
  passthrough to `.packed.hex`. Present because this is a value object rather
  than a `bytes` subclass, so the method is not inherited -- and a downstream
  project was subclassing the type partly to add it back.

- **`interface_enumerations() -> int`** -- how many times this process has
  really enumerated its adapters. Counts the syscall and never a cached hit,
  which is the number that matters once `cache=` makes a lookup and an
  enumeration different events: the enumeration is the one a packet flood
  multiplies. Worth exporting as a metric, and it is the assertion a test
  wants -- read it, do the work, expect `+1`. Both `raw` flags count into one
  total, and the cache is keyed by `raw`, so a process using both warms up
  twice. `clear_interface_cache()` does not advance it.

  Without it, a test checking the property `cache=` exists for had to
  monkeypatch a private name -- including this package's own tests, which now
  use the counter instead.

- **`is_broadcast(address, interface=None, *, cache=False)`** -- the one
  per-packet entry point the enumeration cache had left out. Without an
  `interface` it consults every adapter's prefixes, since `10.0.0.255` is only a
  broadcast if something carries `10.0.0.0/24`: measured **1.25 ms against
  0.004 ms** when the interface is passed, and a server asking the question of
  every request pays that per packet. `UdpEndpoint._is_repliable` uses the
  shared cache now, so `reply_socket()` no longer enumerates per datagram when
  the arrival index did not resolve. Passing `interface` remains the fastest
  path and consults neither the cache nor the syscall.

- **`supports_pktinfo(family=AF_INET)`** -- whether a UDP socket of that family
  can report each datagram's arrival interface on this host. The question a
  server asks *before* deciding how to bind: with packet info one wildcard
  socket serves every address and still knows which one a datagram reached,
  while without it the wildcard must be expanded into a socket per address --
  and on Linux that per-address socket receives no broadcasts at all.

  Answered by asking a socket, not by testing a constant's name:
  `getattr(socket, "IP_PKTINFO", None)` is `None` on CPython 3.9-3.11 on *every*
  platform, while the kernel supported it throughout, so a name test says "no"
  on a platform that works. Cached per family.

- **An opt-in cache for the adapter enumeration**: `get_interfaces(cache=...)`,
  and the same argument on `interface_for`, `interfaces_for` and
  `is_local_address`, plus `clear_interface_cache()` and
  `INTERFACE_CACHE_TTL`. `cache=False` is the default and changes nothing;
  `cache=True` uses the 1-second default TTL; a number is that TTL. `cache=0` is
  a TTL of zero, so it enumerates and reseeds -- the whole of "force a refresh",
  which is why there is no second argument for it.

  Measured on a 7-adapter host: `interface_for` goes **0.98 ms to 0.010 ms**
  (97x), and `is_local_address` likewise. The uncached call reaches 35-42 ms
  where there are many adapters, which is slow enough that a packet flood can
  deny service on its own -- an availability problem, not only a slow one.

  The default TTL is **1 second** because this cache is for collapsing a burst
  of back-to-back calls, not for holding a snapshot: it bounds the cost at one
  syscall per second whatever the arrival rate, ~0.1% overhead at 1000 packets
  per second. `UdpEndpoint`'s own arrival-interface cache now uses the same
  constant, down from a separate 30 s, so there is one number rather than two
  that can disagree.

  **Prefer an event to a TTL where you have one** -- `cache=math.inf` plus
  `clear_interface_cache()` at the moment the answer changes is strictly better
  than any TTL; a server has such a moment when it binds. A **cached call
  returns fresh `Interface` objects**: `Interface` is
  not frozen and `.ips`/`.raw` are mutable, so handing back the stored ones
  would let one caller corrupt every later caller's view. The copy is 0.004 ms
  against 0.969 ms to enumerate.

  The uncached path still calls `get_interfaces()` with **no keyword argument**,
  so an existing test double that takes none keeps working.

- **`Backoff`** -- a retransmission **timer**: grows on loss, **resets on
  progress**. `backoff_delays` is a one-shot schedule for "retry this call a few
  times"; a long-lived session needs a current delay that advances on silence
  and returns to the base when the peer moves the transfer forward. Every
  protocol client in this family had written its own, so the shape is taken from
  the one already working rather than invented.

  `.delay` is **stable between `advance()`/`reset()`**, so arming a deadline,
  logging it and comparing against it all see one value -- a property that
  re-jittered per read would be a trap for exactly this code. Jitter is **off by
  default**, the opposite of `backoff_delays`: a point-to-point session
  retransmitting to one peer has no thundering herd to avoid, and TFTP and TCP
  both specify plain doubling. Two guard rails a hand-rolled version tends to
  miss: `multiplier` is floored at `1.0` so the timer can never *shrink* on
  repeated loss, and `max_delay` is floored at `delay` so a ceiling below the
  base cannot silently truncate the first wait.

- **`backoff_delays(jitter_seconds=)` and `(symmetric=)`**, also on `retry` --
  the two **symmetric** jitter shapes that protocol specifications require and
  the default cannot express, since it only ever shortens a delay:

  - `jitter_seconds=` is absolute and symmetric, uniform in
    `[-jitter_seconds, +jitter_seconds]` -- **RFC 2131 §4.1** (DHCPv4),
    "randomized by the value of a uniform random number chosen from the range
    -1 to +1". The amplitude is capped at the current delay so the value cannot
    go negative before clamping; uncapped, a sub-second delay would pile much of
    its distribution on a single clamped value, which is neither uniform nor
    symmetric. At RFC 2131's own 4 s floor the cap never engages.
  - `symmetric=True` spreads the fractional `jitter` both ways -- **RFC 8415
    §15** (DHCPv6), `RT = 2*RTprev + RAND*RTprev`.

  **In these modes `max_delay` caps the base, not the final value**, so a delay
  may exceed it by up to the amplitude. Both RFCs require it: RFC 8415 applies
  its jitter *after* the cap (`if RT > MRT: RT = MRT + RAND*MRT`) and RFC 2131
  randomises around its 64 s maximum. Clamping was the obvious reading -- and
  the one the request suggested -- and it is wrong invisibly: measured, the
  spread *at the cap* became entirely negative with a mean of -0.024 instead of
  ~0, because every positive excursion was trimmed back. A backed-off client
  spends nearly all its time at the cap, so clamping would reintroduce exactly
  the synchronisation the mode is chosen to prevent. No mode returns a negative
  delay, and **the default schedule is unchanged** -- asserted against a copy of
  the previous implementation rather than against recorded numbers.

- **`UdpEndpoint.reply_socket(datagram, port=...)` accepts an iterable of
  ports**, tried in order, for a server that pins transfer ports to a range a
  firewall can allow (`tftp-hpa -R`, `dnsmasq --tftp-port-range`). Materialised
  once, so a generator is safe but must be finite; empty raises `ValueError`.

- **`UdpEndpoint.arecv()` and `.datagrams()`** -- `recv()` awaited, and an
  `async for` over arrivals. Same arguments, same `Datagram`, and **pktinfo
  survives on every loop type**, including the Windows default
  `ProactorEventLoop`.

  That default is the whole difficulty: it raises `NotImplementedError` from
  `add_reader`, and its own `IocpProactor.recvfrom` discards ancillary data. Nor
  is there an IOCP route -- measured on 3.14, CPython's `_overlapped` exposes no
  `WSARecvMsg`, so posting one through the loop's completion port would mean
  reimplementing the overlapped plumbing *and* calling the private
  `IocpProactor._register`. (`asyncio.DatagramProtocol.datagram_received(data,
  addr)` has no slot for cmsgs either, so a transport could not deliver them
  anyway.)

  So on such a loop a thread does the waiting -- and it **reports readability
  only, never reads**. The `recv` stays on the loop, which keeps `bufsize` a
  per-call argument and `Datagram.truncated` meaning what it means; a thread that
  read for you would have to fix `bufsize` when it started. It is created on the
  first `await`, joined on `close()`, and a test asserts no thread survives the
  endpoint. `recv()` is untouched.

  `asyncio` is imported **lazily**, never at package import time: pulling it into
  `__init__` would force the very import ordering that produced this release's
  `os.sysconf` crash, and a consumer using only the value types should not pay for
  an event-loop import. A test spawns a fresh interpreter to assert
  `'asyncio' not in sys.modules` after `import netimps`.

- **`UdpEndpoint.reply_socket(datagram)`** -- a socket bound so replies leave
  from the address the client addressed, which is the point of pktinfo in one
  call. A wildcard-bound server answering from a fresh socket sends from whatever
  the routing table prefers, and DHCP and TFTP clients both check and drop a
  reply from an address they never talked to. Demonstrated by the contrast: a
  plain wildcard reply to a client that addressed `127.0.0.2` comes from
  `127.0.0.1`.

  Three platform traps it absorbs, each measured rather than reasoned about:
  a v4 arrival on a dual-stack listener is `::ffff:a.b.c.d`, and binding that
  needs `IPV6_V6ONLY` off which Windows does not default to, so it is unmapped
  and answered from an `AF_INET` socket; a broadcast, multicast or unspecified
  destination must not be answered *from*, and is classified and skipped rather
  than discovered by a failed bind, because Linux binds `255.255.255.255` and
  `239.1.2.3` happily where Windows refuses them; and an IPv6 link-local
  destination needs the arrival `ifindex` as its scope, carried as a `%zone`
  suffix. Falls back to the endpoint's own address and then the wildcard, because
  a reply from the wrong address still beats no reply. `connreset=False` by
  default, inverted from `bind()`: a server loop must not die because an earlier
  answer drew an ICMP port-unreachable from a client that had gone.
- **`is_broadcast(address, interface=None)`** -- whether an address is an IPv4
  broadcast, limited *or* subnet. The question a wildcard-bound server asks
  before answering: RFC 1123 says a TFTP server ignores a broadcast request, and
  DHCP must tell a broadcast DISCOVER from a unicast RENEW. `255.255.255.255`
  needs no context; `10.0.0.255` is only a broadcast if some interface carries
  `10.0.0.0/24`, so this consults interface prefixes -- pass `interface` to check
  one adapter and skip the enumeration. A v4-mapped address is unmapped first.
  IPv6 has no broadcast, so a genuine v6 address is always `False`; `is_multicast`
  stays the separate companion, since one name meaning both would hide which
  matched.
- **An unbounded `Interface.mtu` is now a number, not `None`.** The Windows
  loopback adapter reports `0xFFFFFFFF`, which the code called an "unknown"
  sentinel and mapped to `None`. It is ULONG max and means *unbounded* -- there is
  no link to constrain loopback -- so that conflated "no limit" with "could not
  read", and cost callers in the one direction that matters: handling `None` by
  falling back to 1500 capped loopback at 1472 when it delivers **65507**. Linux
  reports its own `lo` as 65536 rather than as nothing, so the two platforms
  disagreed about the same physical reality.

  Such an interface now reports **65535**, the largest datagram the 16-bit IP
  total-length field can describe -- a clamp to reality rather than an invented
  figure. `max_udp_payload()` then yields exactly the 65507 measured to arrive,
  and a test moves a datagram that size to prove it. `None` now means only that
  the platform genuinely could not read an MTU.
- **`max_udp_payload(mtu, ipv6=False)`** -- the largest UDP payload that fits an
  MTU without fragmenting (`1472` for 1500, `1452` for v6). Takes an `int` rather
  than an `Interface` on purpose: `Interface.mtu` is `Optional[int]` and **Windows
  reports no MTU for the loopback adapter**, so whether to fall back to 1500 or
  refuse is the caller's decision. The v4 figure uses the minimum 20-byte header,
  so a packet carrying IP options can still fragment.

- **`AddressInUseError(OSError)`** -- one stable type for "the address is
  taken", raised by `bind()` instead of whatever the platform happened to call
  it. Measured on Windows 11 ARM64 against an exclusive holder, the *same
  situation* had three shapes: `PermissionError`/errno 13 on 3.14,
  `OSError`/errno 10013 on 3.9, and `OSError`/errno 10048 without the takeover
  flag. The 3.14 row is the harmful one -- `PermissionError` says "privilege
  problem", and Windows has no privileged ports, so a consumer branching on the
  type sent its user after an elevation problem that cannot exist.

  `errno` is normalised to `EADDRINUSE`, `bind_error_hint()`'s text is the
  message, and the original is chained as `__cause__` so `winerror` stays
  reachable. It subclasses `OSError` and deliberately **not**
  `PermissionError`: every `except OSError` keeps working while
  `except PermissionError` stops catching a case that was never about
  permission. A genuine POSIX `EACCES` on a port below 1024 is left exactly as
  it was.

- **`Fqdn`** -- a domain name as a value type, with label algebra: `.labels`,
  `.hostname`, `.domain`, `.domains`, `.tld`, `.is_fully_qualified()`,
  `.with_hostname()`, `.is_subdomain_of()`, `.relative_to()`, `.reverse()`,
  `.common_ancestor()`, and `/` to compose. Immutable, hashable, ordered on
  *reversed* labels so sorting groups by TLD. Case-insensitive equality per
  RFC 4343, with `__hash__` agreeing. `.resolve()`, `.ping()` and `.ip()`
  delegate to the existing module functions. `is_valid`/`try_parse` classmethods
  match `MACAddress`'s shape, and `FqdnLike` is the accepted-input union.

  **`name in domain` works like the stdlib's `address in network`** --
  `Fqdn("www.example.com") in Fqdn("example.com")`. Inclusive, where
  `.is_subdomain_of()` is strict: a zone contains its own apex just as a `/24`
  contains its network address. Accepts a `str`, ignores qualification, and
  answers `False` rather than raising for anything unparseable. A **label** test
  is `"com" in f.labels`.

  **Text interop**: `str(f)` is the name, and `f + str` / `str + f` give a plain
  `str`, for building a URL or a log line. `Fqdn + Fqdn` raises and points at
  `/`.

  Also `.unicode` (the display form, decoding punycode -- labels are stored
  ASCII because that is what goes on the wire), `.wire`/`.wire_length` (the DNS
  wire encoding, delegated to the package's own encoder; `.wire_length` is what
  the 255-octet protocol limit applies to, against the 253 printable limit),
  `.is_hostname()` (RFC 1123 LDH, **narrower** than what the type accepts, since
  `_dmarc` and `_sip._tcp` are real names), and `.is_wildcard` (a predicate only
  -- no `matches()`, because DNS and TLS disagree about whether `*.example.com`
  covers `a.b.example.com`).

  **The algebra is deliberately inverted from `pathlib`**, because DNS puts the
  most significant label last: `.name` is the *leftmost* label, `.parent` strips
  the *leftmost*, and `/` **prepends** -- `Fqdn("example.com") / "www"` is
  `www.example.com`. DNS vocabulary is primary and the pathlib spelling is an
  alias on the same value (`.domain`/`.parent`, `.hostname`/`.name`,
  `.labels`/`.parts`). There is no `.suffix` alias for `.tld`: a filesystem
  suffix is part of a name while a TLD is a whole label.

  An **address literal is refused** -- `Fqdn("10.0.0.1")` raises -- because this
  is a name algebra and an IP has no labels, parent or TLD. The trailing dot is
  absoluteness and is part of identity, so `Fqdn("example.com") !=
  Fqdn("example.com.")`, as `Path("a") != Path("/a")`. `.domain` is **not** the
  registrable domain (`example.com`'s is `com`): that needs the Public Suffix
  List, which would be a hard dependency, so the gap is documented instead.
- **`Host.fqdn`** -- the bridge: an `Fqdn` when the host is a name, `None` when
  it is an address. `Host` stays the union type and is otherwise unchanged.
- **`recvmsg()` / `sendmsg()` now work on Windows**, and are public on every
  platform, along with `CMSG_LEN()`, `CMSG_SPACE()` and `supports_recvmsg()`.
  CPython ships neither method on Windows, so this binds `WSARecvMsg` and
  `WSASendMsg` through `ctypes` and delegates to CPython's own methods
  elsewhere. Signatures and return shapes are CPython's exactly, for both
  address families -- an `AF_INET6` sender comes back as the usual
  `(host, port, flowinfo, scope_id)` 4-tuple, and a v6 destination accepts a
  2-, 3- or 4-tuple with an optional `%zone` suffix.
- **`UdpEndpoint` reports the arrival interface on Windows** -- v4, v6 **and**
  dual-stack `::`, on 3.9 through 3.14. `supports_pktinfo` and
  `supports_src_pinning` are no longer always `False` there. It calls the
  Winsock backend directly rather than the patched stdlib method, so disabling
  the patch below does not cost it pktinfo. One gap is deliberate: pinning by
  interface index *alone* raises `ValueError` on Windows, because that platform
  sends a zero source address literally -- a pin of `0.0.0.0` arrives from
  `0.0.0.0` -- where Linux reads zero as "kernel chooses". Pass an
  address-bearing `src`.
- **A v4 arrival on an `AF_INET6` endpoint now reports the documented v4-mapped
  address on every platform.** Linux and macOS carry it in the v6 cmsg; Windows
  reports a *plain* v4 address at `IPPROTO_IP` and is the only platform that
  reports it at all, since its v6 option delivers no cmsg for a v4 arrival. That
  needed `IP_PKTINFO` set on the `AF_INET6` socket as well, which macOS refuses
  outright and Linux accepts and does not need -- so it is set with the error
  ignored.

### Changed

- **The patched `sock.recvmsg` now normalises the v4 `IP_PKTINFO` payload to the
  POSIX layout**; `netimps.recvmsg()` still reports the platform's own bytes, and
  `UdpEndpoint` is unaffected. On Windows the patched method rewrites
  `{addr, ifindex}` (8 bytes) into `{ifindex, spec_dst, addr}` (12 bytes) with
  `spec_dst` zero-filled -- byte-for-byte what macOS produces. The patched
  `sendmsg` accepts either layout, chosen by length.

  Rationale: installing the method name without the layout is a
  half-impersonation, and the missing half is what made POSIX-shaped code unpack
  `=I4s4s` from an 8-byte buffer and raise `struct.error` -- which is not an
  `OSError`, so it escaped receive handlers. `spec_dst` is zero rather than a copy
  of `addr` because the two genuinely differ for a broadcast (measured on Linux:
  the local interface address against `255.255.255.255`), and code reads
  `spec_dst` to get the local address -- so copying `addr` would corrupt exactly
  the field it wanted. Zero is visibly wrong; `255.255.255.255` is not.

  **Known consequence, not fixed by this.** The patch is additive in *names* and
  therefore not in *behaviour*: code testing
  `hasattr(socket.socket, "recvmsg")` to detect POSIX now gets the POSIX answer
  on Windows. **pydhcp 0.6.1 and earlier** read `ipi_spec_dst` for their
  `SERVER_IDENTIFIER`, and **measured, they receive but allocate and reply to
  nothing** on Windows. A zero-filled `spec_dst` does not degrade a consumer that
  resolves its interface from that field, it silences it -- an earlier draft of
  this entry said "will see `0.0.0.0` ... and no longer a crash", which was
  inferred from the field's value rather than measured against the consumer. The
  owner's decision is to accept this: the two projects are released together and
  have no external consumers yet. `UdpEndpoint` is the supported way to obtain
  that address correctly on every platform; `NETIMPS_NO_SOCKET_PATCH=1` opts out
  of the patch entirely.

- **`bind()` and `normalize_host()` now accept the package's usual loose union**,
  not just a `str`: an address object, an `IPv4Interface`/`IPv6Interface` (its
  `.ip` is used), a `Host` or an `Fqdn`. `bind()` previously leaked a raw
  socket-layer `TypeError` -- "str, bytes or bytearray expected, not
  IPv4Address" -- not even a netimps error, for a value `ping`, `resolve` and
  `UdpEndpoint.send` all take; they coerce through a shared helper that these two
  simply never used. `join_host`, `normalize_host`'s inverse, already accepted
  them. A *network* still raises `TypeError`, since it names no single host.

  `normalize_host` uses an **allowlist**, not a `str()` fallback. A fallback
  accepted `None` and turned it into the hostname `"None"` -- a plausible answer
  that is wrong and that a caller cannot detect -- and did the same for an int or
  a list.

### Fixed

- **`import netimps` then `import asyncio` crashed on Windows.** The import-time
  socket patch makes `socket.socket.sendmsg` exist, and CPython's
  `asyncio/selector_events` reads `hasattr(socket.socket, 'sendmsg')` at import
  time as a POSIX proxy, then calls `os.sysconf('SC_IOV_MAX')` guarding only
  `except OSError` -- so the `AttributeError` from a missing `os.sysconf` escaped
  and the import died. `sendmsg` and `os.sysconf` are both POSIX and had always
  travelled together; the patch was the first thing to separate them.

  The patch now installs an `os.sysconf` shim alongside, answering **per name**:
  `SC_IOV_MAX` returns 1024 (tunable with `patch_socket_module(iov_max=...)`) and
  every other name raises `ValueError`. Per name because the three stdlib callers
  guard differently and no single behaviour satisfies them -- `asyncio` catches
  `OSError`, `concurrent.futures` catches `(AttributeError, ValueError)`,
  `multiprocessing` catches `Exception`; raising `OSError` for everything rescues
  asyncio and breaks `ProcessPoolExecutor`. Regression tests run in **fresh
  interpreters**, since in-process tests cannot see it: by the time a test body
  runs, asyncio is already imported.

- **`sendmsg()` failed on every connected stream socket on Windows.**
  `WSASendMsg` refuses `SOCK_STREAM` outright with `WSAEINVAL` -- measured on
  Windows 11 build 28000, where a connected `SOCK_DGRAM` is accepted, so the
  refusal is about the socket *type* and not about being connected. The
  buffers-only path now uses **`WSASend`**, Windows' own scatter-gather send,
  which works there and showed no small `IOV_MAX`-like cap (500 buffers in one
  call, verified). A destination or a control buffer still routes through
  `WSASendMsg`, the only call that carries either, so `UdpEndpoint.send(src=)`
  is unchanged. Ancillary data on a stream socket still fails, which is correct:
  Windows has no per-packet information to attach to one.

- **`UdpEndpoint` reported nothing when a datagram was too large for
  `bufsize`.** `Datagram` now carries **`truncated`**, from `MSG_TRUNC`, beside
  the existing `control_truncated`. The flag was always in `msg_flags` and was
  being dropped, so a caller had no way to tell a complete datagram from the
  leading fragment of a longer one -- and a protocol parser handed a message cut
  mid-field reports a malformed packet rather than a short read. Measured on
  Linux with `bufsize=576`: a 1102-octet datagram arrived cut to 576 with the
  flag set and discarded. Reported, not raised: deciding that a short datagram is
  fatal belongs to the protocol.

  It is reported on the no-pktinfo path too, which now goes through `recvmsg`
  with a zero-length control buffer rather than `recvfrom`, because `recvfrom`
  cannot report it. Losing the arrival interface is a documented degrade; losing
  this is silent data loss, and the two no longer have to be given up together.

- **A cancelled `arecv()` left its reader registered on the loop**, and the
  notifier stayed bound to the first loop for good. Both reported by a consumer
  reading the code, and both reproduced here before fixing.

  Cancelling the awaiting task is the ordinary server shutdown -- cancel the
  receive task, then close the endpoint -- and the registration was removed only
  when it *fired*, so the loop was left watching a socket that then closed and
  raised from the selector on its next poll. Measured:
  `loop.remove_reader(fileno)` after a cancelled `arecv` returned `True`,
  meaning one was still there. A cancelled `arecv` now unregisters itself, and
  the thread path drops its pending future.

  Separately, the notifier thread captured its loop for its whole lifetime, so
  serving one endpoint from a second loop -- `asyncio.run(serve())` twice, or a
  server stopped and restarted -- sent readiness to a closed loop. Measured on a
  `ProactorEventLoop`: the second exchange timed out while the daemon thread
  raised an unhandled "Event loop is closed" to stderr, where no caller could
  see it. A different running loop now retires the old thread and starts
  another, joining the old one rather than abandoning it; the only previous
  reset was `close()`, which also closes the socket. The post is additionally
  guarded, since a loop can close between the select and the call.

- **`bind(options=[(SOL_SOCKET, SO_REUSEADDR, 1)])` failed with a bare
  `WSAEINVAL` on Windows** -- a regression introduced in this same unreleased
  cycle, caught by a consumer's test suite. Windows refuses `SO_REUSEADDR` on a
  socket that already carries `SO_EXCLUSIVEADDRUSE`, and once `bind()` began
  setting the latter for *both* values of `reuse_address`, the stdlib-shaped
  spelling of "share this address" stopped working. The error names neither
  option, so the caller saw only "An invalid argument was supplied".

  An explicit nonzero `SO_REUSEADDR` in `options=` is now treated as
  `allow_address_takeover=True` -- it is the caller asking for takeover in so
  many words. A zero value stays an explicit opt-out. `bind_error_hint` learned
  `WSAEINVAL`, since a bare 10022 is undiagnosable. Verified against the
  reporting consumer's suite: the three tests that failed now pass, and fail
  again when the fix is reverted.

- **A v4 client of a dual-stack listener could not be replied to at all.**
  Measured on Windows 11 ARM64 with an `AF_INET` client on `127.0.0.1` and a
  `bind("::", family=AF_INET6, IPV6_V6ONLY=0)` listener, it failed **both** ways:

  - *With* pktinfo, `reply_socket` correctly returned an `AF_INET` socket, but
    `datagram.sender` was still the v6 4-tuple -- so the `reply.sendto(answer,
    packet.sender)` shown in this library's own docs raised `TypeError: AF_INET
    address must be a pair (host, port)`.
  - *Without* pktinfo there was no `local_address`, so both fallbacks used the
    **listener's** family; the resulting `AF_INET6` socket carries
    `IPV6_V6ONLY=1` on Windows (the platform default, which `bind()` does not
    clear), and `sendto` to a mapped address failed with `WinError 10049`. The
    exchange silently never started.

  Now **the sender's family decides the reply socket's**, with or without
  pktinfo, and the own-address fallback is skipped when it is in the wrong
  family. New **`Datagram.reply_address`** gives the peer in the family that was
  chosen -- a mapped sender as a plain `(host, port)`, everything else unchanged
  -- and is what the examples now pass to `sendto`.

- **`is_multicast` missed a v4-mapped group below Python 3.13.** The stdlib only
  began delegating a mapped address's `is_*` properties to the embedded v4
  address in 3.13, so `IPv6Address("::ffff:224.0.0.1").is_multicast` is `False`
  on 3.9 and `True` on 3.14 -- the function's answer depended on the
  interpreter. It unmaps first now, as `is_broadcast` already did.
  `UdpEndpoint._is_repliable` inherits this, so on 3.9-3.12 a reply socket could
  bind a mapped multicast destination.

- **`reply_socket` answered from the wrong address when the port was taken.**
  The candidate loop caught every `OSError` and advanced the *address*, so an
  explicit `port=` already held on the arrival address fell through to the
  endpoint's own address and then the wildcard **with the same port** -- and
  where that later bind succeeded, the reply left from an address the client
  never addressed, which is the single failure this method exists to prevent.

  Measured on Windows 11 ARM64 against the pre-fix code: holding
  `10.6.0.223:57014` and replying to a datagram that arrived there returned a
  socket bound to `127.0.0.1:57014`.

  A held port and an unusable address are different failures and now move in
  different directions -- an unbindable address (broadcast, multicast, a wrong
  scope) advances the **address**, a held port advances the **port** on the same
  address. When the ports run out on an otherwise bindable address this raises
  **`AddressInUseError`** and binds nothing, so a caller can also tell "port
  busy, try another" from "this address is unbindable", which the old generic
  `OSError` hid. Both `reply_socket` and `AddressInUseError` are new in this
  unreleased cycle, so no released behaviour changed.

- **`bind()`'s default let a second live UDP socket take the port on Linux.**
  `reuse_address=True` (the default) set `SO_REUSEADDR`, and on a *datagram*
  socket that is not the `TIME_WAIT` convenience it is for TCP -- it permits
  duplicate bindings of **live** sockets. Measured on WSL: a second `bind()` of
  the same live UDP `addr:port` with default arguments succeeded and the datagram
  went to the **second** socket, with the holder getting no error. `socket(7)` is
  explicit that the exception is an active *listening* socket, and a UDP socket
  never listens.

  `SO_REUSEADDR` is now set on POSIX for **stream sockets only**. Sharing a UDP
  port stays reachable through the names that say so -- `reuse_port=True`
  (`SO_REUSEPORT`, the option designed for it) or `allow_address_takeover=True`.
  `multicast_socket` sets what it needs itself and was verified not to rely on
  the old default.

  This also corrects two documentation passages that stated the opposite: both
  said "two live sockets still cannot hold one `addr:port`", which is true for
  TCP and false for UDP on Linux.
- **`bind(reuse_address=False)` left a Windows wildcard bind open to hijack.**
  It set *nothing* -- both `SO_REUSEADDR` and `SO_EXCLUSIVEADDRUSE` read 0 --
  and Windows then lets a *more specific* `SO_REUSEADDR` bind take over a
  non-exclusive wildcard. Reproduced: a thief binding `127.0.0.1` received the
  datagram while the holder on `0.0.0.0` got nothing and no error.

  So the flag that reads as "strictest" was the least strict setting available,
  which is the worst shape a safety option can have -- the careful caller got
  the unsafe behaviour. `SO_EXCLUSIVEADDRUSE` is now set on Windows whenever
  `allow_address_takeover` is false, for **both** values of `reuse_address`;
  that option's only effect there is denying the takeover, so it costs nothing.
  `reuse_address` now governs POSIX `SO_REUSEADDR` only, which is what the name
  means everywhere else. `allow_address_takeover=True` remains the one way to
  opt into the old behaviour. Windows-only change, strictly toward safety.
- **`UdpEndpoint.recv()` enumerated every interface on every datagram.**
  Measured on Windows loopback with 300-octet packets: **1.07 ms per packet**
  against 0.015 ms with `resolve_interface=False` -- a 70x cost on the *default*
  path, and one a consuming project measured at 35-42 ms per enumeration on a
  host with more adapters. Worse than a bad default: the class docstring's own
  example uses the default and reads `.interface`, so the documented usage was
  the slow one, and a server loop is a hot loop by definition since the sender
  controls the rate.

  Now resolved through a per-endpoint `index -> Interface` cache, refreshed on a
  **miss** as well as on a 30-second TTL -- a miss means the adapter set changed,
  which is both cheap to act on and exactly when it matters. Negative results are
  cached too, so a stale or vanished index does not re-enumerate forever.
  Measured after: **0.017 ms per packet**, and one enumeration for ten datagrams
  instead of ten.
- `UdpEndpoint.send()`'s docstring still claimed Windows could not honour `src`
  at all and that `supports_src_pinning` was `False` there. Both stopped being
  true earlier in this release.

- **IPv6 `UdpEndpoint` was silently degraded on Windows.** The receive option
  was looked up as `IPV6_RECVPKTINFO`, which Windows does not export at all;
  there `IPV6_PKTINFO` (19) is both the request and the carrier. The result was
  `supports_pktinfo == False` for every `AF_INET6` endpoint on that platform
  while a raw `recvmsg` on the same socket delivered the cmsg perfectly well.
  The round-trip test passed throughout, because it took its own
  "no pktinfo here" early-exit branch, and its guard against exactly this
  consulted the same function that was wrong.
- **v4 pktinfo was silently off on Python 3.9 for Windows**, which exports no
  `socket.IP_PKTINFO` even though Winsock supports it at the documented value
  19. Measured: 3.14 ran the v4 tests while 3.9 skipped nine of them and still
  reported a green suite. The documented literal is now used, with `OSError`
  from `setsockopt` as the real capability signal.
- **`patch_socket_module()` / `socket_patched()`**, and netimps installs the
  patch **on import by default**: `recvmsg`/`sendmsg` onto `socket.socket` and
  `CMSG_LEN`/`CMSG_SPACE` onto the `socket` module, so POSIX-shaped code runs
  unchanged on Windows. Set `NETIMPS_NO_SOCKET_PATCH=1` before the first import
  to decline, or call `patch_socket_module(False)` afterwards. It is strictly
  additive and never replaces a name the platform already provides, so on Linux
  and macOS it is a verified no-op. All four names are installed rather than
  just the method, because Windows lacks `CMSG_SPACE` too and the standard idiom
  is detect, then size a buffer, then receive.

  Cmsg payloads are **not** normalised to Linux's byte layouts. They genuinely
  differ -- a v4 `IP_PKTINFO` cmsg is type 8, 12 bytes,
  `{ifindex; spec_dst; addr}` on Linux against type 19, 8 bytes,
  `{addr; ifindex}` on Windows -- and faking one as the other would make
  correct-looking code read a plausible wrong address instead of failing.
  `UdpEndpoint` is the layer that handles the difference for you.
- **`resolve_wire()`** -- a DNS client on the standard library alone: one
  question over UDP to each nameserver in turn, asked again over TCP when the
  reply is truncated, CNAME chains followed, records returned as native types
  like the other backends. It joins `resolve()`'s chain after `dnspython`,
  for an explicit `ns=` or `source=` only -- so a named nameserver now works
  without `dnspython` installed.
- **`source=`** on `resolve()`, `resolve_dnspython()` and `resolve_wire()`: the
  local address the queries leave from (one per address family as a list).
  `system` and `nslookup` are skipped when it is set, as for `ns=`.
- **`resolve_doh()`** -- DNS over HTTPS (RFC 8484), with an injectable `fetch`
  so a caller's own HTTP stack (proxy, CA bundle) carries the request.

## [0.3.2] - 2026-09-28

### Changed

- **The `cli` extra's `duho` dependency is bounded to `>=0.6.0,<0.7`**
  (previously unbounded at `>=0.3.3`, so a bare `pip install netimps[cli]`
  would have floated onto 0.6.0 unverified). No code change was needed --
  every documented 0.6.0 change was checked against `src/netimps/cli.py`
  and the full suite is unaffected (663 passed, 6 skipped, before and
  after). duho 0.6.0 also adds an opt-in MCP launch feature, triggered by
  setting `NETIMPS_MCP=stdio`; netimps does not opt out and leaves it at
  duho's default.

## [0.3.1] - 2026-09-21

A same-day follow-up to 0.3.0, fixing three defects that release introduced or
exposed. No documented contract changes: the `resolve()` fix *restores* one.

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

[Unreleased]: https://github.com/jose-pr/netimps/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/jose-pr/netimps/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/jose-pr/netimps/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/jose-pr/netimps/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/jose-pr/netimps/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/jose-pr/netimps/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/jose-pr/netimps/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/jose-pr/netimps/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/jose-pr/netimps/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jose-pr/netimps/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/jose-pr/netimps/releases/tag/v0.0.2
[0.0.1]: https://github.com/jose-pr/netimps/releases/tag/v0.0.1
[0.0.0]: https://github.com/jose-pr/netimps/releases/tag/v0.0.0
