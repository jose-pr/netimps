# `netimps` listening — public API header

Header-file-style reference for the listen names of the `netimps` package: every
public export with its signature, arguments, contract and gotchas, so it can be
used without reading its source. It ships inside the package and is
self-contained; the top header is `netimps/AGENTS.md`. Development documentation
lives with the source at <https://github.com/jose-pr/netimps>.

This directory (`netimps/_listen/`) is private and not an import path: every name
below is imported from `netimps`.

## Where a service listens

One argument says where a service listens, and every library that listens reads
it the same way. **`parse_listen`** turns it into the sockets it names;
nothing is opened, resolved or looked up.

**`parse_listen(listen=None, default_ports=0, *, family=None) -> Tuple[ListenAddress, ...]`**

- `listen`: a `ListenLike`, below.
- `default_ports`: an `int`, or a sequence of them. A binding that names no port
  gets each one; `0` is a port the kernel chooses. An empty sequence leaves a
  binding without a port nothing to get, and that binding is refused.
- `family`: `None`, `socket.AF_INET` or `socket.AF_INET6`; see "The family".
  Any other value is `NetimpsValueError`.
- Returns one `ListenAddress` for each address and port, once, in the order they
  were first written.

**`ListenAddress`** — a `NamedTuple`:

| Field | Type | Meaning |
| --- | --- | --- |
| `address` | `IPv4Address \| IPv6Address` | the address to bind; the wildcard of the family for a binding that names an interface. A zone that was written is kept (`fe80::1%eth0`) |
| `port` | `int` | the port; `0` is a port the kernel chooses |
| `interfaces` | `Tuple[Interface \| MACAddress \| str, ...]` | what limits the socket: an `Interface`, a `MACAddress`, or adapter-name text. Empty for a socket that is not limited |

A `ListenAddress` is itself an accepted binding, so
`parse_listen(parse_listen(x)) == parse_listen(x)`: a result can be stored,
passed on and read back.

**`ListenLike`** — what `listen` accepts: `None`, one binding, or a sequence
(list or tuple) of bindings. A binding is:

- text: `"host"`, `"host:port"`, `"[v6]:port"`, the wildcard forms `"*"`,
  `"*:port"` and `":port"`, or several of them joined by commas. A blank part
  between commas is skipped;
- an `IPv4Address` or `IPv6Address`, an `Interface`, a `MACAddress`, a
  `ListenAddress`, or `None` (the wildcard);
- a pair of host and ports, as a tuple or a list (a configuration file only has
  lists). The host is `None`, blank text, `"*"`, text, an address, an
  `Interface` or a `MACAddress`; the ports are an `int`, digit text, `None` (the
  default ports) or a sequence of those. A pair is told from two bindings by its
  second item being port-like (`None`, an `int` that is not a `bool`, digit
  text, or a sequence of those).

### How text is read

In this order, so that no name is ever looked up as a host name:

1. the wildcard forms: `"*"`, `"*:67"`, `":67"`;
2. the whole text as a MAC in any spelling (`aa:bb:cc:dd:ee:ff`,
   `aa-bb-cc-dd-ee-ff`, `aabb.ccdd.eeff`, `aa.bb.cc.dd.ee.ff`, `aabbccddeeff`);
3. host and port split by `split_host`: the port follows the last colon, a bare
   IPv6 address keeps its colons, and a port goes with an IPv6 address only in
   brackets;
4. the host as an IPv4 or IPv6 address;
5. the host as a MAC;
6. otherwise an adapter name (`eth1`, `Wi-Fi 2`, `eth0.100`).

So `"eth1"` and `"localhost"` are adapters, and an adapter whose name is also an
address or a MAC is given as an `Interface`. The colon spelling of a MAC takes
its port in a pair (`("aa:bb:cc:dd:ee:ff", 67)`); an adapter name holding a
colon is given as an `Interface`. Whether an interface exists is for whoever
binds, not for the parse.

Blank text as a whole (`""`, `" , "`, `[]`) names no address and is refused; as
the host of a pair, `""` is the wildcard.

### Examples

With `default_ports=67`, each as `(address, port, interfaces)`:

| `listen` | Result |
| --- | --- |
| `None`, `"*"`, `"0.0.0.0"` | `(0.0.0.0, 67, ())` |
| `":6767"`, `"*:6767"`, `(None, 6767)`, `("", 6767)` | `(0.0.0.0, 6767, ())` |
| `"127.0.0.1:6767,127.0.0.2"` | `(127.0.0.1, 6767, ())`, `(127.0.0.2, 67, ())` |
| `("127.0.0.1", [6767, "6768"])` | `(127.0.0.1, 6767, ())`, `(127.0.0.1, 6768, ())` |
| `"::1"`, `"[::1]"`, `IPv6Address("::1")` | `(::1, 67, ())` |
| `"[::1]:69"`, `("::1", 69)` | `(::1, 69, ())` |
| `"[fe80::1%eth0]:69"` | `(fe80::1%eth0, 69, ())` |
| `"eth1"` | `(0.0.0.0, 67, ("eth1",))` |
| `"eth1:6767,eth2:6767"` | `(0.0.0.0, 6767, ("eth1", "eth2"))` |
| `"aa-bb-cc-dd-ee-ff:6767"` | `(0.0.0.0, 6767, (MACAddress("aa:bb:cc:dd:ee:ff"),))` |
| `"eth1:6767,*:6767"` | `(0.0.0.0, 6767, ())` — a socket named plainly is not limited |

### The family

`family=None` takes each address in the family it is written in. **The wildcard
forms (`None`, `""`, `"*"`, `"*:port"`, `":port"`) and an interface binding are
IPv4's**, as `bind("")` is. `socket.AF_INET` refuses an IPv6 address.
`socket.AF_INET6` refuses an IPv4 address and makes the wildcard forms and an
interface binding IPv6's (`::`). `"::"` and `"0.0.0.0"` are addresses, not
wildcard forms, and keep their family.

### Errors

A value of a type the grammar does not take (a `bool`, a bare number, `bytes`, a
`dict`, a `bool` for a port) is `TypeError`. Everything else is
`NetimpsValueError`, a `ValueError`, with a message that quotes what was
written: a specification that names no address, a port outside 0 to 65535 or
not ASCII digits, a port written twice that disagrees (`("*:67", 68)`),
brackets around anything but an IPv6 address, an adapter name with a `/`, an
address of the wrong family, and a binding with no port when `default_ports` is
empty.

## The sockets a specification names

**`bind_listen(listen=None, default_ports=0, *, family=None, per_address=None, device_binding=True, allow_address_takeover=False, broadcast=False) -> Tuple[UDPEndpoint, ...]`**

Parses (`listen` may be what `parse_listen` returned), drops the interface cache,
looks every interface up, and only then opens sockets. One `UDPEndpoint` comes
back for each socket, in the order of the specification, expansions in place.

- `per_address`: `True` expands every unlimited wildcard into one socket for each
  address of its family; `False` never does; `None` does where
  `has_pktinfo(family)` is false, because a wildcard socket that cannot report
  the arrival interface is no use to a service that needs it.
- `device_binding`: `False` declines the device bind for an interface binding.
- `allow_address_takeover`: passed to `bind`; the default keeps every socket
  exclusive, so a taken port is `AddressInUseError` and not a socket that
  receives nothing.
- `broadcast`: `SO_BROADCAST` on an IPv4 socket. An IPv6 socket never gets it.

What each kind of entry opens:

| Entry | Opens |
| --- | --- |
| an address (`127.0.0.1:67`, `[::1]:69`) | one socket bound to it; its endpoint asks for no packet info |
| a wildcard, not limited | one wildcard socket whose endpoint asks for packet info |
| the same, with `per_address=True` (or `None` and no packet info) | one socket for each address of that family the host holds, every one `iter_addresses` reports, loopback and link-local included, each without packet info. An IPv6 link-local address is bound with its zone, the adapter it is on. Name the addresses yourself to hear fewer |
| a wildcard limited to interfaces | one wildcard socket with packet info and `endpoint.interfaces` the adapters found; a MAC names every adapter carrying it. Bound to the device when `device_binding` is true, `has_device_binding()` is true and exactly one adapter was found |

Every socket is `SOCK_DGRAM`, exclusive, with `connreset` off. **An IPv6 socket
is IPv6 only on every platform** (`IPV6_V6ONLY` 1), so `*` and `::` on one port
are two sockets that do not overlap and no arrival is v4-mapped. An address and
port is bound once whatever the expansion repeats.

Refused before a socket opens, as `NetimpsValueError`: a selector that matches
no adapter with an index (the message says that a host name is never resolved,
for text); a limited binding with `per_address=True`; a limited binding on a host
whose sockets report no packet info for that family.

A device bind the kernel refuses (`DeviceBindingUnsupportedError`, or
`PermissionError` where the option needs a capability) is repeated without the
device, and said once per call at `WARNING` on the logger `netimps._listen`: the
endpoint still serves only its interfaces, and `admits` is the check. An error
the repeat raises is the real one. Any failure closes every socket the call
opened and raises the error unchanged.

### Measured: one port, an IPv4 wildcard and an IPv6-only wildcard

Measured 2026-10-09 on Windows 11 (ARM64, Python 3.14) and Fedora 44 under WSL2
(kernel 6.18, Python 3.14): with `IPV6_V6ONLY` 1 an exclusive IPv4 wildcard
socket and an IPv6 wildcard socket bind one port in either order; a datagram to
`127.0.0.1` reaches only the first and one to `::1` only the second. An IPv6
socket with `IPV6_V6ONLY` 0 beside the IPv4 one is refused (`AddressInUseError`)
on both. macOS and FreeBSD: unmeasured.

### What stays the caller's

The default ports (they are a protocol's), receive buffers
(`set_buffer_size(endpoint.socket, receive=...)` is one call), a receive loop over
the endpoints, and dropping and counting what `admits` refuses. There is no
re-bind and no TCP.
