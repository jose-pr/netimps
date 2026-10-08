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

### What stays the caller's

The default ports (they are a protocol's), and checking that an interface
exists.
