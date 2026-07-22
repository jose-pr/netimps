# netimps

**The network utilities every tool ends up rewriting** — interface discovery,
"which is my IP", reachability checks, CIDR maths, `host:port` parsing, DNS,
ping, scanning and multicast — as one typed, flat-import library.

Built on the standard library: the only runtime dependency is `dnspython`, and
only `resolve()` uses it. Interface enumeration, routing and multicast are
`ctypes` bindings to the platform's own APIs, so there is nothing to compile
and no wheel to miss for your platform.

## Installation

```bash
pip install netimps
```

Requires Python 3.9+.

## 30-second tour

```python
import netimps
from netimps import IPNetwork, MACAddress, parse

# Interfaces: names, MACs, MTU and real prefixes on every OS
for iface in netimps.get_interfaces():
    print(iface.name, iface.mac, iface.mtu, [str(ip) for ip in iface.ips])

# One parsing entry point; types are what you annotate with
parse("10.0.0.5/24", IPNetwork)          # IPv4Network('10.0.0.0/24')
netimps.try_parse("nope", netimps.IPAddress)     # None

# Which of my addresses actually reaches that host?
netimps.get_source_ip("8.8.8.8")         # IPv4Address(...)

# The honest reachability test
netimps.tcp_check("example.com", 443)    # True
```

## Design notes

A few behaviours are deliberate:

- **`Interface.is_loopback` is computed from addresses, not names** — `lo`,
  `lo0` and `Loopback Pseudo-Interface 1` share no spelling.
- **Concrete types are strict about family.** `parse("::1", IPAddress)` works;
  `parse("::1", IPv4Address)` raises rather than quietly returning v6.
- **`resolve` raises on a malformed query** rather than returning `[]` — a
  typo'd record type should not look like "no such record".
- **`ping(ttl=...)` behaves the same on every OS.** Windows `ping` exits `0`
  for "TTL expired in transit", so the reply address is verified instead of
  trusting the exit code.
- **`path_mtu` returns `None` on Windows** — `IP_MTU` does not exist there, and
  guessing would be worse. Use `Interface.mtu` for the local link.

## Learn more

- [API Reference](api/reference.md) — every export, generated from the source.
- [Changelog](changelog.md)
