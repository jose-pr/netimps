# Where a service listens

A service that listens takes one argument that says where, and every library
that listens reads it the same way. `parse_listen` turns it into the sockets it
names, with no I/O; `bind_listen` binds them and returns a `UDPEndpoint` for
each.

```python
import socket
import netimps

netimps.parse_listen("*:67")
# (ListenAddress(address=IPv4Address('0.0.0.0'), port=67, interfaces=()),)

netimps.parse_listen("eth1:67,[::1]:69")
# (ListenAddress(address=IPv4Address('0.0.0.0'), port=67, interfaces=('eth1',)),
#  ListenAddress(address=IPv6Address('::1'), port=69, interfaces=()))

endpoints = netimps.bind_listen("127.0.0.1:0")
for endpoint in endpoints:
    datagram = endpoint.recv()
    if endpoint.admits(datagram):
        ...
```

## What can be written

| Written | Means |
| --- | --- |
| `None`, `"*"`, `"*:67"`, `":67"` | every address (IPv4 unless `family=socket.AF_INET6`) |
| `"127.0.0.1"`, `"127.0.0.1:67"`, `"[::1]:69"`, `"::1"` | one address, with a zone kept (`"fe80::1%eth0"`) |
| `"eth1"`, `"Wi-Fi 2:67"` | the wildcard, limited to that adapter |
| `"aa-bb-cc-dd-ee-ff:67"` | the wildcard, limited to every adapter carrying that MAC |
| `("127.0.0.1", [67, 68])` | a pair of host and ports, as a tuple or a list |
| `["*:67", "[::1]:69"]`, `"*:67,[::1]:69"` | several of those |

A host name is never resolved: `"localhost"` is an adapter name. A
`ListenAddress` is itself accepted, so `parse_listen(parse_listen(x))` is
`parse_listen(x)`. Default ports are the caller's: `parse_listen(listen,
default_ports=(67, 68))` gives each to a binding that names none.

## What is bound

An address is one socket. A wildcard is one socket that reports the arrival
interface, or one socket for each address of the host where that is not
available or `per_address=True` asks for it. A wildcard limited to interfaces is
one socket whose endpoint serves those adapters (`endpoint.interfaces`), bound
to the device on Linux; elsewhere it receives from every interface and
`endpoint.admits(datagram)` says whether a datagram arrived on one it serves.
An IPv6 socket is IPv6 only on every platform, so `"*"` and `"::"` on one port
are two sockets that do not overlap.

Receiving never filters. The caller asks `admits`, so it can count and report
what it drops. Receive buffers, the receive loop and the default ports stay the
caller's.
