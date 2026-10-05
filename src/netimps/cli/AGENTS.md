# `netimps` command line — public API header

Header-file-style reference for the command-line commands of the `netimps`
package: every public export with its signature, arguments, contract and
gotchas, so it can be used without reading its source. It ships inside the
package and is self-contained; the top header is `netimps/AGENTS.md`.
Development documentation lives with the source at
<https://github.com/jose-pr/netimps>.

This directory (`netimps/cli/`) is the public `netimps.cli` subpackage, whose
entry point is `main`; the commands run as the `netimps` console script and as
`python -m netimps`.

## Command line

```
netimps interfaces                       # names, MACs, MTU, addresses
netimps ping 8.8.8.8 -m tcp -p 443       # icmp | tcp | udp
netimps resolve example.com aaaa
netimps resolve 8.8.8.8                  # no rdtype -> auto ptr -> dns.google
netimps check example.com https          # port or scheme name
netimps route 8.8.8.8 --hops
netimps mtu 8.8.8.8 -m udp -p 9999
netimps scan 192.0.2.0/29 -p common
netimps addr 00:00:5e:00:53:01           # address, network or MAC
netimps source 8.8.8.8                   # which local address reaches it
netimps port https                       # 443; `netimps port` gives a free one
netimps split '[::1]:8080'               # -> ::1  8080
```

Aliases: `interfaces|ifaces|if`, `resolve|dns`, `check|tcp`, `addr|parse`, `source|src`.

- **`--json` on every command**, so output is scriptable. Text output is for
  humans and its exact wording is not a stability guarantee; the JSON shape is.

- **stdout carries the answer and nothing else.** Every diagnostic —
  `error: ...`, `no interface named ...`, `no route to ...` — goes to
  **stderr**, so `--json` stays parseable exactly where a script needs it most:
  on failure stdout is empty and the exit code carries the verdict.

- **The positional argument is required** for `ping`, `resolve`, `check` (both
  of its two), `mtu`, `scan`, `addr` and `split`, so `netimps ping` is not an
  answer about the empty string; a missing one is argparse's usage error on
  stderr with exit 2. `route` and `source` default to `8.8.8.8`.

- **JSON shapes** (a contract; keys do not change):
  - `interfaces`: a list of `{name, index, mac, mtu, is_loopback, addresses,
    is_up, raw}` (`raw` is `null` without `--raw`).
  - `ping`: `{ok, host, rtt_ms, ttl, attempts, method}`; `rtt_ms` is
    milliseconds (the library's `PingResult.rtt` is seconds).
  - `resolve`: a list of record strings.
  - `check`: `{ok, host, port}`.
  - `route`: `{dst, src, gateway, interface_index, on_link}` plus `hops` with
    `--hops`; `on_link` is `true`, `false` or `null`.
  - `mtu`: `{dst, mtu, method}` plus `mss` for `--method tcp`; `mtu` is `null`
    for no answer.
  - `scan`: a host target gives `{host, ports}`; a network target gives a list
    of `{host, ports}`.
  - `addr`: `{kind, value, ...}` with `kind` `mac` (`oui`, `is_multicast`,
    `is_local`), `network` (`network_address`, `netmask`, `num_addresses`,
    `version`; an address with a prefix is shown as its network) or `address`
    (`version`, `is_private`, `is_global`, `is_loopback`, `is_multicast`,
    `is_link_scoped`, `reverse_pointer`).
  - `source`: `{dst, src}`.
  - `port`: `{free_port}` with no argument, `{port, scheme}` for a number,
    `{scheme, port}` for a name; the missing half is `null`.
  - `split`: `{host, port}`; `port` is `null` without one.

- **`netimps port <unknown>` exits 1**: a lookup that found no mapping is an
  *answer*, the way an empty `resolve` is, and a valid port with no
  registered scheme is no caller mistake. Which ports have one depends on the
  host's services database: `9999` has none on Linux and Windows and is
  `distinct` on macOS. A port outside
  `0-65535` exits 2. `netimps check <host> <unknown-scheme>` exits 2, because
  there is then no port to connect to and nothing was tested.

- `netimps route` prints an `on-link  <True|False|unknown>` line and renders a
  missing next-hop lookup as `gateway  (unknown)` rather than
  `(on-link, no router)`; `--json` accordingly has `"on_link": null` as a third
  possible value.
