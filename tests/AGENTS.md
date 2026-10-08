# Tests

Everything about running and writing the tests of `netimps`. The root
`AGENTS.md` points here; the shipped API headers are not about tests.

## Running them

Run from the root of a checkout, on the newest interpreter and on the floor
(3.9, so no unquoted `X | Y` unions at runtime). The venvs are the ones the root
`AGENTS.md` describes under "Environment".

```bash
.venv/3.14-nt-arm64/Scripts/pytest -q
.venv/3.9-nt-arm64/Scripts/pytest -q          # the floor -- run it before pushing
```

On POSIX the scripts live in `bin/` rather than `Scripts/`.

`pyproject.toml` puts `src/` on the path, collects `tests/`, and turns warnings
into errors (each exception would be listed there with its reason; there are
none). `tests/integration/` holds the suites that talk to real sockets, a real
event loop or the platform's own binaries, on loopback only; `conftest.py` above
it applies to both. CI runs `pytest -q -rs`, so every skip prints its reason: a
skip is not a pass, and a rising skip count beside a falling pass count is a
signal, not noise.

## What is here

| File | Covers |
| --- | --- |
| `conftest.py` | the suite-wide network guard and its `no_such_host` / `allow_resolver` / `allow_off_host_destination` opt-outs; the `fake_program` and `server` fixtures |
| `fakedns.py` | the fake name server on loopback (UDP and TCP on one number) that the resolver tests talk to: `FakeNameserver`, built by `make_nameserver()` |
| `test_network_guard.py` | the guard itself: every road to a name server or an off-host destination is refused, and the explicit ways through |
| `test_fakedns.py` | the fake name server's port-pair search and what it reports when the host refuses a pair |
| `test_surface.py` | exactly what `netimps.__all__` exports, and the positional arguments of each callable |
| `test_shipped_headers.py` | the shipped `AGENTS.md` headers: every export is in the top header, every header is listed by the `AGENTS.md` nearest above it (the top header's table, or the root file), none is over its line limit, every printed signature is the live one |
| `test_exceptions.py` | the exception hierarchy and the one place each class is defined |
| `test_import_structure.py` | import direction: no name taken from the root, no module over 500 lines and no function-local sibling import without a recorded reason |
| `test_comments.py` | the shipped source and every shipped header describe the code as it is |
| `test_readme.py` | the README's Python example and command lines run (or are named as not executed, with the reason) |
| `test_ip.py` | `parse`/`try_parse`/`is_valid`, the aliases, CIDR maths, `unmap`, `is_wildcard` |
| `test_classification.py` | the classifiers and `try_parse`: one answer on every Python |
| `test_classify.py` | `classify`: text read as a MAC, a network, an interface or an address |
| `test_mac.py` | `MACAddress` parsing, ordering, subclassing, `hex`, and the hash/eq law across every accepted spelling |
| `test_fqdn.py` | `FQDN`: the label algebra, the pathlib inversion, limits, ordering, the hash/eq law |
| `test_host.py` | `Host`: keeps its text, resolves lazily, caches the answer and the failure |
| `test_host_text.py` | `split_zone`, `split_host` and `join_host` pairs and brackets, `is_local_host`, the MAC pattern's privacy |
| `test_parse_classmethods.py` | `Type.parse` / `try_parse` on `MACAddress`, `FQDN` and `Host` |
| `test_text_and_wire_forms.py` | text and wire forms: `MACAddress.format`, `FQDN.encode` / `decode` / `decode_at`, over mixed-case, derived and non-ASCII names |
| `test_value_types.py` | the value types cannot change after construction; copy and pickle keep the class |
| `test_interfaces.py` | `get_interfaces` against the facts the OS fixes (loopback, indices, `/sys/class/net`), the pure helpers, the fallback, the cache, `get_interface`, `is_local_address`, `iter_addresses`, `is_broadcast` |
| `test_interface_flags.py` | `Interface.is_multicast` and `is_point_to_point` against the kernel's own flags and a real group join, and `cache=` through `iter_addresses`, `bind`, `join_group`, `leave_group` and `ping`, counted by `interface_enumerations()` |
| `test_device_binding.py` | `bind(device=)` and `has_device_binding()`: refused before a socket opens, and on Linux the restriction itself on loopback, IPv4 and IPv6 |
| `test_sockets.py` | bind options, `tcp_check`, route, MTU, `disable_connreset`, `set_buffer_size`, `SocketOption`, `max_udp_payload`; loopback, or assertions about shape |
| `test_bind_defaults.py` | `bind()`: family inference, the `connreset` default, the hint and the one exception type for a taken port, hijack resistance, port sharing, the address types it accepts |
| `test_listen_grammar.py` | `parse_listen`: every accepted and refused form as a table, the family rule, the default ports, a result read back as a specification, and no name resolved or adapter listed |
| `test_udp_admits.py` | `UDPEndpoint(interfaces=)` and `admits`: no filtering on receive, a limited endpoint on loopback and on another adapter, the refusals at construction |
| `test_udp_datagram.py` | `send(src=<address>)` without enumeration, truncation on both receive paths, `Datagram.destination` / `is_unicast`, `datagrams(on_error=)` |
| `test_msg.py` | `recvmsg`/`sendmsg` on every platform, and the `socket` patch (install, reverse, no-op on POSIX) |
| `test_freebsd_pktinfo.py` | IPv4 arrival data and source pinning where the carrier is not `IP_PKTINFO` |
| `test_proc.py` | the runner: missing program, exit status, deadline that kills the children, invalid bytes, `LC_ALL`, stdin |
| `test_net.py` | the `resolve` backend chain (real dnspython and wire client against the fake name server, `nslookup` as a fake program), `ping` and its options, the port registry |
| `test_retry.py` | `retry`, `backoff_delays` and `Backoff`: delays, jitter modes, argument checks |
| `test_scheme_ports.py` | the WS-Management scheme spellings and their canonical reverse names |
| `test_dns_wire.py` | the standard-library DNS client against the fake name server and a fake DoH endpoint |
| `test_dns_bounds.py` | a DNS reply is untrusted input and an argument is not an option |
| `test_dns_search_candidates.py` | the names each resolver backend asks about for a given `search=`, which differ by backend |
| `test_resolution.py` | `Host` and `FQDN` resolving through `resolve()` |
| `test_resolution_cache.py` | `cache=` on `resolve`/`Host`/`FQDN`: hits, negative answers, outages, keys, counted by a fake `nslookup` |
| `test_resolution_deadline.py` | `deadline=` bounds a whole resolution, and `ping` bounds its own lookup |
| `test_resolution_errors.py` | `ResolutionError` is an `OSError`; `NoAnswerError` is its leaf |
| `test_resolution_outage.py` | an outage is not an empty answer, in every resolver backend (real dnspython and wire client against the fake name server) |
| `test_cli.py` | the CLI, driven through the real parser; skips itself when the `cli` extra is absent, and asserts the library still imports with `duho` blocked |
| `integration/test_platform_smoke.py` | the **only** non-mocked tests of the platform binaries: the real `ping`/`ping6`, `discover_mtu` and real loopback sockets |
| `integration/test_udp_endpoint.py` | `UDPEndpoint` on real loopback sockets: the receive path, pktinfo, source pinning, the interface cache |
| `integration/test_udp_reply.py` | `reply_socket` and `reply_address` for a pktinfo-using UDP server |
| `integration/test_async_udp.py` | `arecv`/`datagrams` on a **real loop**, both Windows loop types, and no leaked threads |
| `integration/test_async_waits.py` | `aretry` and `await_for_port` on a **real loop**, every Windows loop type: the loop keeps running while they wait, no thread, a deadline bounds the whole wait, cancelling leaves no socket and no task |
| `integration/test_scan.py` | `scan_ports` / `scan_hosts` and the multicast helpers, loopback only |
| `typing/api.py` | the static-typing contract; never executed, checked by mypy with `typing/consumer.ini` |

## A green suite proves nothing about platform behaviour

Nearly every test that touches `ping`, `traceroute` or `nslookup` puts a fake
program on `PATH` (the `fake_program` fixture) and then asserts the argv the
library *builds*, which can never catch a flag the platform does not have: an
argv test passes for `ping(ipv6=True)` putting `-6` in the argv while macOS
`ping` answers `invalid option -- 6` and exits 64.

`integration/test_platform_smoke.py` is the one file that runs the real
binaries, loopback only, and **nothing in it may be mocked**. Every other ping
test asserts the argv the library builds; this file is what turns "CI is green"
into evidence about the platform. If one of its assertions fails, the library is
broken there: do not mock it to make it pass. A claim about another platform
needs a measurement on that platform (a `ci-*` tag runs the matrix), not a
passing test here.

**A test takes its ground truth from the platform**, never from the code it
tests. A guard that asks the library whether the platform delivers a datagram's
arrival interface cannot fail when the library is wrong; ask a real socket and
a real datagram, and take only constants, never decisions, from the module under
test. A regression test is seen to fail against the broken code, not only to
pass against the fix: plant the defect, watch the test fail, restore.

A `pytest.skip` on `OSError` can hide a regression, because a transient bind
failure then reads as "the platform cannot". Skip for an absent capability, and
say which in the reason.

The ctypes paths cannot be asserted against fixed values, so
`test_interfaces.py` checks invariants plus the pure helpers and the fallback,
which *are* exactly testable.

## Tests never hit the network

`conftest.py` enforces it rather than trusting it. An autouse fixture fails, at
the point of the call and naming the test, any off-host name resolution
(`getaddrinfo`, `gethostbyname[_ex]`, `gethostbyaddr`, `getnameinfo`), any
`connect` or `sendto` to an address that is not loopback, unspecified or held by
one of this machine's own interfaces (on every port; the platform decides "held"
by whether a UDP socket can bind it), any name the C resolver would answer
inside `connect`, any payload to a DNS port, a real `nslookup` (judged by the
server argument and `-port=`), and a real `ping`/`traceroute`/`tracert` of
anything but this host. A wildcard resolver (the kind many ISP and corporate
networks run) turns a suite red when it trusts the resolver, because several
tests assert that a name does *not* resolve. Three escape hatches, each
self-documenting in the test's signature:

- `no_such_host` makes every off-host name fail deterministically. Use it
  whenever the precondition is "given a name that does not resolve"; picking
  something in `.invalid` and trusting the resolver is the flake itself.
- `allow_off_host_destination` lifts the destination rule only, for a test whose
  subject needs one: a UDP `connect` to a public address to learn the route
  (sends nothing), a multicast group the test joined, the limited broadcast. The
  test's docstring says which.
- `allow_resolver` lifts the whole guard for one test, marking it as one whose
  failures may be the network's fault.

The guard deliberately **allows address literals to be parsed**:
`getaddrinfo("1.1.1.1", ...)` parses four numbers and returns, no packet leaves
the machine, and blocking it would push tests into mocking things that were
never remote. Where a test needs a program that would reach out, it stands in a
fake (`fake_program`) rather than patching `subprocess`. `socket.sendmsg` is not
hooked, because a test pins that the library's own stays installed.

## Fakes

**`fake_program` is how tests stand in for a platform binary.** It writes a
program into a temporary directory first on `PATH`: a `#!` script on POSIX, a
`distlib`-built `.exe` launcher on Windows (a `.cmd` shim is refused by the
runner, so it would not exercise the real path). `fake.argv` / `fake.calls` read
back what the library passed; `stdout`, `stderr` and `returncode` may be lists,
one per run. The fixture adds the fake's directory to the guard's allow-list, so
a fake `nslookup` is not mistaken for a real off-host query. Never patch
`subprocess` or `_proc.run` to stand in for a program, except to make the runner
report a deadline the test cannot wait for. A fake is a real process: a test
that passes `timeout=0.1` through to one races the interpreter's start-up, so
use a deadline the fake can meet.

**`FakeNameserver`, built by `make_nameserver()` in `fakedns.py`,** is a name
server on loopback that answers from a small zone over UDP and TCP on one port,
never answers a name containing `silent`, and can be told to drop one record
type. The `server` fixture hands one to a test and skips when the host has no
port free on both transports.

**A test patches the module whose globals the code reads.** A private package
re-exports names from its modules in its `__init__`, and that copy is a
different binding: `monkeypatch.setattr(netimps._dns, "resolve", ...)` leaves
`_dns._lookup.resolve` alone and the test passes without testing anything. Patch
`netimps._dns._lookup`, or `netimps._ping._probe._socket` for the `socket`
module as `_ping` sees it. `test_import_structure.py` keeps a function-local
import from hiding such a binding.

## What the structural tests pin

- `test_surface.py`: the exact contents of `netimps.__all__` and the positional
  arguments of each callable, so an addition, a removal or a keyword-only
  option that becomes positional fails by name.
- `test_import_structure.py`: no module takes a name from the root, no module is
  over 500 lines unless it is named there with its reason, and a function-local
  import of a sibling needs a recorded cause.
- `test_comments.py`: the shipped source and every shipped header contain no
  history wording; a phrase that is a fact goes in its `_ALLOWED` tuple with the
  reason, and an entry whose phrase has left the source fails its own test.
- `test_shipped_headers.py`: see the table above. A signature a header prints is
  compared with `inspect.signature`, so a changed default shows as a failure
  naming the header and the call.
- `test_readme.py`: the README's example and command lines run; an entry that no
  longer matches a README line fails, so the tables cannot go stale.

## The typing check

`typing/api.py` proves the promises of the shipped header's static-typing
section hold for somebody importing the package. It is never executed. It is
checked with a **consumer's** mypy config, `typing/consumer.ini`, not the
package's own, for two reasons, and the second one bites:

1. The package sets `enable_incomplete_feature = ["TypeForm"]` so mypy will
   type-check `__init__.py`'s own overload definitions. Nobody downstream sets
   it, so checking `api.py` with it on is not the check that matters.
2. It keeps the two `lint`-job invocations on different option sets, which is
   what stops the first from poisoning the second through `.mypy_cache`.
   Measured with mypy 1.20.2: from a cold cache, `mypy tests/typing/api.py`
   alone is **clean**, but `mypy src/netimps` followed by `mypy
   tests/typing/api.py` under the *same* config reports **25** `call-overload`
   errors. `TypeForm[_T]` serialises into the cache as plain `type[_T]`, so the
   second run reads a degraded `netimps` and loses every union-alias overload.
   `--no-incremental` restores it.

So do not collapse the two invocations onto one config without passing
`--no-incremental`, and do not read a `call-overload` error in `api.py` as a
contract regression before re-running it from a cold cache.

```bash
.venv/3.14-nt-arm64/Scripts/python -m mypy --config-file tests/typing/consumer.ini tests/typing/api.py
```
