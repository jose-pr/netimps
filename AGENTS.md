# netimps

Contributor orientation for a checkout of `netimps`, a small, self-contained
network-utilities library: a typed layer over `ipaddress`, native interface
discovery, and the host helpers every network tool rewrites. This file is
development documentation, so it does not ship in the wheel or the sdist; the
library's own reference is the shipped headers below, which are inside the
installed package and must stay self-contained.

| Header | Covers |
| --- | --- |
| `src/netimps/AGENTS.md` | the top API header: every public name with its signature, the conventions, the exceptions, the command line's contract, the environment variables. It lists the per-package headers beside it (`src/netimps/*/AGENTS.md`), which hold the detail of each large topic |
| `tests/AGENTS.md` | running and writing the tests: the network guard, the fakes, the typing check, every test file |

A public API change updates its shipped header in the same commit; the table of
those headers lives in the top one.

## Layout

```
src/netimps/   the package, below
tests/         the suite, with integration/ and typing/ (see tests/AGENTS.md)
docs/          the published site, with mkdocs.yml; built strictly as a release gate
benchmarks/    run on demand, never in CI; results/ is tracked
examples/      two runnable scripts, local and read-only
.github/       the workflows (test, docs, release, probe) and probe/capture.py
pyproject.toml, README.md, CHANGELOG.md, RELEASENOTES.md, LICENSE
```

Under `src/netimps/`, one line per package:

- `__init__.py`, `__main__.py` — the one flat import surface, declared in
  `__all__`, and `python -m netimps`.
- `_ip/` — IP aliases and builders, CIDR maths, classification, host and zone
  splitting, `Host`.
- `_ifaddrs/` — interface discovery through `getifaddrs(3)` and
  `GetAdaptersAddresses`, the enumeration cache, lookups.
- `_sockets/` — `bind`, socket options, source IP, TCP checks, route, hops, MTU.
- `_dns/` — `resolve`, its five backends, the cache, the message codec.
- `_ping/` — `ping` over the platform binary, or a TCP or UDP probe.
- `_udp/` — `UDPEndpoint` and `Datagram`: arrival interface, source pinning.
- `_msg/` — `recvmsg` and `sendmsg` everywhere, and the `socket` patch.
- `_winsock/` — the `ctypes` `WSARecvMsg`/`WSASendMsg` behind `_msg`; Windows
  only, reached only through `_msg`.
- `_fqdn/` — the `FQDN` value type.
- `cli/` — the one public subpackage: the `duho`-backed command line.

The single modules are `_exceptions.py` (the hierarchy), `_parse.py` (the
generic `parse`, `try_parse`, `is_valid`, `classify`, above `_ip`, `_fqdn` and
`_mac`), `_mac.py`, `_scheme.py`, `_scan.py`, `_multicast.py`, `_retry.py`,
`_pktinfo.py` (the pktinfo constants and layouts, imported by neither `_udp` nor
`_msg`), and `_proc.py`, the only module that imports `subprocess` and the one
runner every platform binary goes through.

## Environment

Venvs are named `.venv/<version>-<os>-<arch>/`, one per interpreter this project
is tested against: the latest, and the floor (3.9), which is what CI's oldest
job runs. The suffix is not decoration: on a machine that can run more than one
architecture it is the only thing that tells the two apart.

`<arch>` is what the interpreter was **built for** (`sysconfig.get_platform()`),
not what the host is (`platform.machine()`). They differ: an ARM64 Windows box
runs emulated x64 CPython perfectly happily and reports `ARM64` for the machine
while the interpreter is `win-amd64`. Prefer a native build where one exists:
the emulated one is slower and can diverge on exactly the low-level behaviour
this package pokes at.

```bash
py -3.14-arm64 -m venv .venv/3.14-nt-arm64
py -3.9-arm64  -m venv .venv/3.9-nt-arm64

.venv/3.14-nt-arm64/Scripts/pip install -e ".[dev,docs]"
.venv/3.9-nt-arm64/Scripts/pip install -e ".[dev]"
```

On POSIX the scripts live in `bin/` rather than `Scripts/`, and the name is e.g.
`.venv/3.14-posix-x86_64`. The `dev` extra installs every other extra, so tests
that depend on one run rather than skip.

## Checks

CI runs, on a push to `main`, on a pull request against `main`, on a `ci-*` tag
(a throwaway tag, so an agent without dashboard access can trigger and poll a
run) and on `workflow_dispatch`:

- `black --check src/ tests/`, with `target-version = py39` from
  `pyproject.toml`. Run `black src/ tests/` before committing.
- `mypy --platform linux src/netimps`, then `--platform darwin`, then
  `--platform win32`. `mypy` checks every per-platform branch whatever host it
  runs on but resolves names against the platform it *thinks* it targets, so
  `ctypes.WinDLL`, `socket.SIO_RCVALL` and `socket.ioctl` type fine on Windows
  and fail on the Linux runner. A clean run on one platform says nothing about
  `attr-defined` errors on another.
- `mypy --config-file tests/typing/consumer.ini tests/typing/api.py`, the typing
  contract checked as a consumer would (`tests/AGENTS.md`, "The typing check").
- the test suite, `pytest -q -rs`: the full 3.9 to 3.14 matrix on ubuntu plus
  both edges on windows and macos, and the dependency floors on the oldest
  Python. The commands, the test files and how to write one are in
  `tests/AGENTS.md`. Run both venvs before pushing.

The docs site is built and deployed by a separate `docs.yml`: on a
docs-affecting push to `main`, on `workflow_dispatch`, and on the **Release
workflow completing successfully** (`workflow_run`, *not* `release: published`,
which never fires because GitHub does not start runs from `GITHUB_TOKEN`-created
events), so a wrong sentence on the landing page can be corrected without
cutting a version. `mkdocs build --strict` is the check.

`benchmarks/run.py` is a perf suite run **on demand**, never per push: shared
runners are too noisy for the numbers to mean anything. `python
benchmarks/run.py --save` writes one JSON per (platform, interpreter,
architecture) into `benchmarks/results/`, which is tracked so a before/after
comparison stays recoverable.

## Conventions

- **A private module imports a name from the module that owns it, never from
  the root.** `__init__` imports each private module or package once and
  declares `__all__`; `tests/test_import_structure.py` pins the direction and
  the 500-line module limit. A private package re-exports names for its
  siblings, and a test patches where the code reads the name
  (`tests/AGENTS.md`).
- **`duho` is a CLI-only dependency.** Only modules under `cli/` import it, and
  `cli.main()` imports it inside the function, so a no-extra install gets a
  message rather than an `ImportError` traceback. The library never requires an
  extra.
- **A platform fact is measured, not reasoned, and the comment beside the code
  that depends on it carries the measurement.** The manpages disagree across
  BSD and Linux and a green suite on one platform proves nothing about another:
  a claim about a platform needs a measurement there (a `ci-*` tag runs the
  matrix). `.github/probe/capture.py` answers a platform question with captured
  bytes: push a `probe-*` tag (not `ci-*`, which is `test.yml`'s) or dispatch
  `probe.yml`, then read the uploaded artifact. Its output is redacted by
  default (`--raw` keeps MACs and addresses for local diagnosis) because the
  transcript is uploaded and may be pasted into an issue.
- **Check every platform before adding a socket option or constant, not just
  Windows.** CPython exports `IP_MTU`, `IP_MTU_DISCOVER` and `IP_DONTFRAG` on
  none, so a `getattr(socket, "IP_MTU", None)` guard disables the code
  everywhere. Where the constant is documented and stable, use the literal and
  let the `OSError` from `setsockopt` or `getsockopt` be the "unsupported"
  signal; the BSDs differ from each other as well as from Linux.
- **Comments describe the code as it is**, in a line or three: the constraint,
  the reason, the unit, and a measured platform fact with its date. No history,
  no other project by name, nothing a reader of the public repository cannot
  open. `tests/test_comments.py` enforces the history part over the source and
  every shipped header.
- **Line endings are LF** (`.gitattributes`).

## Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](CHANGELOG.md) and a [`RELEASENOTES.md`](RELEASENOTES.md).
Pre-1.0, MINOR means "the documented API broke" and nothing else: additions and
fixes are PATCH. Pushing a tag matching `v*` triggers the release workflow: test
gate → build → strict docs build (a *gate*, not a deploy) → GitHub release →
publish to PyPI with `skip-existing: true`, so a run that fails partway through
can be re-run. Creating the release fires `docs.yml`, which owns every Pages
deploy. The package builds locally with `hatchling`.
