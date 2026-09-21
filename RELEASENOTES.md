# Release notes

The detailed companion to [`CHANGELOG.md`](CHANGELOG.md): migration detail,
benchmark figures and the validation evidence behind each release. The
changelog says *what changed*; this says *what it costs you and how it was
checked*.

## 0.3.1 — 2026-09-21

Three patch-level fixes, none found by the test suite. Two of the three were
**pinned as the requirement by a passing test** — the suite asserted the
defect. That is the pattern worth naming: a test written from the
implementation can only ever confirm the implementation.

### Nothing to migrate

No documented contract changed. The `resolve()` fix restores the contract
0.3.0 broke, so code written against 0.2.x is correct again without edits, and
code written against 0.3.0's raise keeps working if it passes `strict=True`.

### What was wrong, and how each was found

- **`resolve()` raised on a resolver outage** instead of returning `[]`,
  contradicting its own docstring in the same release. Reported by the
  maintainer within hours of 0.3.0. `if not resolve(host):` — the idiom the
  function exists for — became an uncaught `ResolutionError` anywhere DNS was
  unreachable, which is the one condition a caller most wants to survive.
  `strict=True` is the opt-in for callers that do need an outage told apart
  from a dead name.
- **`bind_error_hint` misdiagnosed Windows `WSAEACCES` as a privilege
  problem.** Found in `pydhcp`, which requires `netimps>=0.3.0` and had
  written its own replacement with the measurement in a comment. A consumer
  routing around our bug is a stronger signal than any test we had — ours
  asserted the wrong behaviour as the requirement.
- **`docs.yml`'s `release: published` trigger never fired**, because GitHub
  does not start workflow runs from `GITHUB_TOKEN`-created events. The 0.3.0
  site was correct only because the push-to-main trigger happened to cover it.
  This release is the first to exercise the `workflow_run` replacement.

### Benchmarks

Not re-run. Nothing here touches a hot path — two error-message branches, one
return statement and a workflow trigger. The 0.3.0 baseline below still
stands.

**Next perf target:** none set. The figure worth watching is
`get_interfaces`, since every membership lookup pays it (see the table below).

## 0.3.0 — 2026-09-21

A correctness release. Nothing here was a performance change.

### Benchmarks

**No previous→current table: 0.3.0 establishes the baseline.** `benchmarks/`
did not exist before this release, so there is nothing to compare against. The
committed baseline is `benchmarks/results/windows-py3.14.6-arm64.json`.

| metric | median ms | why it is the one to watch |
| --- | --- | --- |
| `get_interfaces` | 1.30 | full ctypes NIC enumeration; every membership lookup pays it |
| `is_local_address` | 0.0088 | re-enumerates, which is why it is not free |
| `collapse` (256 × /16) | 2.31 | the expensive pure-computation path |
| `parse` (IPv4 literal) | 0.0023 | the hot path for anything taking an address as text |
| `parse` × 1024 | 4.75 | per-call overhead against a realistic workload |

Read: `is_local_address` costing ~4× a single parse is not a parsing problem,
it is the enumeration behind it. Cache the enumeration before touching the
parser.

**Caveats.** These are **local** figures from one Windows 11 ARM64 laptop
(Snapdragon X2 Elite, CPython 3.14.6), 400 samples per metric, taken while
other work was running. Per this project's rules a performance claim in a
release comes from CI, not a local run — so treat the table as a shape and a
starting point, not as evidence. Syscall-bound metrics (`get_interfaces`,
`get_source_ip`, `get_free_port`) are far noisier than the pure-computation
ones; compare on the median and expect the max to be somebody else's
scheduler.

### Migration

Seven documented contracts changed. In rough order of how likely you are to
hit them:

**`MACAddress` no longer compares equal to a `str`.**

```python
mac == "aa:bb:cc:dd:ee:ff"                    # was True, now False
MACAddress.try_parse("aa:bb:cc:dd:ee:ff") == mac   # the replacement
```

This is the one change with no compatible middle ground. `__eq__` accepted any
spelling while `__hash__` hashed only the packed bytes, so `mac == text` was
`True` while `mac in {text}` was `False` and a dict lookup silently missed. No
hash can agree with every spelling of a string, so the coercion had to go. In
exchange, `==`, `in` and dict lookup now agree with each other.

Also narrower: mixed separators (`00-11:22-33:44-55`) and `MACAddress(True)`
now raise.

**`resolve()` no longer stops on an empty answer.** Only a non-empty answer
stops the chain. Names that only NSS can resolve — `localhost`, hosts-file
entries, `.local` — now resolve instead of returning `[]`. The cost: a
genuinely non-existent name costs two or three backend calls instead of one,
and the last may spawn `nslookup`. `backends="dnspython"` restores the single
call if you need it.

**`Route.on_link` is `Optional[bool]`.** `None` means no next-hop lookup could
be made, which previously came back as a confident `True`. `None` is falsy, so
`if route.on_link:` keeps the safe branch; `route.on_link is True` and
`== True` change meaning.

**`bind(reuse_address=True)` on Windows** now sets `SO_EXCLUSIVEADDRUSE`
instead of `SO_REUSEADDR`, because on Windows the latter lets *another
process* bind a port you are already listening on. Pass
`allow_address_takeover=True` if you were relying on that. POSIX is unchanged.

**Ports are validated.** `tcp_check`, `wait_for_port`, `scan_ports`,
`scan_hosts`, `get_pmtu`, `discover_mtu` and `get_tcp_mss` raise `ValueError`
outside `0-65535` and `TypeError` for a non-`int` — including a service-name
string, which must go through `get_default_port` first. Previously the socket
layer masked the value to 16 bits, so `port + 65536` answered about `port`.

**`resolve_nslookup` raises** for an option-shaped, empty or whitespace query
(rejected before any subprocess starts), and for a non-zero exit carrying no
"no such name" marker. An exit-1 NXDOMAIN is still `[]`.

**`netimps.__version__` is read, not restated.** It now comes from
`importlib.metadata.version("netimps")` rather than a literal in
`__init__.py`, so it cannot drift from the distribution metadata. A source
tree with no installed metadata reports `0.0.0+unknown` rather than a stale
number.

**CLI:** positional arguments are required rather than defaulting to `""`, and
every diagnostic moved from stdout to stderr so `--json` stays parseable on
error paths.

### Validation

| check | result |
| --- | --- |
| tests | 657 passed, 6 skipped (432 before this cycle), on **both** 3.14 and the 3.9 floor |
| tests, with the network guard active | 657 passed |
| tests, against a simulated wildcard resolver | 657 passed |
| `mypy src/netimps` | clean for `--platform linux`, `darwin` and `win32` (27 errors before) |
| `mypy tests/typing/api.py` | clean under `tests/typing/consumer.ini` (never executed before) |
| `black --check` | clean, 29 files |
| `mkdocs build --strict` | exit 0 |
| `python -m build` | wheel + sdist; `py.typed` and both shipped docs present; no `*.local.*` leakage; editable re-install intact |
| `leak_check.py` | PASS |

**CI:** run `35601208005`, all ten matrix entries (Python 3.9–3.14 on Ubuntu,
3.9 and 3.14 on Windows and macOS) plus the lint job, green. The probe
workflow was validated separately in run `35600571900`, green on all three
runners.

The macOS behaviour this release fixes cannot be checked on the development
machine, so it was validated on runners. Four earlier runs failed and are the
reason several of these fixes exist in their current form — notably
`IP_DONTFRAG` being 28 on Darwin where it is 67 on FreeBSD, and the multicast
scope living in the address rather than in `ipaddress.is_link_local`. Skip
reasons are printed (`pytest -rs`) so a skipped platform test cannot be
mistaken for a passing one; on macOS no smoke test skips, which is what makes
"IPv6 ping works there" a measurement rather than an inference.

### Publication state

Prepared, `main` pushed, tag awaiting the release workflow.
