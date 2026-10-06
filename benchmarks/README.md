# Benchmarks

A perf suite for `netimps`, run **on demand**. It is deliberately not wired into
CI: shared runners are too noisy for these numbers to mean anything, and a
benchmark that cries wolf gets ignored.

## Reproduce

```bash
python benchmarks/run.py                       # print the table
python benchmarks/run.py --save                # also write results/<name>.json
python benchmarks/run.py --samples 2000        # tighter median
python benchmarks/run.py --only parse          # substring filter
python benchmarks/run.py --save --name my-box  # override the filename
```

From a checkout, `run.py` puts `src/` on the path itself, so no install is
needed. Nothing here touches the network — every case is loopback or pure
computation, so a result is reproducible on a disconnected machine and you are
never accidentally benchmarking somebody's DNS server.

## Schema

One JSON file per (platform, interpreter, architecture) in `results/`, named
`<system>-py<version>-<machine>.json`. Results are **tracked and committed** —
that is the only thing that makes a before/after comparison recoverable later.

```json
{
  "schema": 1,
  "package": "netimps",
  "version": "0.4.0",
  "python": "3.14.6",
  "implementation": "CPython",
  "platform": "Windows-11-10.0.28000-SP0",
  "machine": "ARM64",
  "samples": 400,
  "metrics": {
    "parse_ipv4_literal": {
      "min_ms": 0.0019,
      "median_ms": 0.0023,
      "max_ms": 0.0100,
      "samples": 400
    }
  },
  "notes": { "parse_ipv4_literal": "the hot path for anything that accepts an address as text" }
}
```

**Compare on `median_ms`.** A single average hides run-to-run noise; `max_ms` on
a laptop is usually somebody else's scheduler rather than your code. `min_ms` is
the closest thing to "the work itself", and the gap between min and median is
the honest measure of how much the machine is lying to you.

No machine identity (hostname, addresses) is recorded — these files are
committed, and a benchmark result is not a reason to publish where it ran.

## Reading the numbers

Two groups behave very differently, and conflating them is the usual mistake:

- **Pure computation** — `parse_*`, `split_host`, `collapse`, `subtract`,
  `get_default_port`. Microseconds, stable, and the only ones where a small
  median change is likely to be real.
- **Syscall-bound** — `get_interfaces`, `is_local_address_scan`,
  `get_source_ip`, `get_free_port`. These cross into the kernel, so they are both
  slower and far noisier. `get_interfaces` is the expensive one by a wide margin,
  and `is_local_address` is not free precisely because it re-enumerates: only an
  address no adapter holds measures that, since a loopback address returns
  first (`is_local_address_loopback`), and `_scan_cached` shows the cache.
- **The hot paths of a UDP server and a client** — `udp_endpoint_*`,
  `udp_reply_socket`, `resolve_*` and `host_ip_*`. Each endpoint case has a
  `*_baseline` beside it that does the same on a bare socket or the standard
  library's own lookup, so the difference is what the library adds. The receive
  cases include the send that feeds them in both halves. `resolve_fake_nameserver`
  asks the test suite's fake name server on loopback, started on first use, and
  every name case asks for `localhost` or an address literal: nothing leaves the
  machine.

## Baseline

`results/windows-py3.14.6-arm64.json` is the **pre-optimization baseline**,
captured before any performance work, so these numbers are a starting point,
not an improvement.

Two figures from it are worth knowing before optimising anything:

| metric | median | why it matters |
| --- | --- | --- |
| `get_interfaces` | ~1.3 ms | every membership lookup pays this |
| `parse_ipv4_literal` | ~0.0023 ms | ~1.3 ms buys ~560 address parses |

So `is_local_address` costing ~500x a `parse` is not a parsing problem — it is
the enumeration behind it. Cache the enumeration before touching the parser.

> Per the repo's rules, a **performance claim in a release, changelog or plan
> comes from CI, not from a local run.** These local results are a sanity check
> and a shape, not evidence.
