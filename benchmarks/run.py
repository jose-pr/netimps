"""Performance suite for netimps.

Run on demand, never as per-push CI -- shared runners are too noisy for the
numbers to mean anything, and a benchmark that cries wolf gets ignored.

    python benchmarks/run.py                 # print a table
    python benchmarks/run.py --save          # also write benchmarks/results/<name>.json
    python benchmarks/run.py --samples 2000  # more samples for a tighter median

Every metric reports **min / median / max milliseconds per call** over N
samples. Compare on the median: a single average hides run-to-run noise, and on
a laptop the max is usually somebody else's scheduler, not your code.

Nothing here touches the network. The two cases that would -- name resolution
and ICMP -- are measured against loopback and against the parsing/argv-building
path respectively, so a result is reproducible on a disconnected machine and
does not silently benchmark somebody's DNS server.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import platform
import statistics
import sys
import time
from typing import Callable, Dict, List

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

import netimps  # noqa: E402  (deliberately after the path insert)

RESULTS = pathlib.Path(__file__).resolve().parent / "results"


def _measure(fn: "Callable[[], object]", samples: int) -> "Dict[str, float]":
    """Time ``fn`` ``samples`` times and reduce to min/median/max ms per call.

    ``perf_counter`` per call rather than ``timeit``'s total-over-N: the whole
    point is the spread, and a total divided by N throws it away.
    """
    timings: "List[float]" = []
    for _ in range(samples):
        start = time.perf_counter()
        fn()
        timings.append((time.perf_counter() - start) * 1000.0)
    return {
        "min_ms": min(timings),
        "median_ms": statistics.median(timings),
        "max_ms": max(timings),
        "samples": samples,
    }


def _interfaces_once():
    return netimps.get_interfaces()


_CACHED_INTERFACES = None


def _iter_addresses_once():
    global _CACHED_INTERFACES
    if _CACHED_INTERFACES is None:
        _CACHED_INTERFACES = netimps.get_interfaces()
    return list(netimps.iter_addresses(_CACHED_INTERFACES))


_SUBNETS = ["10.%d.0.0/16" % octet for octet in range(256)]
_MANY_ADDRESSES = ["10.0.%d.%d" % (a, b) for a in range(8) for b in range(256)]


#: name -> (callable, what the number means). Keep these honest: each one should
#: be something a caller actually does in a loop.
BENCHMARKS = {
    "parse_ipv4_literal": (
        lambda: netimps.parse("192.0.2.10"),
        "the hot path for anything that accepts an address as text",
    ),
    "parse_ipv6_literal": (
        lambda: netimps.parse("2001:db8::1"),
        "same, for v6 -- ipaddress is measurably slower here",
    ),
    "try_parse_rejects": (
        lambda: netimps.try_parse("definitely not an address"),
        "the validation path; rejection goes through an exception",
    ),
    "parse_mac_colon": (
        lambda: netimps.MACAddress("00:11:22:33:44:55"),
        "MAC parsing, the most common spelling",
    ),
    "mac_as_str": (
        lambda: netimps.MACAddress("00:11:22:33:44:55").as_str("-", upper=True),
        "render back out, as a CLI or log line would",
    ),
    "normalize_host_v6_bracketed": (
        lambda: netimps.normalize_host("[2001:db8::1]:443"),
        "host:port splitting, the case that trips naive rsplit",
    ),
    "collapse_256_subnets": (
        lambda: netimps.collapse(_SUBNETS),
        "CIDR merge over a /8 worth of /16s",
    ),
    "subtract_from_default_route": (
        lambda: netimps.subtract(["0.0.0.0/0"], ["10.0.0.0/8", "192.168.0.0/16"]),
        "the set difference ipaddress does not ship",
    ),
    "get_interfaces": (
        _interfaces_once,
        "full NIC enumeration through ctypes -- the expensive one",
    ),
    "iter_addresses_cached": (
        _iter_addresses_once,
        "flattening an already-enumerated list; isolates the loop from the syscall",
    ),
    "is_local_address_hit": (
        lambda: netimps.is_local_address("127.0.0.1"),
        "membership lookup; re-enumerates, which is why it is not free",
    ),
    "get_source_ip_loopback": (
        lambda: netimps.get_source_ip("127.0.0.1"),
        "unconnected UDP socket + getsockname; sends nothing",
    ),
    "get_free_port": (
        netimps.get_free_port,
        "bind(0) + close, the standard racy-but-useful helper",
    ),
    "get_default_port": (
        lambda: netimps.get_default_port("https"),
        "scheme registry lookup",
    ),
    "parse_1024_addresses": (
        lambda: [netimps.parse(a) for a in _MANY_ADDRESSES],
        "bulk parse, to show per-call overhead against a real workload",
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=500)
    parser.add_argument("--save", action="store_true", help="write results/<name>.json")
    parser.add_argument("--name", default=None, help="override the result filename")
    parser.add_argument(
        "--only", default=None, help="substring filter on benchmark name"
    )
    args = parser.parse_args()

    selected = {
        name: value
        for name, value in BENCHMARKS.items()
        if args.only is None or args.only in name
    }
    if not selected:
        print("no benchmark matches %r" % (args.only,), file=sys.stderr)
        return 2

    metrics = {}
    width = max(len(name) for name in selected)
    print("%-*s %10s %10s %10s" % (width, "benchmark", "min ms", "median", "max ms"))
    print("-" * (width + 33))
    for name, (fn, _why) in selected.items():
        fn()  # warm up: first call pays for imports, caches and page faults
        result = _measure(fn, args.samples)
        metrics[name] = result
        print(
            "%-*s %10.4f %10.4f %10.4f"
            % (width, name, result["min_ms"], result["median_ms"], result["max_ms"])
        )

    payload = {
        "schema": 1,
        "package": "netimps",
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "samples": args.samples,
        "metrics": metrics,
        "notes": {name: why for name, (_fn, why) in selected.items()},
    }

    if args.save:
        RESULTS.mkdir(exist_ok=True)
        name = args.name or "%s-py%s-%s" % (
            platform.system().lower(),
            platform.python_version(),
            platform.machine().lower(),
        )
        path = RESULTS / ("%s.json" % name)
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print("\nwrote %s" % path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
