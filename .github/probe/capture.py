"""Capture real platform behaviour that unit tests cannot assert.

Throwaway CI instrumentation: it answers questions the repo's findings queue
has open ("what does macOS ping6 actually print?") with captured bytes rather
than with a guess. Prints a human-readable transcript and writes the same
content as JSON for download.

Never raises -- every probe records its own failure and the run continues, so
one broken step cannot hide the rest of the transcript.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time

_PARSER = argparse.ArgumentParser(description="Capture real platform behaviour.")
_PARSER.add_argument(
    "--raw",
    action="store_true",
    help="do not redact MACs and addresses (local diagnosis only)",
)
ARGS = _PARSER.parse_args()

RESULTS = {"platform": {}, "probes": []}

#: This host's own names, longest first so a FQDN is masked before the short
#: form can eat its prefix.
_HOST_NAMES = sorted({socket.gethostname(), socket.getfqdn()}, key=len, reverse=True)

#: A MAC, and an IPv4/IPv6 address with a host part worth hiding.
_MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")
_V4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def redact(text):
    """Mask host identity while keeping everything a platform question needs.

    The transcript is uploaded as a CI artifact and pasted into findings, and
    none of the questions it answers -- which flag does this ping take, is this
    socket option exported, what punctuation does a reply line use -- needs the
    runner's real MAC or LAN layout. So the *shape* is kept and the identity is
    not: a MAC keeps its OUI, an address keeps its leading octet.

    Loopback, link-local and the documentation ranges are left alone: they
    identify nobody and they are frequently the point of the measurement.
    """
    if ARGS.raw:
        return text
    # Recurse: the transcript is printed as strings but *recorded* as nested
    # lists and dicts, and redacting only the printed half would leave the
    # uploaded artifact -- the part that actually travels -- unredacted.
    if isinstance(text, dict):
        return {key: redact(value) for key, value in text.items()}
    if isinstance(text, (list, tuple)):
        return type(text)(redact(item) for item in text)
    if not isinstance(text, str):
        return text

    def mask_v4(match):
        first = match.group(1)
        whole = match.group(0)
        if first in ("127", "169", "0") or whole.startswith(
            ("192.0.2.", "198.51.100.", "203.0.113.")
        ):
            return whole
        return "%s.x.x.x" % first

    # The host's own name, which appears in the platform block and all over the
    # resolver section. The *shape* is what those probes are about -- notably
    # whether it ends in `.local`, which is the mDNS question -- so the suffix
    # survives and the name does not.
    for name in _HOST_NAMES:
        if name:
            suffix = ".local" if name.lower().endswith(".local") else ""
            text = text.replace(name, "<hostname>" + suffix)

    text = _MAC_RE.sub(lambda m: m.group(1)[:8] + ":xx:xx:xx", text)
    text = _V4_RE.sub(mask_v4, text)
    # Global IPv6 only: fe80:: and ::1 stay, since both are the measurement.
    text = re.sub(r"\b(2[0-9a-fA-F]{3}):[0-9a-fA-F:]{4,}\b", r"\1:xxxx::x", text)
    return text


def section(title):
    print("\n" + "=" * 78)
    print("== " + title)
    print("=" * 78)


def record(name, **fields):
    entry = {"name": name}
    entry.update({k: redact(v) for k, v in fields.items()})
    RESULTS["probes"].append(entry)
    return entry


def run(name, argv, timeout=20.0):
    """Run argv, capturing argv/exit/elapsed/stdout/stderr verbatim."""
    print("\n--- %s" % name)
    print("$ %s" % " ".join(argv))
    if shutil.which(argv[0]) is None:
        print("   [absent: %s not on PATH]" % argv[0])
        record(name, argv=argv, absent=True)
        return
    start = time.perf_counter()
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout)
        elapsed = time.perf_counter() - start
        out = (proc.stdout or b"").decode("utf-8", "replace")
        err = (proc.stderr or b"").decode("utf-8", "replace")
        print("   exit=%d elapsed=%.3fs" % (proc.returncode, elapsed))
        for line in out.splitlines():
            print("   out| %s" % redact(line))
        for line in err.splitlines():
            print("   err| %s" % redact(line))
        record(
            name,
            argv=argv,
            exit=proc.returncode,
            elapsed=round(elapsed, 3),
            stdout=out,
            stderr=err,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - start
        print("   TIMEOUT after %.3fs" % elapsed)
        record(name, argv=argv, timeout=True, elapsed=round(elapsed, 3))
    except OSError as exc:
        print("   OSError: %r" % (exc,))
        record(name, argv=argv, error=repr(exc))


def call(name, fn):
    """Evaluate fn(), capturing its value or its exception."""
    start = time.perf_counter()
    try:
        value = fn()
        elapsed = time.perf_counter() - start
        print("   %-46s = %s   (%.3fs)" % (name, redact(repr(value)), elapsed))
        record(name, value=repr(value), elapsed=round(elapsed, 3))
    except BaseException as exc:  # noqa: BLE001 - a probe must never abort
        elapsed = time.perf_counter() - start
        print("   %-46s ! %r   (%.3fs)" % (name, exc, elapsed))
        record(name, error=repr(exc), elapsed=round(elapsed, 3))


# --------------------------------------------------------------------------
section("Host")
# --------------------------------------------------------------------------
RESULTS["platform"] = {
    "sys.platform": sys.platform,
    "os.name": os.name,
    "platform.platform": platform.platform(),
    "platform.machine": platform.machine(),
    "platform.release": platform.release(),
    "python": sys.version,
    "hostname": socket.gethostname(),
    "fqdn": socket.getfqdn(),
}
for key, value in RESULTS["platform"].items():
    print("   %-22s %s" % (key, redact(str(value))))

POSIX = os.name != "nt"
DARWIN = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")

# --------------------------------------------------------------------------
section("ping binaries and usage text")
# --------------------------------------------------------------------------
for binary in ("ping", "ping6"):
    print("\n--- which %s" % binary)
    found = shutil.which(binary)
    print("   %s" % found)
    record("which:%s" % binary, value=found)

# BSD ping prints its usage on stderr when given an unknown flag; Linux has -h.
run("ping-usage", ["ping", "-h"] if LINUX else ["ping", "-Z"])
if shutil.which("ping6"):
    run("ping6-usage", ["ping6", "-Z"])

# --------------------------------------------------------------------------
section("Raw ping: exactly the argv the library emits today")
# --------------------------------------------------------------------------
if POSIX:
    run("lib-argv-v4-loopback", ["ping", "-c", "1", "-W", "1", "-n", "127.0.0.1"])
    run("lib-argv-v6-loopback", ["ping", "-c", "1", "-W", "1", "-n", "-6", "::1"])
    run("v6-no-dash6", ["ping", "-c", "1", "-W", "1", "-n", "::1"])
    if shutil.which("ping6"):
        run("ping6-loopback", ["ping6", "-c", "1", "::1"])
        run("ping6-loopback-n", ["ping6", "-c", "1", "-n", "::1"])
else:
    run("lib-argv-v4-loopback", ["ping", "-n", "1", "-w", "1000", "127.0.0.1"])
    run("lib-argv-v6-loopback", ["ping", "-n", "1", "-w", "1000", "-6", "::1"])

# --------------------------------------------------------------------------
section("-W semantics: seconds (Linux) or milliseconds (BSD)?")
# --------------------------------------------------------------------------
# 192.0.2.1 is TEST-NET-1: routable nowhere, so it never answers, and the
# elapsed time is the whole measurement. Linux -W is SECONDS, so -W 1 and -W 4
# differ by ~3s. BSD -W is MILLISECONDS, so both return almost immediately --
# which would mean netimps' `-W max(1, ceil(timeout))` gives macOS a 1ms
# deadline for every ping.
if POSIX:
    run("W-1-blackhole", ["ping", "-c", "1", "-W", "1", "-n", "192.0.2.1"], timeout=30)
    run("W-4-blackhole", ["ping", "-c", "1", "-W", "4", "-n", "192.0.2.1"], timeout=30)
    if DARWIN:
        # If -W is milliseconds, this is the 4-second wait the library meant.
        run(
            "W-4000-blackhole",
            ["ping", "-c", "1", "-W", "4000", "-n", "192.0.2.1"],
            timeout=30,
        )
else:
    run("w-1000-blackhole", ["ping", "-n", "1", "-w", "1000", "192.0.2.1"], timeout=30)
    run("w-4000-blackhole", ["ping", "-n", "1", "-w", "4000", "192.0.2.1"], timeout=30)

# --------------------------------------------------------------------------
section("-t semantics: TTL (Linux) or overall deadline (BSD)?")
# --------------------------------------------------------------------------
# netimps sends `-t <ttl>` on every POSIX platform. On BSD `-t` is a deadline in
# seconds and `-m` is the TTL, so ping(ttl=5) there would set a 5s timeout and
# leave the hop limit at its default -- silently not the requested probe.
if POSIX:
    run("t-1-loopback", ["ping", "-c", "1", "-W", "1", "-n", "-t", "1", "127.0.0.1"])
    run("m-1-loopback", ["ping", "-c", "1", "-W", "1", "-n", "-m", "1", "127.0.0.1"])
    run(
        "t-1-offlink",
        ["ping", "-c", "1", "-W", "2", "-n", "-t", "1", "192.0.2.1"],
        timeout=30,
    )
else:
    run("i-1-loopback", ["ping", "-n", "1", "-w", "1000", "-i", "1", "127.0.0.1"])

# --------------------------------------------------------------------------
section("-I semantics: source address (Linux) or multicast-only (BSD)?")
# --------------------------------------------------------------------------
# netimps sends `-I <address>` on every POSIX platform for src=. BSD documents
# -I as applying only to multicast destinations and spells the unicast source
# address -S, so a pinned source may be silently ignored or rejected there.
if POSIX:
    run(
        "I-loopback-src",
        ["ping", "-c", "1", "-W", "1", "-n", "-I", "127.0.0.1", "127.0.0.1"],
    )
    run(
        "S-loopback-src",
        ["ping", "-c", "1", "-W", "1", "-n", "-S", "127.0.0.1", "127.0.0.1"],
    )
else:
    run(
        "S-loopback-src",
        ["ping", "-n", "1", "-w", "1000", "-S", "127.0.0.1", "127.0.0.1"],
    )

# --------------------------------------------------------------------------
section("-4 / -6 / -s / -M acceptance")
# --------------------------------------------------------------------------
if POSIX:
    run("dash4-loopback", ["ping", "-c", "1", "-W", "1", "-n", "-4", "127.0.0.1"])
    run("size-100", ["ping", "-c", "1", "-W", "1", "-n", "-s", "100", "127.0.0.1"])
    run("localhost-name", ["ping", "-c", "1", "-W", "1", "-n", "localhost"])
    if DARWIN:
        run(
            "M-do-unsupported",
            ["ping", "-c", "1", "-W", "1", "-n", "-M", "do", "127.0.0.1"],
        )

# --------------------------------------------------------------------------
section("netimps: library-level results")
# --------------------------------------------------------------------------
try:
    import netimps

    print("   netimps from %s" % (netimps.__file__,))
except Exception as exc:  # noqa: BLE001
    print("   IMPORT FAILED: %r" % (exc,))
    netimps = None
    record("import-netimps", error=repr(exc))

if netimps is not None:
    print("\n-- ping()")
    call("ping('127.0.0.1')", lambda: netimps.ping("127.0.0.1"))
    call("ping('127.0.0.1').rtt_ms", lambda: netimps.ping("127.0.0.1").rtt_ms)
    call("ping('::1')", lambda: netimps.ping("::1"))
    call("ping('::1', ipv6=True)", lambda: netimps.ping("::1", ipv6=True))
    call("ping('localhost')", lambda: netimps.ping("localhost"))
    call("ping('localhost', ipv6=True)", lambda: netimps.ping("localhost", ipv6=True))
    call("ping('localhost', ipv6=False)", lambda: netimps.ping("localhost", ipv6=False))
    call("ping('127.0.0.1', ttl=1)", lambda: netimps.ping("127.0.0.1", ttl=1))
    call("ping('192.0.2.1', timeout=3)", lambda: netimps.ping("192.0.2.1", timeout=3))
    call(
        "ping('127.0.0.1', src='127.0.0.1')",
        lambda: netimps.ping("127.0.0.1", src="127.0.0.1"),
    )
    call(
        "ping('127.0.0.1', method='tcp', port=22)",
        lambda: netimps.ping("127.0.0.1", method="tcp", port=22),
    )
    call(
        "ping('127.0.0.1', method='udp', port=9)",
        lambda: netimps.ping("127.0.0.1", method="udp", port=9),
    )

    print("\n-- interfaces (validates the ctypes getifaddrs/GetAdaptersAddresses path)")

    def dump_interfaces():
        rows = []
        for iface in netimps.get_interfaces():
            rows.append(
                {
                    "name": iface.name,
                    "mac": str(iface.mac) if iface.mac else None,
                    "mtu": iface.mtu,
                    "index": getattr(iface, "index", None),
                    "up": getattr(iface, "is_up", None),
                    "loopback": getattr(iface, "is_loopback", None),
                    "ips": [str(ip) for ip in iface.ips],
                }
            )
        return rows

    try:
        rows = dump_interfaces()
        record("get_interfaces", value=rows)
        for row in rows:
            print("   %s" % redact(json.dumps(row)))
    except Exception as exc:  # noqa: BLE001
        print("   get_interfaces FAILED: %r" % (exc,))
        record("get_interfaces", error=repr(exc))

    print("\n-- sockets / routing / MTU")
    call("get_source_ip('1.1.1.1')", lambda: netimps.get_source_ip("1.1.1.1"))
    call(
        "get_source_ip('2606:4700:4700::1111')",
        lambda: netimps.get_source_ip("2606:4700:4700::1111"),
    )
    call("get_free_port()", lambda: netimps.get_free_port())
    call("tcp_check('127.0.0.1', 1)", lambda: netimps.tcp_check("127.0.0.1", 1))
    call("get_route('1.1.1.1')", lambda: netimps.get_route("1.1.1.1"))
    call("get_route('127.0.0.1')", lambda: netimps.get_route("127.0.0.1"))
    call("get_pmtu('1.1.1.1')", lambda: netimps.get_pmtu("1.1.1.1"))
    call("get_tcp_mss('127.0.0.1', 22)", lambda: netimps.get_tcp_mss("127.0.0.1", 22))
    call("is_local_address('127.0.0.1')", lambda: netimps.is_local_address("127.0.0.1"))
    call("interface_for('127.0.0.1')", lambda: netimps.interface_for("127.0.0.1"))

    print("\n-- DNS: the .local / mDNS chain question")
    own = socket.gethostname()
    print("   gethostname() = %r" % (own,))
    record("gethostname", value=own)
    for name in (own, "localhost", "example.com"):
        for rtype in ("a", "aaaa"):
            call(
                "resolve_dnspython(%r, %r)" % (name, rtype),
                lambda n=name, t=rtype: netimps.resolve_dnspython(n, t),
            )
            call(
                "resolve_system(%r, %r)" % (name, rtype),
                lambda n=name, t=rtype: netimps.resolve_system(n, t),
            )
            call(
                "resolve_nslookup(%r, %r)" % (name, rtype),
                lambda n=name, t=rtype: netimps.resolve_nslookup(n, t),
            )
            call(
                "resolve(%r, %r)" % (name, rtype),
                lambda n=name, t=rtype: netimps.resolve(n, t),
            )

    print("\n-- multicast setup (platform option availability)")
    call(
        "multicast_socket('239.1.2.3', 0)",
        lambda: netimps.multicast_socket("239.1.2.3", 0),
    )
    call(
        "multicast_socket('ff02::1', 0)", lambda: netimps.multicast_socket("ff02::1", 0)
    )

# --------------------------------------------------------------------------
section("Socket option availability (the silent-gap checklist)")
# --------------------------------------------------------------------------
for opt in (
    "IP_MTU",
    "IP_MTU_DISCOVER",
    "IP_DONTFRAG",
    "IP_PKTINFO",
    "IPV6_RECVPKTINFO",
    "IPV6_PKTINFO",
    "SO_REUSEPORT",
    "IP_RECVERR",
    "TCP_MAXSEG",
    "IPV6_DONTFRAG",
    "IPV6_USE_MIN_MTU",
):
    value = getattr(socket, opt, None)
    print("   socket.%-20s %s" % (opt, value))
    record("sockopt:%s" % opt, value=value)

out_path = os.environ.get("PROBE_JSON", "probe.json")
with open(out_path, "w", encoding="utf-8") as handle:
    # Redact once, here, at the only point where the transcript leaves the
    # process. Doing it per-call-site is how `RESULTS["platform"]` -- assigned
    # directly rather than through record() -- kept its hostname and FQDN while
    # everything else was masked. One boundary, one guarantee.
    json.dump(redact(RESULTS), handle, indent=2, default=str)
print("\nwrote %s (%d probes)" % (out_path, len(RESULTS["probes"])))
