"""Capture real platform behaviour that unit tests cannot assert.

Throwaway CI instrumentation: it answers platform questions ("what does macOS
ping6 actually print?") with captured bytes rather than with a guess. Prints a
human-readable transcript and writes the same
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
import struct
import subprocess
import sys
import time

_PARSER = argparse.ArgumentParser(description="Capture real platform behaviour.")
_PARSER.add_argument(
    "--raw",
    action="store_true",
    help="do not redact MACs and addresses (local diagnosis only)",
)
_PARSER.add_argument(
    "--device-only",
    action="store_true",
    help="run only the device-binding probe (standard library only) and exit",
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

    The transcript is uploaded as a CI artifact and may be pasted into an issue, and
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


def finish():
    """Write the transcript as JSON, redacted once at the boundary."""
    out_path = os.environ.get("PROBE_JSON", "probe.json")
    with open(out_path, "w", encoding="utf-8") as handle:
        # Redact once, here, at the only point where the transcript leaves the
        # process. Doing it per-call-site is how `RESULTS["platform"]` -- assigned
        # directly rather than through record() -- kept its hostname and FQDN
        # while everything else was masked. One boundary, one guarantee.
        json.dump(redact(RESULTS), handle, indent=2, default=str)
    print("\nwrote %s (%d probes)" % (out_path, len(RESULTS["probes"])))


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
section("Binding a socket to a device")
# --------------------------------------------------------------------------
# Question: which option, if any, makes a UDP socket receive only what arrives
# on one interface, as an ordinary user? Each candidate is tried on every
# platform with its own number, because the same number means another option
# elsewhere and an `ok` there proves nothing by itself: what counts is whether
# the option *restricts what is received*. A wildcard socket is bound, the
# option names a device, and a datagram is sent to it over loopback.
#
#   control        no option: loopback delivery works at all
#   loopback       the device named is loopback: the datagram must arrive
#   other          the device named is another interface: a datagram that
#                  entered through loopback must NOT arrive
#
# An option restricts receive when `loopback` arrives and `other` does not.
# The reverse case (a loopback-bound socket and a datagram that entered through
# a real NIC) needs a peer on the network and is left to a real-peer harness.
#
# The Windows `*_UNICAST_IF` options are documented as steering what is *sent*;
# they are here to see whether they also restrict what is received.
#
# Standard library only, from a checkout:
#     python3 .github/probe/capture.py --device-only

#: (label, family, level, option number, spellings of the device). A spelling is
#: "name" (the interface name as bytes), "host" (the index as a native int) or
#: "network" (the index packed in network byte order).
_DEVICE_OPTIONS = [
    ("SO_BINDTODEVICE", 4, socket.SOL_SOCKET, 25, ("name",)),
    ("SO_BINDTODEVICE", 6, socket.SOL_SOCKET, 25, ("name",)),
    ("IP_BOUND_IF", 4, socket.IPPROTO_IP, 25, ("host",)),
    ("IPV6_BOUND_IF", 6, socket.IPPROTO_IPV6, 125, ("host",)),
    ("IP_UNICAST_IF", 4, socket.IPPROTO_IP, 31, ("network", "host")),
    ("IPV6_UNICAST_IF", 6, socket.IPPROTO_IPV6, 31, ("host", "network")),
]


def _device_value(spelling, index, name):
    if spelling == "name":
        return name.encode()
    if spelling == "host":
        return index
    return struct.pack("!I", index)


def _device_receive(version, level, option, value):
    """Bind a wildcard socket with the option set (``None``: no option), send it
    one datagram over loopback, and return (error text or None, arrived or None)."""
    family = socket.AF_INET if version == 4 else socket.AF_INET6
    loopback = "127.0.0.1" if version == 4 else "::1"
    receiver = sender = None
    try:
        receiver = socket.socket(family, socket.SOCK_DGRAM)
        if version == 6:
            receiver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        if value is not None:
            try:
                receiver.setsockopt(level, option, value)
            except OSError as exc:
                return ("errno %s %s" % (exc.errno, exc.strerror), None)
        receiver.bind(("" if version == 4 else "::", 0))
        receiver.settimeout(0.5)
        port = receiver.getsockname()[1]
        sender = socket.socket(family, socket.SOCK_DGRAM)
        sender.sendto(b"device-probe", (loopback, port))
        try:
            data, _ = receiver.recvfrom(64)
            return (None, data == b"device-probe")
        except socket.timeout:
            return (None, False)
    except OSError as exc:
        return ("errno %s %s" % (exc.errno, exc.strerror), None)
    finally:
        for sock in (receiver, sender):
            if sock is not None:
                sock.close()


def _device_verdict(control, on_loop, on_other):
    if on_loop[0] is not None:
        return "setsockopt refused (%s)" % (on_loop[0],)
    if control[1] is not True:
        return "control did not arrive: no verdict"
    if on_loop[1] and on_other[1] is False:
        return "RESTRICTS RECEIVE"
    if on_loop[1] and on_other[1]:
        return "accepted, does not restrict receive"
    if on_other[0] is not None:
        return "other device refused (%s)" % (on_other[0],)
    return "loopback-bound socket received nothing: no verdict"


def probe_device_binding():
    """Print one line per (option, family, spelling) and return the verdicts."""
    names = dict(socket.if_nameindex())
    loop = [i for i, n in names.items() if n.startswith("lo") or "oopback" in n]
    loop_index = loop[0] if loop else 1
    others = sorted(i for i in names if i != loop_index)
    ids = "%s/%s" % (os.getuid(), os.geteuid()) if hasattr(os, "getuid") else "n/a"
    print("   uid/euid: %s" % ids)
    print(
        "   loopback device: %s (index %s); other devices: %s"
        % (
            names.get(loop_index),
            loop_index,
            ", ".join("%s=%s" % (i, names[i]) for i in others) or "none",
        )
    )
    record("device-host", uid=ids, loopback=names.get(loop_index), others=names)
    verdicts = []
    for label, version, level, option, spellings in _DEVICE_OPTIONS:
        for spelling in spellings:
            control = _device_receive(version, level, option, None)
            value = _device_value(spelling, loop_index, names.get(loop_index, "lo"))
            on_loop = _device_receive(version, level, option, value)
            on_other, other_name = ("no other device", None), None
            for index in others:
                value = _device_value(spelling, index, names[index])
                on_other, other_name = (
                    _device_receive(version, level, option, value),
                    names[index],
                )
                if on_other[0] is None:
                    break
            verdict = _device_verdict(control, on_loop, on_other)
            print(
                "   %-16s v%s %-7s control=%s loopback=%s other(%s)=%s => %s"
                % (
                    label,
                    version,
                    spelling,
                    control[1] if control[0] is None else control[0],
                    on_loop[1] if on_loop[0] is None else on_loop[0],
                    other_name,
                    on_other[1] if on_other[0] is None else on_other[0],
                    verdict,
                )
            )
            record(
                "device:%s:v%s:%s" % (label, version, spelling),
                control=control,
                loopback=on_loop,
                other=on_other,
                other_device=other_name,
                verdict=verdict,
            )
            verdicts.append((label, version, spelling, verdict))
    return verdicts


try:
    probe_device_binding()
except BaseException as exc:  # noqa: BLE001 - a probe must never abort
    print("   device probe failed: %r" % (exc,))
    record("device-probe", error=repr(exc))
if ARGS.device_only:
    finish()
    sys.exit(0)

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
    call("ping('127.0.0.1').rtt", lambda: netimps.ping("127.0.0.1").rtt)
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
    call("get_interface('127.0.0.1')", lambda: netimps.get_interface("127.0.0.1"))

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
section("pktinfo: constants, cmsg payloads, dual-stack and src pinning")
# --------------------------------------------------------------------------
# Captures *bytes*, not conclusions. The v4 pktinfo cmsg has a different field
# order and length on Windows than on Linux, macOS has no `IP_PKTINFO` at all
# and needs `IP_RECVDSTADDR`/`IP_RECVIF` instead, and Windows sends a zero
# source address literally where Linux reads it as "kernel chooses". Every one
# of those was a surprise, so the raw hex is recorded and left uninterpreted --
# a later reader can re-parse it without re-running the matrix.

print("\n--- constants")
for _opt in (
    "IP_PKTINFO",
    "IP_RECVDSTADDR",
    "IP_RECVIF",
    "IP_UNICAST_IF",
    "IPV6_PKTINFO",
    "IPV6_RECVPKTINFO",
    "IPV6_UNICAST_IF",
    "IPV6_V6ONLY",
    "MSG_CTRUNC",
    "MSG_TRUNC",
):
    _value = getattr(socket, _opt, None)
    print("   socket.%-20s %s" % (_opt, _value))
    record("pktinfo:const:%s" % _opt, value=_value)

for _helper in ("CMSG_LEN", "CMSG_SPACE", "recvmsg", "sendmsg"):
    _present = hasattr(socket, _helper) or hasattr(socket.socket, _helper)
    print("   stdlib %-20s %s" % (_helper, "present" if _present else "ABSENT"))
    record("pktinfo:stdlib:%s" % _helper, value=_present)

if netimps is not None:
    print("\n--- netimps messaging layer")
    call("netimps.has_recvmsg()", lambda: netimps.has_recvmsg())
    # False on POSIX is the correct answer: the patch is strictly additive, so a
    # platform that already has these must come back untouched.
    call("netimps.is_socket_patched()", lambda: netimps.is_socket_patched())
    call("netimps.CMSG_SPACE(8)", lambda: netimps.CMSG_SPACE(8))
    call("netimps.CMSG_LEN(8)", lambda: netimps.CMSG_LEN(8))


def pktinfo_capture(label, family, bind_host, send_to, setopts, v6only=None):
    """Enable *setopts*, receive one datagram, record every cmsg verbatim."""
    print("\n--- %s" % label)
    info = {"family": int(family), "bind": bind_host, "sent_to": send_to}
    server = client = None
    try:
        server = socket.socket(family, socket.SOCK_DGRAM)
        if v6only is not None and hasattr(socket, "IPV6_V6ONLY"):
            try:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(v6only))
                info["v6only"] = int(v6only)
            except OSError as exc:
                info["v6only_error"] = repr(exc)
        server.bind((bind_host, 0))
        port = server.getsockname()[1]
        applied = []
        for level, option, name in setopts:
            if option is None:
                applied.append("%s=absent" % name)
                continue
            try:
                server.setsockopt(level, option, 1)
                applied.append("%s=ok" % name)
            except OSError as exc:
                applied.append("%s=%r" % (name, exc))
        info["setsockopt"] = applied
        print("   setsockopt: %s" % ", ".join(applied))

        client = socket.socket(
            socket.AF_INET if "." in send_to else family, socket.SOCK_DGRAM
        )
        client.sendto(b"probe", (send_to, port))
        server.settimeout(5.0)
        data, ancdata, flags, sender = netimps.recvmsg(
            server, 2048, netimps.CMSG_SPACE(256)
        )
        info["data"] = data.decode("ascii", "replace")
        info["sender"] = repr(sender)
        info["msg_flags"] = flags
        info["cmsgs"] = [
            {"level": lvl, "type": ctype, "len": len(cdata), "hex": cdata.hex()}
            for lvl, ctype, cdata in ancdata
        ]
        print(
            "   sender=%s flags=%#x cmsgs=%d"
            % (info["sender"], flags, len(info["cmsgs"]))
        )
        for entry in info["cmsgs"]:
            print(
                "   cmsg level=%(level)s type=%(type)s len=%(len)s hex=%(hex)s" % entry
            )
        if not info["cmsgs"]:
            print("   [no cmsg -- the option did not deliver on this platform]")
    except BaseException as exc:  # noqa: BLE001 - a probe must never abort
        info["error"] = repr(exc)
        print("   ! %r" % (exc,))
    finally:
        for sock in (server, client):
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass
    record("pktinfo:%s" % label, **info)
    return info


if netimps is not None and netimps.has_recvmsg():
    _ip_pktinfo = getattr(socket, "IP_PKTINFO", None)
    _ip_recvdstaddr = getattr(socket, "IP_RECVDSTADDR", None)
    _ip_recvif = getattr(socket, "IP_RECVIF", None)
    _v6_recv = getattr(socket, "IPV6_RECVPKTINFO", None) or getattr(
        socket, "IPV6_PKTINFO", None
    )

    # (a) macOS has no IP_PKTINFO. Set every v4 option this platform exports and
    # let the cmsg list say which of them actually delivered.
    pktinfo_capture(
        "v4-loopback",
        socket.AF_INET,
        "127.0.0.1",
        "127.0.0.1",
        [
            (socket.IPPROTO_IP, _ip_pktinfo, "IP_PKTINFO"),
            (socket.IPPROTO_IP, _ip_recvdstaddr, "IP_RECVDSTADDR"),
            (socket.IPPROTO_IP, _ip_recvif, "IP_RECVIF"),
        ],
    )

    # A virtual IP: does the arrival address report the VIP rather than the
    # bound wildcard? This is the whole reason the feature exists.
    pktinfo_capture(
        "v4-wildcard-to-127.0.0.2",
        socket.AF_INET,
        "0.0.0.0",
        "127.0.0.2",
        [
            (socket.IPPROTO_IP, _ip_pktinfo, "IP_PKTINFO"),
            (socket.IPPROTO_IP, _ip_recvdstaddr, "IP_RECVDSTADDR"),
            (socket.IPPROTO_IP, _ip_recvif, "IP_RECVIF"),
        ],
    )

    pktinfo_capture(
        "v6-loopback",
        socket.AF_INET6,
        "::1",
        "::1",
        [(socket.IPPROTO_IPV6, _v6_recv, "IPV6_RECV/PKTINFO")],
    )

    # (b) Does a v6-ONLY socket accept IP_PKTINFO? Windows accepted it on a
    # dual-stack socket; whether it does with V6ONLY=1 decides whether the
    # option can be set unconditionally or must be conditional.
    pktinfo_capture(
        "v6only-accepts-IP_PKTINFO",
        socket.AF_INET6,
        "::1",
        "::1",
        [
            (socket.IPPROTO_IPV6, _v6_recv, "IPV6_RECV/PKTINFO"),
            (socket.IPPROTO_IP, _ip_pktinfo, "IP_PKTINFO"),
        ],
        v6only=True,
    )

    # (c) Dual-stack: a v4 arrival on an AF_INET6 socket. Linux reports the
    # v4-mapped form from the v6 option alone; Windows was measured delivering
    # NO cmsg unless IP_PKTINFO is also set, and then the *plain* v4 address.
    pktinfo_capture(
        "dualstack-v4-arrival",
        socket.AF_INET6,
        "::",
        "127.0.0.1",
        [
            (socket.IPPROTO_IPV6, _v6_recv, "IPV6_RECV/PKTINFO"),
            (socket.IPPROTO_IP, _ip_pktinfo, "IP_PKTINFO"),
        ],
        v6only=False,
    )


def pin_capture(label, family, host, src):
    """Pin a source with UDPEndpoint.send(src=) and report what the peer saw.

    The endpoint binds the **wildcard**, deliberately. Binding it to *host*
    first was the original mistake here: the bind already fixes the source, so
    every pin "worked" and reported 127.0.0.1 whatever it was asked for --
    a probe that cannot fail measures nothing.
    """
    print("\n--- %s" % label)
    info = {"family": int(family), "src": repr(src)}
    wildcard = "::" if family == socket.AF_INET6 else "0.0.0.0"
    endpoint = peer = None
    try:
        peer = socket.socket(family, socket.SOCK_DGRAM)
        peer.bind((host, 0))
        peer.settimeout(5.0)
        endpoint = netimps.UDPEndpoint(netimps.bind(wildcard, 0, family=family))
        info["bound"] = wildcard
        info["has_src_pinning"] = endpoint.has_src_pinning
        info["has_pktinfo"] = endpoint.has_pktinfo
        sent = endpoint.send(b"pinned", host, peer.getsockname()[1], src=src)
        info["sent"] = sent
        _data, observed = peer.recvfrom(100)
        info["observed_source"] = repr(observed)
        print(
            "   pinning=%s sent=%s observed_source=%s"
            % (info["has_src_pinning"], sent, info["observed_source"])
        )
    except BaseException as exc:  # noqa: BLE001
        info["error"] = repr(exc)
        print("   ! %r" % (exc,))
    finally:
        for sock in (endpoint, peer):
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass
    record("pktinfo:%s" % label, **info)
    return info


if netimps is not None:
    # (d) 127.0.0.2 succeeded locally and 127.0.0.3 returned WSAEINVAL, with no
    # explanation and both bindable. Run both on every platform: if the
    # asymmetry is real it needs documenting, and if it was local noise that
    # matters just as much.
    pin_capture("pin-v4-127.0.0.1", socket.AF_INET, "127.0.0.1", "127.0.0.1")
    pin_capture("pin-v4-127.0.0.2", socket.AF_INET, "127.0.0.1", "127.0.0.2")
    pin_capture("pin-v4-127.0.0.3", socket.AF_INET, "127.0.0.1", "127.0.0.3")
    pin_capture("pin-v6-::1", socket.AF_INET6, "::1", "::1")

    # Index-only pinning. On Windows a zero address is sent literally, so this
    # must raise rather than send from 0.0.0.0; elsewhere the kernel chooses.
    # Index 1 is loopback on every platform measured so far.
    pin_capture("pin-v4-index-only", socket.AF_INET, "127.0.0.1", 1)
    pin_capture("pin-v6-index-only", socket.AF_INET6, "::1", 1)

    # IP_UNICAST_IF is the candidate replacement for an index-only pin on
    # Windows. The byte order is **not** the same for the two families, which is
    # the trap: MSDN specifies the index in *network* order for IP_UNICAST_IF
    # and *host* order for IPV6_UNICAST_IF. Both spellings are tried for both
    # families so the transcript shows which one the platform accepted rather
    # than leaving a WSAEINVAL to be misread as "unsupported".
    print("\n--- IP_UNICAST_IF / IPV6_UNICAST_IF")
    for _label, _family, _level, _name, _default in (
        ("v4", socket.AF_INET, socket.IPPROTO_IP, "IP_UNICAST_IF", 31),
        ("v6", socket.AF_INET6, socket.IPPROTO_IPV6, "IPV6_UNICAST_IF", 31),
    ):
        _option = getattr(socket, _name, _default)
        for _order, _payload in (
            ("network", struct.pack("!I", 1)),
            ("host", struct.pack("=I", 1)),
            ("int", 1),
        ):
            _sock = None
            _key = "pktinfo:unicast_if:%s:%s" % (_label, _order)
            try:
                _sock = socket.socket(_family, socket.SOCK_DGRAM)
                _sock.setsockopt(_level, _option, _payload)
                _readback = _sock.getsockopt(_level, _option)
                print(
                    "   %s %s (%s order) -> ok, getsockopt=%r"
                    % (_label, _name, _order, _readback)
                )
                record(_key, value=repr(_readback))
            except BaseException as exc:  # noqa: BLE001
                print("   %s %s (%s order) ! %r" % (_label, _name, _order, exc))
                record(_key, error=repr(exc))
            finally:
                try:
                    if _sock is not None:
                        _sock.close()
                except OSError:
                    pass


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

finish()
