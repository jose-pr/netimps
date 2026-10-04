"""The public surface: exactly what ``netimps.__all__`` exports.

A name added, removed or renamed has to change this list in the same commit,
so the surface never moves by accident. The list is sorted the way ``sorted``
sorts it.
"""

import netimps

EXPECTED = [
    "AddressInUseError",
    "Backoff",
    "CMSG_LEN",
    "CMSG_SPACE",
    "DNSDecodeError",
    "Datagram",
    "FQDN",
    "FQDNLike",
    "Host",
    "HostLike",
    "INTERFACE_CACHE_TTL",
    "IPAddress",
    "IPAddressLike",
    "IPInterface",
    "IPInterfaceLike",
    "IPNetwork",
    "IPNetworkLike",
    "IPv4Address",
    "IPv4Interface",
    "IPv4Network",
    "IPv6Address",
    "IPv6Interface",
    "IPv6Network",
    "Interface",
    "InterfaceLike",
    "InterfaceQuery",
    "LINK_LOCAL_V4",
    "LINK_LOCAL_V6",
    "LOOPBACK_V4",
    "LOOPBACK_V6",
    "MACAddress",
    "MACAddressLike",
    "NetimpsError",
    "NetimpsValueError",
    "NoAnswerError",
    "PORT_RANGES",
    "PingResult",
    "PortsLike",
    "RESOLUTION_CACHE_TTL",
    "ResolutionError",
    "ResolutionTimeoutError",
    "Route",
    "SocketAddress",
    "SocketOption",
    "UDPEndpoint",
    "backoff_delays",
    "bind",
    "bind_error_hint",
    "clear_interface_cache",
    "clear_resolution_cache",
    "collapse",
    "count_hops",
    "disable_connreset",
    "discover_mtu",
    "get_default_port",
    "get_default_scheme",
    "get_free_port",
    "get_hostname",
    "get_interface",
    "get_interfaces",
    "get_pmtu",
    "get_route",
    "get_source_ip",
    "get_tcp_mss",
    "has_dns",
    "has_pktinfo",
    "has_recvmsg",
    "interface_enumerations",
    "is_broadcast",
    "is_link_scoped",
    "is_local_address",
    "is_local_host",
    "is_multicast",
    "is_socket_patched",
    "is_unicast",
    "is_valid",
    "is_wildcard",
    "iter_addresses",
    "iter_interfaces",
    "join_group",
    "join_host",
    "leave_group",
    "max_udp_payload",
    "multicast_socket",
    "parse",
    "patch_socket_module",
    "ping",
    "recvmsg",
    "register_port",
    "resolve",
    "resolve_dnspython",
    "resolve_doh",
    "resolve_nslookup",
    "resolve_system",
    "resolve_wire",
    "retry",
    "scan_hosts",
    "scan_ports",
    "sendmsg",
    "set_buffer_size",
    "split_host",
    "split_zone",
    "subtract",
    "tcp_check",
    "try_parse",
    "unmap",
    "wait_for_port",
]


def test_all_is_exactly_the_pinned_list():
    """An export that appeared or vanished without this list changing."""
    assert sorted(netimps.__all__) == EXPECTED


def test_every_export_exists_and_is_listed_once():
    """A name in ``__all__`` that the package does not define, or a duplicate."""
    assert len(set(netimps.__all__)) == len(netimps.__all__)
    missing = [name for name in netimps.__all__ if not hasattr(netimps, name)]
    assert missing == []


def test_importing_netimps_does_not_ask_for_the_host_name():
    """``platform.node()`` is a WMI query on Windows; a constant computed from
    it made every ``import netimps`` pay for it. Run in a fresh interpreter
    with the call booby-trapped, because this process imported netimps long
    ago."""
    import os
    import subprocess
    import sys

    code = (
        "import platform\n"
        "def trap():\n"
        "    raise RuntimeError('platform.node called at import')\n"
        "platform.node = trap\n"
        "import netimps\n"
        "print('imported')\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(path for path in sys.path if path)
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "imported"


# --- signatures ---------------------------------------------------------------

import inspect
import typing

# How many arguments each callable accepts positionally; every other option is
# keyword-only. A callable absent from this table accepts at most
# ``_DEFAULT_POSITIONAL``.
POSITIONAL = {
    "Backoff": 1,
    "FQDN": 0,
    "Host": 1,
    "Interface": 2,
    "MACAddress": 1,
    "PingResult": 2,
    "Route": 1,
    "UDPEndpoint": 1,
    "backoff_delays": 2,
    "count_hops": 1,
    "discover_mtu": 1,
    "get_free_port": 1,
    "get_interface": 1,
    "get_interfaces": 0,
    "get_pmtu": 2,
    "get_route": 1,
    "get_source_ip": 2,
    "get_tcp_mss": 2,
    "iter_addresses": 1,
    "join_group": 2,
    "leave_group": 2,
    "max_udp_payload": 1,
    "multicast_socket": 2,
    "patch_socket_module": 1,
    "ping": 1,
    "register_port": 2,
    "resolve": 2,
    "resolve_dnspython": 2,
    "resolve_doh": 2,
    "resolve_nslookup": 2,
    "resolve_system": 2,
    "resolve_wire": 2,
    "retry": 2,
    "scan_hosts": 2,
    "scan_ports": 2,
    "set_buffer_size": 1,
    "split_host": 1,
    "tcp_check": 2,
    "try_parse": 2,
    "wait_for_port": 2,
}
_DEFAULT_POSITIONAL = 3

# Shapes fixed by what they mirror: the standard library's ``recvmsg`` and
# ``sendmsg`` and the ``CMSG_*`` helpers, and two named tuples that are
# positional by nature.
EXEMPT = {"recvmsg", "sendmsg", "CMSG_LEN", "CMSG_SPACE", "Datagram", "SocketOption"}

# Parameters that may stay ``Any``: what they hold is not known to this package.
ANY_ALLOWED: "typing.Set[typing.Tuple[str, str]]" = set()


def _callables():
    for name in sorted(netimps.__all__):
        obj = getattr(netimps, name)
        if not (inspect.isfunction(obj) or inspect.isclass(obj)):
            continue
        if getattr(obj, "__module__", "").split(".")[0] != "netimps":
            continue
        try:
            sig = inspect.signature(obj)
        except (TypeError, ValueError):
            continue
        yield name, obj, sig


def test_options_are_keyword_only_past_the_counted_positionals():
    """A signature that still takes its options positionally: ``ping(dst, 3,
    2.0, None, ...)`` reads as nothing, and inserting a parameter later
    silently shifts every such call."""
    wrong = {}
    for name, _obj, sig in _callables():
        if name in EXEMPT:
            continue
        count = sum(
            1
            for p in sig.parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        )
        allowed = POSITIONAL.get(name, _DEFAULT_POSITIONAL)
        if count > allowed:
            wrong[name] = (count, allowed)
    assert wrong == {}, f"{len(wrong)} callables take too many positionals: {wrong}"


def test_every_public_annotation_resolves():
    """``typing.get_type_hints`` raising means a consumer introspecting the
    signature fails; a name used in a hint has to exist at run time."""
    failures = {}
    for name, obj, _sig in _callables():
        target = obj.__init__ if inspect.isclass(obj) else obj
        try:
            typing.get_type_hints(target)
        except Exception as exc:  # noqa: BLE001 - the message is the report
            failures[name] = repr(exc)
    assert failures == {}


def test_no_public_parameter_is_bare_any():
    """``Any`` on a parameter says "do anything with it" to the caller's type
    checker and checks nothing; a missing annotation is the same."""
    bare = []
    for name, obj, sig in _callables():
        if name in EXEMPT:
            continue
        target = obj.__init__ if inspect.isclass(obj) else obj
        try:
            hints = typing.get_type_hints(target)
        except Exception:  # noqa: BLE001 - reported by the test above
            continue
        for pname, param in sig.parameters.items():
            if pname.startswith("_") or (name, pname) in ANY_ALLOWED:
                continue
            if pname not in hints or hints[pname] is typing.Any:
                bare.append(f"{name}({pname})")
    assert bare == [], f"{len(bare)} parameters are bare Any or unannotated: {bare}"


# --- methods -------------------------------------------------------------------

# Positional arguments (``self`` excluded) of each public method that takes more
# than one. A method absent from this table takes at most one; every other
# option is keyword-only.
METHOD_POSITIONAL = {
    "FQDN.decode_at": 2,
    "FQDN.try_parse": 2,
    "Host.try_parse": 2,
    "MACAddress.hex": 2,
    "MACAddress.try_parse": 2,
    "UDPEndpoint.asend": 3,
    "UDPEndpoint.reply_socket": 2,
    "UDPEndpoint.send": 3,
}


def _public_methods():
    for cname in sorted(netimps.__all__):
        cls = getattr(netimps, cname)
        if not inspect.isclass(cls) or cls.__module__.split(".")[0] != "netimps":
            continue
        for mname, _member in inspect.getmembers(cls):
            if mname.startswith("_"):
                continue
            raw = inspect.getattr_static(cls, mname)
            func = raw.fget if isinstance(raw, property) else raw
            if isinstance(func, (staticmethod, classmethod)):
                func = func.__func__
            if not inspect.isfunction(func):
                continue
            params = list(inspect.signature(func).parameters.values())
            if not isinstance(raw, staticmethod):
                params = params[1:]  # self or cls
            yield cname, mname, params


def test_method_options_are_keyword_only_past_the_counted_positionals():
    """``recv(1500, False)`` and ``reply_socket(d, 0, True)`` read as nothing."""
    wrong = {}
    for cname, mname, params in _public_methods():
        if cname in EXEMPT:
            continue
        count = sum(
            1 for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        )
        allowed = METHOD_POSITIONAL.get("%s.%s" % (cname, mname), 1)
        if count > allowed:
            wrong["%s.%s" % (cname, mname)] = (count, allowed)
    assert wrong == {}, f"methods take too many positionals: {wrong}"


def test_no_method_carries_a_test_hook_in_its_signature():
    """A parameter named ``_sleep`` or ``_random`` is a seam, not an option."""
    hooks = [
        "%s.%s(%s)" % (cname, mname, p.name)
        for cname, mname, params in _public_methods()
        for p in params
        if p.name.startswith("_")
    ]
    for name, obj, sig in _callables():
        hooks += ["%s(%s)" % (name, p) for p in sig.parameters if p.startswith("_")]
    assert hooks == []


def test_udp_endpoint_names_its_destination_dst():
    """Every function that takes a destination calls it ``dst``."""
    for method in ("send", "asend"):
        names = list(inspect.signature(getattr(netimps.UDPEndpoint, method)).parameters)
        assert names[:4] == ["self", "data", "dst", "port"], (method, names)
