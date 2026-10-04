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
    "PORT_RANGES",
    "PingResult",
    "PortsLike",
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
    "get_ip",
    "get_pmtu",
    "get_route",
    "get_source_ip",
    "get_tcp_mss",
    "has_pktinfo",
    "has_recvmsg",
    "interface_enumerations",
    "is_broadcast",
    "is_link_scoped",
    "is_local_address",
    "is_multicast",
    "is_socket_patched",
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
