"""Surface contract: the public API export list.

This test pins what names the package exports after each phase of the
standard-alignment plan. It starts failing when Phase 2 renames take effect
(names shift but get_hostname is not yet callable), and passes again after
Phase 3 (where get_hostname() is implemented).

The list includes:
- Today's __all__ with phase-2 names entries applied
- Plus the four new exported aliases: InterfaceLike, InterfaceQuery, PortsLike,
  SocketAddress
- Plus get_hostname (new function, replaces get_hostname()())
- The four exception names from sub-plan 01 (already in __all__)
"""

import netimps


def test_public_surface():
    """The exported names match the post-phase-2 target surface."""
    expected = sorted(
        [
            # Types: the v4/v6 unions you annotate with, plus the stdlib concretes.
            "IPAddress",
            "IPInterface",
            "IPNetwork",
            "IPv4Address",
            "IPv4Interface",
            "IPv4Network",
            "IPv6Address",
            "IPv6Interface",
            "IPv6Network",
            "MACAddress",
            "IPAddressLike",
            "IPInterfaceLike",
            "IPNetworkLike",
            # Phase 2: HostLike -> HostLike
            "HostLike",
            # Phase 2: MACAddressLike -> MACAddressLike
            "MACAddressLike",
            # Parsing.
            "parse",
            "try_parse",
            "is_valid",
            "get_ip",
            "Host",
            "is_link_scoped",
            # Phase 2: LINK_LOCAL_V4 -> LINK_LOCAL_V4
            "LINK_LOCAL_V4",
            "LOOPBACK_V4",
            "LOOPBACK_V6",
            "LINK_LOCAL_V6",
            "collapse",
            "subtract",
            # Phase 2: split_host -> split_host
            "split_host",
            "join_host",
            "unmap",
            "is_wildcard",
            "get_default_port",
            "get_default_scheme",
            "register_port",
            "resolve",
            "resolve_dnspython",
            "resolve_system",
            "resolve_nslookup",
            "resolve_wire",
            "resolve_doh",
            "ResolutionError",
            "ResolutionTimeoutError",
            "DNSDecodeError",
            "NetimpsError",
            "NetimpsValueError",
            "ping",
            "PingResult",
            "Interface",
            "get_interfaces",
            "clear_interface_cache",
            "interface_enumerations",
            "INTERFACE_CACHE_TTL",
            "is_broadcast",
            "iter_addresses",
            # Socket / route helpers.
            "get_source_ip",
            "get_free_port",
            "tcp_check",
            "wait_for_port",
            "get_route",
            "bind",
            "AddressInUseError",
            "SocketOption",
            "disable_connreset",
            "set_buffer_size",
            "bind_error_hint",
            # Phase 2: get_interface -> get_interface
            "get_interface",
            # Phase 2: iter_interfaces -> iter_interfaces
            "iter_interfaces",
            "is_local_address",
            # Phase 2: UDPEndpoint -> UDPEndpoint
            "UDPEndpoint",
            # Phase 2: has_pktinfo -> has_pktinfo
            "has_pktinfo",
            "Datagram",
            # Phase 2: FQDN -> FQDN, FQDNLike -> FQDNLike
            "FQDN",
            "FQDNLike",
            # Ancillary-data messaging, available on every platform (Windows included).
            "recvmsg",
            "sendmsg",
            "CMSG_LEN",
            "CMSG_SPACE",
            # Phase 2: has_recvmsg -> has_recvmsg
            "has_recvmsg",
            "patch_socket_module",
            # Phase 2: is_socket_patched -> is_socket_patched
            "is_socket_patched",
            "retry",
            "Backoff",
            "backoff_delays",
            # Scanning.
            "scan_ports",
            "scan_hosts",
            "PORT_RANGES",
            # Multicast.
            "multicast_socket",
            "join_group",
            "leave_group",
            "is_multicast",
            "Route",
            # Phase 2: count_hops -> count_hops
            "count_hops",
            "get_pmtu",
            "discover_mtu",
            "max_udp_payload",
            "get_tcp_mss",
            # Phase 2: get_hostname()() -> get_hostname; phase 3 adds it
            "get_hostname",
            # Phase 1: New exported aliases
            "InterfaceLike",
            "InterfaceQuery",
            "PortsLike",
            "SocketAddress",
        ]
    )
    actual = sorted(netimps.__all__)
    assert actual == expected, (
        f"Surface mismatch.\nExpected:\n{expected}\n\nActual:\n{actual}\n\n"
        f"Missing: {set(expected) - set(actual)}\n"
        f"Extra: {set(actual) - set(expected)}"
    )
