"""``netimps addr``: what an address, network, MAC or name is."""

from __future__ import annotations

import typing as _ty

from netimps import (
    Host,
    IPv4Interface,
    IPv4Network,
    IPv6Interface,
    IPv6Network,
    MACAddress,
    NetimpsValueError,
    classify,
    is_link_scoped,
)

from ._common import ERROR, FOUND, Command, address_text, error, guarded


class Addr(Command):
    """Inspect an address, a hostname or a MAC."""

    _parsername_ = "addr"
    _parseraliases_ = ["parse"]

    value: str
    "Address, hostname, network or MAC to inspect"
    ("value",)

    @guarded
    def __call__(self) -> int:
        found = self.read()
        if found is None:
            error(
                "error: %r is not an address, network, MAC or resolvable name"
                % self.value
            )
            return ERROR
        if isinstance(found, MACAddress):
            self.emit(*self.mac(found))
        elif isinstance(found, (IPv4Network, IPv6Network)):
            self.emit(*self.network(found))
        elif isinstance(found, (IPv4Interface, IPv6Interface)):
            # An address with a prefix is shown as the network it sits in.
            self.emit(*self.network(found.network))
        else:
            self.emit(*self.address(found))
        return FOUND

    def read(self) -> _ty.Any:
        try:
            return classify(self.value)
        except NetimpsValueError:
            # Not a literal: a name, which only a resolver can read.
            return Host(self.value).ip()

    def mac(self, mac: MACAddress) -> "_ty.Tuple[_ty.Any, str]":
        payload = {
            "kind": "mac",
            "value": str(mac),
            "oui": mac.oui.hex(":"),
            "is_multicast": mac.is_multicast,
            "is_local": mac.is_local,
        }
        plain = [
            "mac          %s" % mac,
            "oui          %s" % mac.oui.hex(":"),
            "multicast    %s" % mac.is_multicast,
            "administered %s" % ("locally" if mac.is_local else "universally"),
        ]
        return payload, "\n".join(plain)

    def network(self, network: _ty.Any) -> "_ty.Tuple[_ty.Any, str]":
        payload = {
            "kind": "network",
            "value": str(network),
            "network_address": str(network.network_address),
            "netmask": str(network.netmask),
            "num_addresses": network.num_addresses,
            "version": network.version,
        }
        plain = [
            "network   %s" % network,
            "netmask   %s" % network.netmask,
            "addresses %d" % network.num_addresses,
        ]
        return payload, "\n".join(plain)

    def address(self, address: _ty.Any) -> "_ty.Tuple[_ty.Any, str]":
        payload = {
            "kind": "address",
            "value": address_text(address),
            "version": address.version,
            "is_private": address.is_private,
            "is_global": address.is_global,
            "is_loopback": address.is_loopback,
            "is_multicast": address.is_multicast,
            "is_link_scoped": is_link_scoped(address),
            "reverse_pointer": address.reverse_pointer,
        }
        plain = [
            "address     %s (IPv%d)" % (address_text(address), address.version),
            "private     %s" % address.is_private,
            "global      %s" % address.is_global,
            "loopback    %s" % address.is_loopback,
            "multicast   %s" % address.is_multicast,
            "link-scoped %s" % is_link_scoped(address),
        ]
        return payload, "\n".join(plain)
