"""Which interfaces an endpoint serves, and whether a datagram is one of theirs (internal)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Tuple

from .._exceptions import NetimpsValueError
from .._ifaddrs import Interface
from ._datagram import Datagram

if TYPE_CHECKING:
    import socket as _socket


class _AdmitMixin:
    """``interfaces``, ``admits`` and ``repr`` for :class:`UDPEndpoint`."""

    __slots__ = ()

    socket: "_socket.socket"
    has_pktinfo: bool
    has_src_pinning: bool
    interfaces: "Tuple[Interface, ...]"

    @staticmethod
    def _served(interfaces: "Iterable[Interface]") -> "Tuple[Interface, ...]":
        """The interfaces as a tuple, each an :class:`Interface` with an index."""
        try:
            found = tuple(interfaces)
        except TypeError:
            raise TypeError(
                "interfaces is a sequence of Interface, not %s %r"
                % (type(interfaces).__name__, interfaces)
            ) from None
        for item in found:
            if not isinstance(item, Interface):
                raise TypeError(
                    "interfaces holds Interface objects, not %s %r"
                    % (type(item).__name__, item)
                )
            if not item.index:
                raise NetimpsValueError(
                    "interface %r has no index, so no datagram can arrive on it"
                    % (item.name,)
                )
        return found

    def admits(self, datagram: "Datagram") -> bool:
        """Whether *datagram* arrived on an interface this endpoint serves.

        True when :attr:`interfaces` is empty. Otherwise true when the
        datagram's ``interface_index`` is the index of one of them; a datagram
        with no arrival interface (``interface_index`` 0) is not admitted.
        """
        if not self.interfaces:
            return True
        index = datagram.interface_index
        return bool(index) and any(index == item.index for item in self.interfaces)

    def __repr__(self) -> str:
        try:
            bound = self.socket.getsockname()
        except OSError:  # unbound, or closed
            bound = None
        served = (
            ", interfaces=%r" % ([i.name for i in self.interfaces],)
            if self.interfaces
            else ""
        )
        return "UDPEndpoint(bound=%r, pktinfo=%r, src_pinning=%r%s)" % (
            bound,
            self.has_pktinfo,
            self.has_src_pinning,
            served,
        )
