"""Choosing the socket a reply leaves from (internal)."""

from __future__ import annotations

import socket as _socket
from typing import Iterable, Optional, Union

from .._ifaddrs import Interface
from .._ip import IPAddress, IPv4Address, IPv6Address
from .._parse import parse, try_parse
from ._datagram import Datagram


class _ReplyMixin:
    """``reply_socket`` and the decisions behind it, for :class:`UDPEndpoint`."""

    __slots__ = ()

    socket: "_socket.socket"

    def _reply_family(self, datagram: "Datagram") -> int:
        """The address family a reply to *datagram* must actually use.

        The **sender's** family, not the listener's. A dual-stack ``AF_INET6``
        listener sees a v4 client as ``::ffff:a.b.c.d``; a reply socket in the
        listener's family cannot reach it, because the socket comes up with
        ``IPV6_V6ONLY=1`` on Windows and ``sendto`` to a mapped address is then
        refused outright (``WinError 10049``). Deciding from the sender means
        the answer is the same with or without pktinfo; a decision taken from
        the arrival address would leave the no-pktinfo path silently never
        replying.

        Falls back to the socket's own family when the sender cannot be parsed,
        the only thing left to guess with.
        """
        from .._ip import unmap

        sender = datagram.sender
        host = sender[0] if isinstance(sender, tuple) and sender else None
        if isinstance(host, str):
            parsed = try_parse(host.split("%")[0], IPAddress)
            if parsed is not None:
                return (
                    _socket.AF_INET if unmap(parsed).version == 4 else _socket.AF_INET6
                )
        return self.socket.family

    @staticmethod
    def _is_repliable(local: "IPAddress", interface: "Optional[Interface]") -> bool:
        """Whether *local* is an address a reply socket may actually bind to.

        Classified rather than discovered by a failed bind, because **the
        platforms disagree about which addresses are bindable**. Measured: Linux
        binds ``255.255.255.255`` and ``239.1.2.3`` without complaint while
        Windows refuses both. So "try it and fall back on OSError" silently
        produces a socket bound to the broadcast address on Linux -- and a reply
        sent *from* ``255.255.255.255`` is one most clients discard, which is
        exactly the failure this method exists to prevent.

        Excluded: the unspecified address (nothing to answer from), multicast,
        and broadcast -- both the limited form and the **subnet** form, which
        needs the arrival interface's prefixes and is what
        :func:`netimps.is_broadcast` is for. Passing ``interface`` keeps that
        check off the enumerating path.
        """
        from .._ifaddrs import is_unicast

        return is_unicast(local, interface, cache=True)

    def reply_socket(
        self,
        datagram: "Datagram",
        port: "Union[int, Iterable[int]]" = 0,
        *,
        connreset: bool = False,
    ) -> "_socket.socket":
        """A new socket bound so replies leave from the address the client used.

        The point of pktinfo, in one call. A wildcard-bound server that answers
        from a fresh socket sends from whichever address the routing table
        prefers, which is not necessarily the one the client addressed -- and a
        client that checks (DHCP and TFTP both do) drops the reply::

            packet = endpoint.recv()
            with endpoint.reply_socket(packet) as reply:
                reply.sendto(answer, packet.reply_address)

        Falls back deliberately rather than failing: the returned socket is bound
        to the first of these that works -- the arrival address, then this
        endpoint's own bound address, then the wildcard. A socket that answers
        from the wrong address still answers.

        **A taken port is not an unusable address, and the two failures move in
        different directions.** An address that cannot be bound at all (a
        broadcast or multicast destination, a link-local one whose scope is
        wrong) advances to the next *address*; a port that is merely held
        advances to the next *port* on the same address. Conflating them is a
        silent correctness bug: if every ``OSError`` advanced the address, an
        explicit ``port=`` already taken on the arrival address would fall
        through to the endpoint's own address and then the wildcard **with the
        same port** -- and where that later bind succeeded, the reply would
        leave from an address the client never addressed, the one failure this
        method exists to prevent. So when the ports run out on an address, this
        raises :class:`netimps.AddressInUseError` rather than answering from
        somewhere else.

        Three things make this worth a method, each established by measurement:

        - **A v4 arrival on a dual-stack listener is ``::ffff:a.b.c.d``**, and
          binding that needs an ``AF_INET6`` socket with ``IPV6_V6ONLY`` off --
          which Windows does not default to. So a mapped address is unmapped and
          answered from a plain ``AF_INET`` socket instead.
        - **A broadcast, multicast or unspecified destination must not be
          answered from.** These are *classified* and skipped, not discovered by
          a failed bind, because the platforms disagree about which are bindable:
          measured, Linux binds ``255.255.255.255`` and ``239.1.2.3`` happily
          while Windows refuses both. Relying on the refusal would mean replying
          *from* the broadcast address on Linux, which most clients discard. The
          subnet-broadcast case needs the arrival interface's prefixes, which is
          what :func:`netimps.is_broadcast` supplies.
        - **An IPv6 link-local destination needs a scope id**, taken from
          ``datagram.interface_index``, or the bind fails with "invalid
          argument".

        ``connreset=False``, as :func:`netimps.bind` does for a datagram socket:
        a reply socket is a server's, and a server loop should not die because an
        earlier answer drew an ICMP port-unreachable from a client that had gone
        away.
        The non-hijackable bind options apply as everywhere else.

        :param datagram: a :class:`Datagram` from :meth:`recv`. Its
            ``destination`` is what this binds to; with ``None`` -- no pktinfo
            -- it goes straight to the fallbacks.
        :param port: local port for the reply socket; ``0`` lets the OS choose,
            which is what a per-transaction socket wants. Also accepts **any
            iterable of ports**, tried in the order given, for a server that
            pins transfer ports to a range a firewall can allow (``tftp-hpa
            -R``, ``dnsmasq --tftp-port-range``). The iterable is materialised
            once and reused for each address candidate, so a generator is safe
            -- but it must be finite. Empty raises :class:`ValueError`.
        :param connreset: passed to :func:`netimps.bind`; see above.
        :raises AddressInUseError: every port was held on an otherwise bindable
            address. Deliberately *not* a fallback to a different address.
        """
        from .._ip import unmap

        # **The sender's real family decides the reply socket's**, not the
        # listener's. A dual-stack `AF_INET6` listener sees a v4 client as
        # `::ffff:a.b.c.d`, and a reply socket in the listener's family cannot
        # reach it: measured on Windows 11 ARM64, the `AF_INET6` socket comes up
        # with `IPV6_V6ONLY=1` (the platform default, which `bind()` does not
        # clear) and `sendto` to a mapped address fails with `WinError 10049`,
        # "address not valid in its context". The transfer then silently never
        # starts. That happened whenever there was no `destination` to go on
        # -- `pktinfo=False`, or a platform that reported none -- because both
        # fallbacks used the listener's family.
        family = self._reply_family(datagram)
        candidates: "list" = []

        local = datagram.destination
        if local is not None and self._is_repliable(local, datagram.interface):
            plain = unmap(local)
            if isinstance(plain, IPv4Address):
                # Answer v4 from a v4 socket. The mapped form would need an
                # AF_INET6 socket with V6ONLY cleared, which is not the default
                # on Windows and is a worse thing to require than a second
                # socket family.
                candidates.append((_socket.AF_INET, str(plain)))
            elif isinstance(plain, IPv6Address):
                text = str(plain)
                if plain.is_link_local and datagram.interface_index:
                    # The zone goes *in the address string*, which is what the
                    # kernel wants. Without a scope id a link-local bind is
                    # refused: the same address can exist on several interfaces
                    # and it will not guess which. `%zone` is how a
                    # sockaddr_in6 scope is spelled for `bind`.
                    text = "%s%%%d" % (text, int(datagram.interface_index))
                candidates.append((_socket.AF_INET6, text))

        # Fallback 1: whatever this endpoint itself is bound to -- right for a
        # listener pinned to one address, and a no-op for a wildcard one. It is
        # only usable when it is in the *reply's* family: a v6 wildcard listener
        # answering a v4 client would otherwise offer `::` to an `AF_INET`
        # socket, so such a mismatch is skipped and the v4 wildcard below is
        # used instead.
        try:
            own = self.socket.getsockname()
            if own and own[0]:
                plain_own = unmap(parse(str(own[0]).split("%")[0], IPAddress))
                wanted = 6 if family == _socket.AF_INET6 else 4
                if plain_own.version == wanted:
                    candidates.append((family, str(plain_own)))
        except (OSError, ValueError):  # pragma: no cover - a closed socket
            pass

        # Fallback 2: the wildcard, which always binds.
        candidates.append((family, ""))

        from .._sockets import bind as _bind
        from .._exceptions import AddressInUseError

        if isinstance(port, int):
            ports: "tuple" = (port,)
        else:
            # Materialised once: the same ports are retried for each address
            # candidate, and a generator would be empty by the second.
            ports = tuple(port)
            if not ports:
                raise ValueError("port must not be an empty iterable")

        last: "Optional[BaseException]" = None
        exhausted: "Optional[AddressInUseError]" = None
        for candidate_family, address in candidates:
            for one in ports:
                try:
                    return _bind(
                        address,
                        one,
                        family=candidate_family,
                        kind=_socket.SOCK_DGRAM,
                        connreset=connreset,
                    )
                except AddressInUseError as exc:
                    # The address is fine and the port is held: the next port on
                    # *this* address is the only move that preserves the reply's
                    # source address. Moving to the next address would answer
                    # from one the client never used.
                    last = exhausted = exc
                    continue
                except (OSError, ValueError) as exc:
                    # A broadcast, multicast or otherwise unbindable destination
                    # lands here, which is why the list is tried rather than
                    # vetted. The address is the problem, so no other port on it
                    # will do better.
                    last = exc
                    break
            else:
                # Every port held on an address that is otherwise bindable. Do
                # not fall back to an address the client did not address.
                raise exhausted  # type: ignore[misc]

        # Every candidate failed, including the wildcard, so something is wrong
        # with the socket rather than with the address.
        raise OSError(
            "could not bind a reply socket for %r" % (datagram.destination,)
        ) from last
