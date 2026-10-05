"""URL-scheme to port mappings (internal).

A small registry mapping scheme names to their conventional ports and back,
seeded with the entries the system services database gets wrong or omits
(there is no ``/etc/services`` entry for the socks variants at all).

Also the home of :func:`coerce_port`, the single place a port number is
validated. It lives here because this is already the module every port-taking
entry point consults to turn a spec into a number, and an unvalidated port is
not a loud failure: the socket layer masks it to 16 bits and answers
confidently about a *different* port.

:func:`get_default_port` and :func:`get_default_scheme` are re-exported from
:mod:`netimps`; :func:`coerce_port` is internal to the package.
"""

from __future__ import annotations

import socket as _socket
from typing import Dict, Optional

from ._exceptions import NetimpsValueError

__all__ = ["get_default_port", "get_default_scheme", "register_port"]

#: Conventional scheme -> port mappings, consulted before the system services
#: database. Seeded with the entries :func:`socket.getservbyname` gets wrong or
#: does not know (it has no entry for the socks variants at all). Mutable via
#: :func:`register_port`; not a frozen table, deliberately -- callers have
#: protocols of their own to add.
_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    # WebSocket (RFC 6455) rides HTTP/HTTPS ports and is absent from
    # /etc/services. Listed after http/https so those stay the canonical name
    # for 80/443 (get_default_scheme(443) == "https", not "wss").
    "ws": 80,
    "wss": 443,
    "ftp": 21,
    "ftps": 990,
    "ssh": 22,
    "sftp": 22,
    "telnet": 23,
    "smtp": 25,
    "dns": 53,
    "tftp": 69,
    "pop3": 110,
    "ntp": 123,
    "imap": 143,
    "ldap": 389,
    "smb": 445,
    "smtps": 465,
    "syslog": 514,
    "ldaps": 636,
    "imaps": 993,
    "pop3s": 995,
    "socks": 1080,
    "socks4": 1080,
    "socks5": 1080,
    "mysql": 3306,
    "rdp": 3389,
    "postgresql": 5432,
    # WS-Management over HTTP and HTTPS: IANA registers 5985 and 5986 as
    # `wsman` and `wsmans`, and Windows Remote Management, PowerShell remoting
    # and their URIs spell the same two ports `winrm`/`winrms` and `psrp`. The
    # IANA names come first so they stay the canonical ones for the reverse
    # lookup.
    "wsman": 5985,
    "wsmans": 5986,
    "winrm": 5985,
    "winrms": 5986,
    "psrp": 5985,
    "redis": 6379,
    "http-alt": 8080,
}

#: Reverse index, rebuilt by :func:`register_port`. The *first* scheme
#: registered for a port wins as its canonical name, so
#: ``get_default_scheme(1080)`` is ``"socks"`` rather than whichever alias
#: happens to be last.
_PORT_SCHEMES: "Dict[int, str]" = {}


def _reindex_ports() -> None:
    _PORT_SCHEMES.clear()
    for name, num in _DEFAULT_PORTS.items():
        _PORT_SCHEMES.setdefault(num, name)


_reindex_ports()

#: The inclusive bounds of the TCP/UDP port space, as the 16-bit field on the
#: wire defines them. Named rather than inlined so the error message and the
#: check cannot drift apart.
MIN_PORT = 0
MAX_PORT = 65535

#: Protocols consulted in the system services database, in order. An explicit
#: protocol is not optional: see :func:`_service_port`.
_SERVICE_PROTOCOLS = ("tcp", "udp")


def coerce_port(port: object, label: str = "port") -> int:
    """Validate a port number, returning it, or raise.

    The shared gate for every port-taking entry point. Skipping it is not a
    loud failure: the socket layer masks the value to 16 bits, so a caller
    asking about ``115823`` -- the obvious ``base + offset`` arithmetic slip
    in a loop -- is told about ``50287`` instead, with nothing to indicate the
    question changed.

    ``bool`` is rejected rather than read as its ``0``/``1`` value: ``True``
    is never a port anyone meant, and letting it through would scan port 1.

    :param label: what the number is, for the message (``"port"``,
        ``"source port"``); the caller knows and this function does not.

    Raises :class:`TypeError` for a non-``int`` and :class:`ValueError`
    outside ``0-65535``.
    """
    if isinstance(port, bool) or not isinstance(port, int):
        raise TypeError("%s must be an int, got %r" % (label, type(port).__name__))
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(
            "%s out of range: %r (must be %d-%d)" % (label, port, MIN_PORT, MAX_PORT)
        )
    return port


def _service_port(scheme: str) -> "Optional[int]":
    """The services-database port for ``scheme``, TCP first, then UDP.

    ``getservbyname(scheme)`` with no protocol returns whichever entry the
    platform's database happens to find first, so the same call can answer
    with the TCP port on one host and the UDP port on another -- a
    platform-dependent answer from a table documented as stable. Asking in a
    fixed order removes that: TCP wins where a name has both, and a UDP-only
    service (``bootpc``, ``syslog``) is still found rather than lost to the
    stricter lookup.
    """
    for protocol in _SERVICE_PROTOCOLS:
        try:
            return _socket.getservbyname(scheme, protocol)
        except OSError:
            continue
    return None


def _service_name(port: int) -> "Optional[str]":
    """The services-database name for ``port``, TCP first, then UDP.

    The same fixed order as :func:`_service_port`, and for the same reason --
    port 514 is ``shell``/``cmd`` over TCP and ``syslog`` over UDP, and a
    protocol-less lookup picks between them per platform.
    """
    for protocol in _SERVICE_PROTOCOLS:
        try:
            return _socket.getservbyport(port, protocol)
        except (OSError, OverflowError, TypeError):
            continue
    return None


def register_port(scheme: str, port: int, *, canonical: bool = False) -> None:
    """Register (or override) a scheme's conventional port.

    The built-in table covers the common cases; a protocol of the caller's own
    is added here::

        register_port("myproto", 9999)
        get_default_port("myproto")     # 9999
        get_default_scheme(9999)        # 'myproto'

    Re-registering a scheme **moves** it: the port it occupied before the call
    stops mapping back to it, or the registry would contradict itself::

        register_port("myproto", 8888)
        get_default_port("myproto")     # 8888
        get_default_scheme(9999)        # None, not 'myproto'

    If another scheme is still registered on the vacated port, it inherits the
    slot (earliest registration first, the same rule the initial index uses).

    :param scheme: scheme name; matched case-insensitively.
    :param port: TCP/UDP port number, 0-65535.
    :param canonical: make ``scheme`` the name :func:`get_default_scheme` returns for
        ``port``, displacing any existing one. By default the first registration
        for a port keeps that slot, so adding an alias does not silently change
        what an existing port maps back to.

    Raises :class:`ValueError` on an out-of-range port or empty scheme, and
    :class:`TypeError` on a non-``int`` port.
    """
    if not scheme or not scheme.strip():
        raise ValueError("scheme must be a non-empty string")
    port = coerce_port(port)

    scheme = scheme.strip().lower()
    previous = _DEFAULT_PORTS.get(scheme)
    _DEFAULT_PORTS[scheme] = port
    if previous is not None and previous != port:
        # The scheme moved. Leaving the stale reverse entry in place is how the
        # registry ends up stating both "myproto is 8888" and "9999 is
        # myproto" at once; hand the vacated slot to whichever scheme still
        # claims that port, if any.
        if _PORT_SCHEMES.get(previous) == scheme:
            del _PORT_SCHEMES[previous]
            for name, num in _DEFAULT_PORTS.items():
                if num == previous:
                    _PORT_SCHEMES[previous] = name
                    break
    if canonical or port not in _PORT_SCHEMES:
        _PORT_SCHEMES[port] = scheme


def get_default_port(scheme: str) -> Optional[int]:
    """Return the conventional port for a URL scheme, or ``None`` if unknown.

    Checks the built-in/registered table first, then falls back to the system
    services database via :func:`socket.getservbyname`::

        get_default_port("https")    # 443
        get_default_port("socks5")   # 1080  (absent from /etc/services)
        get_default_port("443")      # 443   (a port number as text)
        get_default_port("nope")     # None

    The database is asked for **TCP first, then UDP**, so a name carrying both
    answers with its TCP port on every platform rather than with whichever
    entry that host's database lists first.

    Text made of ASCII digits is a port, not a scheme: it comes back as an
    ``int``, so a command line or a config file can hand over either spelling.
    A number outside ``0-65535`` raises :class:`NetimpsValueError`; it is
    neither a port nor a scheme. Any other spelling of a number (``"+80"``,
    ``"8_0"``, surrounding spaces) is looked up as a name and is unknown.

    :raises TypeError: for a ``scheme`` that is not text.

    Case-insensitive. Extend the table with :func:`register_port`.
    """
    if not isinstance(scheme, str):
        raise TypeError(
            "scheme must be text (a name or a port number), got %s"
            % (type(scheme).__name__,)
        )
    scheme = scheme.lower()
    # A port is ASCII digits and nothing else, the rule split_host applies:
    # int() alone also reads "+80", "8_0", " 80 " and non-ASCII digits.
    if scheme.isascii() and scheme.isdigit():
        number = int(scheme)
        if not MIN_PORT <= number <= MAX_PORT:
            raise NetimpsValueError(
                "port out of range: %r (must be %d-%d)" % (scheme, MIN_PORT, MAX_PORT)
            )
        return number
    if scheme in _DEFAULT_PORTS:
        return _DEFAULT_PORTS[scheme]
    return _service_port(scheme)


def get_default_scheme(port: int) -> Optional[str]:
    """Return the conventional scheme for a port, or ``None`` if unknown.

    The inverse of :func:`get_default_port`::

        get_default_scheme(443)     # 'https'
        get_default_scheme(1080)    # 'socks'   (canonical, not an alias)
        get_default_scheme(9999)    # None

    Falls back to the system services database via
    :func:`socket.getservbyport`, asked for **TCP first, then UDP**: port 514
    is ``shell``/``cmd`` over TCP and ``syslog`` over UDP, and a
    protocol-less lookup picks between them per platform. Where several
    schemes share a port, the canonical one is returned -- see
    :func:`register_port`.

    An out-of-range ``port`` is ``None`` rather than an error: this is a table
    lookup, not a socket operation, so "no such entry" is the honest answer.
    The port-taking network helpers validate instead, via
    :func:`coerce_port`.
    """
    if port in _PORT_SCHEMES:
        return _PORT_SCHEMES[port]
    return _service_name(port)
