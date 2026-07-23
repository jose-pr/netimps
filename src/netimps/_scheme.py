"""URL-scheme to port mappings (internal).

A small registry mapping scheme names to their conventional ports and back,
seeded with the entries the system services database gets wrong or omits
(there is no ``/etc/services`` entry for the socks variants at all).

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import socket as _socket
from typing import Dict, Optional

__all__ = ["get_default_port", "get_default_scheme", "register_port"]

#: Conventional scheme -> port mappings, consulted before the system services
#: database. Seeded with the entries :func:`socket.getservbyname` gets wrong or
#: does not know (it has no entry for the socks variants at all). Mutable via
#: :func:`register_port`; not a frozen table, deliberately -- consumers keep
#: needing to add their own.
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


def register_port(scheme: str, port: int, canonical: bool = False) -> None:
    """Register (or override) a scheme's conventional port.

    The built-in table covers the common cases, but every consumer eventually
    has a protocol of its own::

        register_port("myproto", 9999)
        get_default_port("myproto")     # 9999
        get_default_scheme(9999)        # 'myproto'

    :param scheme: scheme name; matched case-insensitively.
    :param port: TCP/UDP port number, 0-65535.
    :param canonical: make ``scheme`` the name :func:`get_default_scheme` returns for
        ``port``, displacing any existing one. By default the first registration
        for a port keeps that slot, so adding an alias does not silently change
        what an existing port maps back to.

    Raises :class:`ValueError` on an out-of-range port or empty scheme.
    """
    if not scheme or not scheme.strip():
        raise ValueError("scheme must be a non-empty string")
    if not isinstance(port, int) or isinstance(port, bool):
        raise TypeError("port must be an int, got %r" % (type(port).__name__,))
    if not 0 <= port <= 65535:
        raise ValueError("port out of range: %r" % (port,))

    scheme = scheme.strip().lower()
    _DEFAULT_PORTS[scheme] = port
    if canonical or port not in _PORT_SCHEMES:
        _PORT_SCHEMES[port] = scheme


def get_default_port(scheme: str) -> Optional[int]:
    """Return the conventional port for a URL scheme, or ``None`` if unknown.

    Checks the built-in/registered table first, then falls back to the system
    services database via :func:`socket.getservbyname`::

        get_default_port("https")    # 443
        get_default_port("socks5")   # 1080  (absent from /etc/services)
        get_default_port("nope")     # None

    Case-insensitive. Extend the table with :func:`register_port`.
    """
    scheme = scheme.lower()
    if scheme in _DEFAULT_PORTS:
        return _DEFAULT_PORTS[scheme]
    try:
        return _socket.getservbyname(scheme)
    except OSError:
        return None


def get_default_scheme(port: int) -> Optional[str]:
    """Return the conventional scheme for a port, or ``None`` if unknown.

    The inverse of :func:`get_default_port`::

        get_default_scheme(443)     # 'https'
        get_default_scheme(1080)    # 'socks'   (canonical, not an alias)
        get_default_scheme(9999)    # None

    Falls back to the system services database via
    :func:`socket.getservbyport`. Where several schemes share a port, the
    canonical one is returned -- see :func:`register_port`.
    """
    if port in _PORT_SCHEMES:
        return _PORT_SCHEMES[port]
    try:
        return _socket.getservbyport(port)
    except (OSError, OverflowError, TypeError):
        return None
