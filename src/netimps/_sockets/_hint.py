"""Turning a failed bind into an error that says what to change."""

from __future__ import annotations

import errno as _errno
from typing import Optional
from .._exceptions import AddressInUseError

#: Winsock codes that mean "the address is taken", whatever Python wrapped them
#: in. 10048 is WSAEADDRINUSE; 10013 is WSAEACCES, which on a bind means the
#: address is held exclusively rather than that the caller lacks a privilege.
_WSA_IN_USE = frozenset((10048, 10013))


def _with_hint(exc: "OSError", port: "Optional[int]") -> "OSError":
    """Return *exc* rebuilt so its message carries :func:`bind_error_hint`.

    An address that is taken becomes :class:`AddressInUseError`, classified here
    because ``bind`` already knows -- it is the code that writes the hint. Any
    other failure the hint recognises keeps its class and ``errno`` (a POSIX
    ``EACCES`` on a low port stays a :class:`PermissionError`: narrowing it to
    "in use" would be the same misdiagnosis in the other direction); one it does
    not recognise is returned untouched.
    """
    winerror = getattr(exc, "winerror", None)
    in_use = winerror in _WSA_IN_USE or exc.errno == _errno.EADDRINUSE
    hint = bind_error_hint(exc, port)
    if not in_use and hint is None:
        return exc
    if in_use:
        error: "OSError" = AddressInUseError(
            _errno.EADDRINUSE, hint or "address already in use"
        )
    else:
        detail = exc.strerror or str(exc)
        error = type(exc)(exc.errno, "%s (%s)" % (hint, detail))
    # Keep the platform's own code reachable; __cause__ carries the rest.
    if winerror is not None:
        try:
            error.winerror = winerror  # type: ignore[attr-defined]
        except AttributeError:  # pragma: no cover - read-only on some builds
            pass
    return error


def bind_error_hint(
    exc: BaseException, port: "Optional[int]" = None
) -> "Optional[str]":
    """Turn a bind failure into a sentence a user can act on, or ``None``.

    The raw ``OSError`` from a failed bind is famously unhelpful, and the errno
    differs per platform -- Windows reports ``WinError 10013``/``10048`` where
    POSIX reports ``EACCES``/``EADDRINUSE``. :func:`bind` already puts this text
    in the exception it raises; call this for an ``OSError`` that came from
    somewhere else, such as a stdlib ``socket.bind``::

        try:
            sock.bind(("", 67))
        except OSError as exc:
            raise OSError(bind_error_hint(exc, 67) or str(exc)) from exc

    Returns ``None`` for anything unrecognised, so the caller keeps the
    original error rather than a worse paraphrase. This **does not raise** --
    deciding what to do with a failure belongs to the caller.
    """
    import errno as _errno

    if not isinstance(exc, OSError):
        return None

    winerror = getattr(exc, "winerror", None)
    where = "port %d" % port if port is not None else "that port"

    if winerror == 10013:
        # WSAEACCES, and it is NOT a privilege problem. Windows has no
        # privileged-port concept at all -- any user may bind port 80 -- so the
        # POSIX reading of this code sends the reader after an elevation
        # problem that cannot exist here. What it actually means is that
        # another socket holds the address exclusively (SO_EXCLUSIVEADDRUSE),
        # or that a firewall or an excluded port range is refusing it.
        #
        # Python maps WSAEACCES to PermissionError with errno EACCES, so the
        # winerror must be tested BEFORE the POSIX branch below or the generic
        # "permission denied" wins and says the wrong thing. Measured: binding
        # over an exclusively-held socket reported "permission denied binding
        # port 64514" -- a privilege message about an unprivileged port.
        return (
            "%s is held exclusively by another socket, or blocked by a "
            "firewall or an excluded port range (WSAEACCES); it is in use, "
            "not privileged -- Windows has no privileged ports" % where.capitalize()
        )

    if winerror == 10022:
        # WSAEINVAL, and from a bind path it almost always means the socket
        # carries two reuse options that contradict each other -- Windows
        # refuses `SO_REUSEADDR` on a socket that already has
        # `SO_EXCLUSIVEADDRUSE`, and says only "invalid argument" without
        # naming either. A bare 10022 is undiagnosable, which is the whole
        # reason this branch exists.
        return (
            "Invalid argument (WSAEINVAL) -- on Windows this usually means "
            "conflicting reuse options on one socket: SO_REUSEADDR is refused "
            "once SO_EXCLUSIVEADDRUSE is set. Ask for sharing by name with "
            "allow_address_takeover=True rather than passing SO_REUSEADDR "
            "through options="
        )

    if isinstance(exc, PermissionError) or exc.errno == _errno.EACCES:
        hint = "permission denied binding %s" % where
        if port is not None and port < 1024:
            hint += "; ports below 1024 need root/Administrator"
        return hint

    if exc.errno == _errno.EADDRINUSE or winerror == 10048:
        return "%s is already in use" % where.capitalize()

    if exc.errno == _errno.EADDRNOTAVAIL or winerror == 10049:
        return (
            "that address is not available on this host; "
            "it must belong to a local interface"
        )

    return None
