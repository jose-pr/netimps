"""Every exception the package raises on its own account (internal).

:class:`NetimpsError` is the one base: a caller who wants "anything netimps
reported" catches it. Each class also inherits the builtin a caller would
already catch for that kind of failure (``ValueError``, ``TimeoutError``,
``OSError``), so existing ``except`` clauses keep working.

A caller's own mistake -- a bad option, a wrong argument type -- is not here:
it raises plain :class:`ValueError` or :class:`TypeError`.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

__all__ = [
    "NetimpsError",
    "NetimpsValueError",
    "ResolutionError",
    "ResolutionTimeoutError",
    "DNSDecodeError",
    "AddressInUseError",
]


class NetimpsError(Exception):
    """The base of every exception netimps raises on its own account."""


class NetimpsValueError(NetimpsError, ValueError):
    """Text that is not the value it was asked to become: a malformed address,
    MAC, domain name or ``host:port``.

    Also a :class:`ValueError`, so ``except ValueError`` keeps catching it.
    """


class ResolutionError(NetimpsError):
    """A backend could not even attempt the query (missing binary, unsupported
    ``rdtype``, transport/setup failure). Distinct from a definitive DNS
    answer of "no such record", which is `[]`, not an exception.
    """


class ResolutionTimeoutError(ResolutionError, TimeoutError):
    """A resolution backend's deadline expired before it had an answer.

    Caught by ``except ResolutionError`` (so the :func:`netimps.resolve` chain
    moves on) and by ``except TimeoutError``.
    """


class DNSDecodeError(NetimpsValueError):
    """Bytes or a name that the DNS message codec cannot read or write: a
    truncated or looping reply, a reply for another query, an empty or
    over-long label, a record type the codec does not handle.
    """


class AddressInUseError(NetimpsError, OSError):
    """The address is taken -- one stable type, whatever the platform called it.

    "The port is already bound" surfaces as **three different shapes** depending
    on the flags and the interpreter. Measured on Windows 11 ARM64 against an
    exclusive holder:

    ==========================  ==================  ========  ==========
    call                        type                ``errno``  ``winerror``
    ==========================  ==================  ========  ==========
    3.14, ``allow_takeover``    ``PermissionError``  13        10013
    3.9, ``allow_takeover``     ``OSError``          10013     10013
    either, plain               ``OSError``          10048     10048
    ==========================  ==================  ========  ==========

    The 3.14 row is the harmful one: ``PermissionError`` says "privilege
    problem", and on Windows there is no such thing for a port -- the address is
    simply held. A caller branching on the type then sends its user after an
    elevation problem that cannot exist -- and the alternative is a wrapper that
    re-derives the fact by string-matching :func:`bind_error_hint`'s message,
    which is worse.

    So :func:`bind` raises this instead, with ``errno`` normalised to
    ``EADDRINUSE``, the hint as the message, and the original exception chained
    as ``__cause__`` -- so ``winerror`` and the platform's own code stay
    reachable for anyone who wants them.

    **Subclasses :class:`OSError` and deliberately not
    :class:`PermissionError`**: every existing ``except OSError`` keeps working,
    while ``except PermissionError`` stops catching a case that was never about
    permission. A genuine privilege failure -- POSIX ``EACCES`` on a port below
    1024 -- is left exactly as it was.
    """

    __slots__ = ()
