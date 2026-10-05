"""The ``os.sysconf`` stand-in the socket patch installs where the platform has none."""

from __future__ import annotations

from typing import Any

from ._dispatch import _mark

#: What ``SC_IOV_MAX`` is reported as where the platform has no ``sysconf``.
#:
#: **There is nothing to query.** Windows exposes no buffer-count limit: the
#: socket module has no ``IOV``-like name, ``WSASend``'s ``dwBufferCount`` is a
#: bare ``DWORD``, and measured on build 28000 it accepted **1048576** buffers
#: in one call -- the bound is memory, not a kernel ceiling. The only genuinely
#: system-reported limit nearby is ``SO_MAX_MSG_SIZE`` (65507 for UDP, -1 for
#: TCP), which caps *bytes per datagram* rather than buffers per call and so
#: answers a different question.
#:
#: 1024 therefore matches Linux's real ``IOV_MAX``: a caller batching by this
#: number behaves identically on both platforms, and since Windows has no limit
#: nobody is worse off here than they already are on POSIX. It is a batch size,
#: not a ceiling, and that is the whole reason it can be a constant.
_IOV_MAX = 1024

#: What ``SC_OPEN_MAX`` is reported as: the size of the C runtime's file
#: descriptor table. Measured 2026-10-05 on Windows 11, CPython 3.9 and 3.14:
#: ``os.open`` hands out descriptors 0 to 8191 and then fails with ``EMFILE``
#: ("Too many open files"). Sockets are handles, not descriptors, and are not
#: counted against it (20000 were opened in one process).
_OPEN_MAX = 8192

#: The names the shim answers. Each has a value the platform fixes and that was
#: measured; everything else raises, because a number for ``SC_NPROCESSORS_ONLN``
#: or ``SC_PAGE_SIZE`` has a right way to be asked for on Windows that is not
#: this function.
_SYSCONF_VALUES = {"SC_IOV_MAX": _IOV_MAX, "SC_OPEN_MAX": _OPEN_MAX}


@_mark
def _shim_sysconf(name: "Any") -> int:
    """Stand in for ``os.sysconf`` where the platform has none.

    Needed only because patching ``socket.socket.sendmsg`` breaks an invariant
    the stdlib relies on: ``sendmsg`` and ``os.sysconf`` are both POSIX and have
    always travelled together, so ``hasattr(socket.socket, "sendmsg")`` has been
    a sound proxy for "``os.sysconf`` is available too". CPython's
    ``asyncio/selector_events`` reads exactly that way at import time::

        _HAS_SENDMSG = hasattr(socket.socket, 'sendmsg')
        if _HAS_SENDMSG:
            try: SC_IOV_MAX = os.sysconf('SC_IOV_MAX')
            except OSError: _HAS_SENDMSG = False

    With ``sendmsg`` present and ``os.sysconf`` absent, that is an uncaught
    ``AttributeError`` and ``import asyncio`` dies.

    **Per name, not one blanket answer**, because the three stdlib callers guard
    differently and no single behaviour satisfies them all:

    ====================================  =============================
    caller                                catches
    ====================================  =============================
    ``asyncio/selector_events.py``        ``OSError``
    ``concurrent/futures/process.py``     ``(AttributeError, ValueError)``
    ``multiprocessing/util.py``           ``Exception``
    ====================================  =============================

    Measured: raising ``OSError`` for everything rescues asyncio and breaks
    ``ProcessPoolExecutor``; raising ``ValueError`` or ``AttributeError`` for
    everything does the reverse. So ``SC_IOV_MAX`` returns a value -- which is
    honest, since :func:`sendmsg` works on a stream socket via ``WSASend`` --
    and an unanswered name raises :class:`ValueError`, which is both what POSIX
    ``sysconf`` does for an unrecognised name and what the other two callers
    already handle.

    ``SC_OPEN_MAX`` is answered too. Code written for POSIX reads it behind
    ``hasattr(os, "sysconf")`` with no guard, since every POSIX system has it:
    an SFTP server library sizes its open-handle limit that way, and a
    ``ValueError`` there fails every session.

    (``asyncio``'s guard is the outlier here. ``concurrent.futures`` catches
    ``AttributeError`` with the comment "sysconf not available or setting not
    available", so handling a missing ``sysconf`` is the established convention
    and asyncio does not handle it.)
    """
    try:
        return _SYSCONF_VALUES[name]
    except (KeyError, TypeError):
        raise ValueError("unrecognized configuration name %r" % (name,))
