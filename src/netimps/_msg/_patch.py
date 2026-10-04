"""Installing and removing the ``socket`` patch, and the environment switch for it."""

from __future__ import annotations

import os as _os
import socket as _socket
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ._dispatch import (
    CMSG_LEN,
    CMSG_SPACE,
    _is_ours,
    _mark,
    has_recvmsg,
    recvmsg,
    sendmsg,
)
from ._shape import _from_posix_shape, _to_posix_shape
from ._sysconf import _IOV_MAX, _SYSCONF_VALUES, _shim_sysconf

__all__ = ["patch_socket_module", "is_socket_patched"]


#: What :func:`patch_socket_module` installed, so it can be undone exactly.
#: Empty means nothing is installed, which is the state on every platform whose
#: CPython already provides these.
_installed: "Dict[str, Any]" = {}


def _free(target: "Any", attribute: str) -> bool:
    """Whether *attribute* of *target* may be installed over: absent, or put
    there by a copy of this package. The platform's own is never replaced."""
    existing = getattr(target, attribute, None)
    return existing is None or _is_ours(existing)


def is_socket_patched() -> bool:
    """Whether netimps has added anything to :mod:`socket` right now.

    A function rather than a constant because the answer changes when
    :func:`patch_socket_module` is called, and a module-level flag copied by
    ``from netimps import ...`` would go stale at the first toggle.
    """
    return bool(_installed)


def patch_socket_module(
    enable: bool = True, *, iov_max: "Optional[int]" = None
) -> "List[str]":
    """Add ``recvmsg``/``sendmsg``/``CMSG_LEN``/``CMSG_SPACE`` where missing.

    netimps calls this on import, so ``sock.recvmsg(...)`` works on Windows
    without the caller changing anything. Returns the names it changed, newest
    call only -- an empty list means there was nothing to do.

    Idempotent in both directions, and strictly additive: a name the platform
    already provides is never replaced, so on Linux and macOS this is a
    verified no-op. A name another copy of this package installed is taken
    over, so the second import of the package in a process owns the patch.
    ``enable=False`` removes exactly what was installed, leaving a
    natively-provided name alone.

    On a platform with no ``os.sysconf`` this also installs one -- see
    :func:`_shim_sysconf` for why that is part of the same patch rather than a
    separate feature.

    :param enable: install when true, restore the original state when false.
    :param iov_max: what the installed ``os.sysconf`` reports for
        ``SC_IOV_MAX``. Default :data:`_IOV_MAX` (1024, matching Linux).

        **This is a batch size, not a ceiling, and it is a choice rather than a
        measurement** -- which is why it is a parameter. Windows reports no
        buffer-count limit anywhere (no ``IOV``-like socket name;
        ``WSASend``'s ``dwBufferCount`` is a bare ``DWORD``, and 1048576
        buffers in one call were accepted on build 28000), and the system limit
        is not settable on POSIX either: Linux's is
        ``#define UIO_MAXIOV 1024`` in ``linux/uio.h``, with no sysctl and no
        ``/proc`` entry. So there is nothing to query and nothing to set; this
        is the only knob that exists. Raise it if you gather more than 1024
        buffers per call and want them in one syscall.
    :returns: the names added or removed by this call.
    :raises ValueError: for an ``iov_max`` below 1.
    """
    changed: "List[str]" = []

    if enable and iov_max is not None and iov_max < 1:
        raise ValueError("iov_max must be at least 1, got %r" % (iov_max,))

    if not enable:
        # Reset the tunable too: leaving a previous call's iov_max in place
        # would make a later re-install silently inherit it.
        _SYSCONF_VALUES["SC_IOV_MAX"] = _IOV_MAX
        for name in list(_installed):
            target, attribute = _installed.pop(name)
            try:
                delattr(target, attribute)
            except AttributeError:  # pragma: no cover - already gone
                pass
            changed.append(name)
        return changed

    if not has_recvmsg():
        # Nothing to offer: leave `socket` exactly as it was rather than
        # installing a function whose only behaviour is to raise.
        return changed

    for name, value in (
        ("socket.recvmsg", _patched_recvmsg),
        ("socket.sendmsg", _patched_sendmsg),
    ):
        attribute = name.split(".", 1)[1]
        if name in _installed or not _free(_socket.socket, attribute):
            continue
        setattr(_socket.socket, attribute, value)
        _installed[name] = (_socket.socket, attribute)
        changed.append(name)

    # `os.sysconf` is part of this patch, not a separate feature: it is needed
    # only because installing `sendmsg` above makes the stdlib's
    # "sendmsg implies POSIX implies os.sysconf" inference wrong. Installing and
    # removing them together is what keeps that coupling honest -- see
    # `_shim_sysconf`.
    if iov_max is not None:
        _SYSCONF_VALUES["SC_IOV_MAX"] = int(iov_max)
        if "os.sysconf_names" in _installed:
            # Keep the advertised table in step with what sysconf answers.
            _os.sysconf_names.update(_SYSCONF_VALUES)  # type: ignore[attr-defined]

    if "os.sysconf" not in _installed and _free(_os, "sysconf"):
        earlier_copy = hasattr(_os, "sysconf")
        setattr(_os, "sysconf", _shim_sysconf)
        _installed["os.sysconf"] = (_os, "sysconf")
        changed.append("os.sysconf")
        if earlier_copy or not hasattr(_os, "sysconf_names"):
            setattr(_os, "sysconf_names", dict(_SYSCONF_VALUES))
            _installed["os.sysconf_names"] = (_os, "sysconf_names")
            changed.append("os.sysconf_names")

    # A separate loop with its own names rather than reusing `name, value`: the
    # two tables hold different callable shapes, and mypy types a reused loop
    # variable from whichever came first.
    for helper, function in (
        ("CMSG_LEN", CMSG_LEN),
        ("CMSG_SPACE", CMSG_SPACE),
    ):
        if helper in _installed or not _free(_socket, helper):
            continue
        setattr(_socket, helper, function)
        _installed[helper] = (_socket, helper)
        changed.append(helper)

    return changed


@_mark
def _patched_recvmsg(
    self: "Any",
    bufsize: int,
    ancbufsize: int = 0,
    flags: int = 0,
) -> "Tuple[bytes, List[Tuple[int, int, bytes]], int, Optional[Any]]":
    """Bound-method form of :func:`recvmsg`, installed on :class:`socket.socket`.

    **Reshapes the ancillary data into the POSIX field order**, unlike
    :func:`recvmsg`, which reports the platform's own bytes. See
    :func:`_to_posix_shape`: this method only exists on platforms where it
    natively would not, so code reaching for it is POSIX-shaped code, and giving
    it the name without the layout is the half-impersonation that makes such
    code misparse.
    """
    data, ancdata, msg_flags, address = recvmsg(self, bufsize, ancbufsize, flags)
    return data, _to_posix_shape(ancdata), msg_flags, address


@_mark
def _patched_sendmsg(
    self: "Any",
    buffers: "Sequence[bytes]",
    ancdata: "Iterable[Tuple[int, int, bytes]]" = (),
    flags: int = 0,
    address: "Optional[Any]" = None,
) -> int:
    """Bound-method form of :func:`sendmsg`, installed on :class:`socket.socket`.

    Accepts a POSIX-shaped ``in_pktinfo`` as well as the native one, chosen by
    length -- see :func:`_from_posix_shape`. The counterpart to the reshaping
    the patched :meth:`recvmsg` does, so a caller can round-trip what it
    received.
    """
    return sendmsg(self, buffers, _from_posix_shape(ancdata), flags, address)


def _patch_requested() -> bool:
    """Whether the import-time patch is wanted.

    Read once, at import. ``NETIMPS_SOCKET_PATCH`` unset or empty means yes;
    ``1``, ``true``, ``yes``, ``on`` mean yes and ``0``, ``false``, ``no``,
    ``off`` mean no, in any case. Anything else raises :class:`ValueError`
    naming the variable: a typo must not read as a choice.

    ``NETIMPS_NO_SOCKET_PATCH`` set to anything raises as well. That name has
    the opposite sense, so honouring it is impossible and ignoring it would
    install the patch for someone who had asked for it to be left out.
    """
    if "NETIMPS_NO_SOCKET_PATCH" in _os.environ:
        raise ValueError(
            "NETIMPS_NO_SOCKET_PATCH is no longer supported. "
            "Use NETIMPS_SOCKET_PATCH=0 to disable the patch."
        )
    value = _os.environ.get("NETIMPS_SOCKET_PATCH", "").strip().lower()
    if value in ("", "1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValueError(
        "NETIMPS_SOCKET_PATCH must be one of 1/true/yes/on or 0/false/no/off, "
        "got %r" % (_os.environ["NETIMPS_SOCKET_PATCH"],)
    )
