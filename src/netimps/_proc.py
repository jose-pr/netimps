"""The one place netimps starts another program.

Every platform binary the library drives (``ping``, ``nslookup``, ``route``,
``traceroute``) goes through :func:`run`, so the rules below hold for all of
them and no caller repeats them:

* an argument list, never a shell;
* the program is found with :func:`shutil.which` before anything starts, and
  its absence is a :class:`FileNotFoundError` that names the program;
* ``stdin`` is closed, so the child can never read the caller's input;
* ``LC_ALL=C`` is added to a copy of the environment;
* both streams are captured and decoded with a named encoding;
* the run is bounded, and on a deadline the child **and its children** are
  killed before :class:`TimeoutError` is raised.
"""

from __future__ import annotations

import functools
import os
import shutil
import signal
import subprocess
import sys
from typing import Dict, List, Mapping, NamedTuple, Optional, Sequence

_IS_WINDOWS = sys.platform == "win32"

#: What a console program writes in. Measured 2026-10-04 on Windows 11: ``ping``,
#: ``nslookup`` and ``tracert`` all wrote a non-ASCII host name back in the OEM
#: code page (cp437 here; the ANSI page 1252 and UTF-8 both mis-decode it).
#: Everywhere else a tool writes the locale's encoding, which ``LC_ALL=C`` pins
#: to bytes that UTF-8 reads as ASCII.
_ENCODING = "oem" if _IS_WINDOWS else "utf-8"

#: Extensions that make Windows run a program through ``cmd.exe``, which
#: re-parses the arguments.
_SHELL_SHIM_SUFFIXES = (".bat", ".cmd")

#: Seconds to wait for a killed child's pipes to drain before giving up on them.
_REAP_SECONDS = 5.0


class Result(NamedTuple):
    """What a finished program left behind."""

    returncode: int
    stdout: str
    stderr: str


@functools.lru_cache(maxsize=None)
def _which(program: str, path: "Optional[str]") -> "Optional[str]":
    return shutil.which(program, path=path)


def clear_cache() -> None:
    """Forget where programs were found; the next :func:`run` searches again."""
    _which.cache_clear()


def _find(program: str) -> str:
    """The absolute path of ``program``, or :class:`FileNotFoundError`.

    Cached per ``(program, PATH)``, so a changed ``PATH`` is searched afresh.
    """
    found = _which(program, os.environ.get("PATH"))
    if found is None:
        raise FileNotFoundError(
            "%s was not found on PATH; install it or add its directory to PATH"
            % (program,)
        )
    if found.lower().endswith(_SHELL_SHIM_SUFFIXES):
        raise PermissionError(
            "refusing to run %s: %s is a cmd.exe script, which re-parses its "
            "arguments" % (program, found)
        )
    return found


def _kill_tree(process: "subprocess.Popen[bytes]") -> None:
    """Kill ``process`` and everything it started."""
    if _IS_WINDOWS:
        root = os.environ.get("SystemRoot", r"C:\Windows")
        taskkill = os.path.join(root, "System32", "taskkill.exe")
        try:
            subprocess.run(
                [taskkill, "/F", "/T", "/PID", str(process.pid)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_REAP_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            # The child leads its own session (see run), so its group is
            # exactly the tree to kill.
            os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined]
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass


def run(
    program: str,
    args: "Sequence[str]" = (),
    *,
    timeout: "Optional[float]",
    env: "Optional[Mapping[str, str]]" = None,
) -> Result:
    """Run ``program`` with ``args`` and return its status and output.

    ``env`` is added to a copy of the current environment, with ``LC_ALL=C``
    beneath it. Output is decoded with ``errors="replace"``, so invalid bytes
    become U+FFFD rather than an exception. A non-zero exit is **not** an
    error here; the caller reads :attr:`Result.returncode`.

    :raises FileNotFoundError: ``program`` is not on ``PATH``.
    :raises PermissionError: it resolves to a ``.bat`` or ``.cmd`` script.
    :raises TimeoutError: it ran past ``timeout`` seconds; the child and its
        children are killed first.
    :raises OSError: the system could not start it.
    """
    path = _find(program)
    environment: "Dict[str, str]" = dict(os.environ)
    environment["LC_ALL"] = "C"
    if env:
        environment.update(env)

    options: "Dict[str, object]" = {}
    if _IS_WINDOWS:
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        options["start_new_session"] = True

    process = subprocess.Popen(
        [path, *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        **options,  # type: ignore[arg-type]
    )
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        try:
            process.communicate(timeout=_REAP_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        raise TimeoutError(
            "%s did not finish within %s seconds" % (program, timeout)
        ) from None
    except BaseException:
        _kill_tree(process)
        process.wait()
        raise
    return Result(
        process.returncode,
        (out or b"").decode(_ENCODING, "replace"),
        (err or b"").decode(_ENCODING, "replace"),
    )
