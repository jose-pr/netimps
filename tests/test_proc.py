"""The subprocess runner, against real fake programs on PATH.

Nothing here patches ``subprocess``: each test runs the real spawn, capture,
decode and kill path against a program the ``fake_program`` fixture wrote.
"""

import ctypes
import os
import sys
import time

import pytest

# Private: the runner every platform binary goes through.
from netimps import _proc


def _alive(pid):
    """Whether a process with this id is still running."""
    if sys.platform == "win32":
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return code.value == 259  # STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers signal 0; reaped means gone.
    try:
        reaped, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return reaped == 0


def test_run_returns_status_and_both_streams(fake_program):
    """The result carries the exit status and decoded stdout and stderr."""
    fake = fake_program("netimps-probe", stdout="out", stderr="err", returncode=3)
    result = _proc.run("netimps-probe", ["a", "b c"], timeout=20)
    assert tuple(result) == (3, "out", "err")
    assert fake.argv == ["a", "b c"]


def test_a_missing_program_is_reported_before_anything_runs(fake_program):
    """FileNotFoundError names the program; callers map it as an OSError."""
    fake_program("netimps-probe")
    with pytest.raises(FileNotFoundError, match="netimps-absent") as caught:
        _proc.run("netimps-absent", [], timeout=20)
    assert isinstance(caught.value, OSError)


def test_a_non_zero_exit_is_a_result_not_an_error(fake_program):
    """The runner reports the status; each caller decides what it means."""
    fake_program("netimps-probe", stderr="boom", returncode=7)
    result = _proc.run("netimps-probe", [], timeout=20)
    assert result.returncode == 7 and result.stderr == "boom"


def test_a_timeout_raises_and_leaves_no_child_behind(fake_program):
    """The deadline kills the program *and* the child it started.

    The fake starts a sleeping grandchild that inherits the output pipes; a
    runner that killed only the direct child would hang in ``communicate`` or
    leave the grandchild running.
    """
    fake = fake_program("netimps-probe", hang=True)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="netimps-probe"):
        _proc.run("netimps-probe", [], timeout=2.0)
    assert time.monotonic() - started < 30
    pids = fake.hung_pids
    assert len(pids) == 2, "the fake never recorded its processes"
    deadline = time.monotonic() + 10
    while any(_alive(pid) for pid in pids) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert [pid for pid in pids if _alive(pid)] == []


def test_invalid_bytes_are_replaced_not_raised(fake_program):
    """A byte the decoder cannot map does not raise out of the runner.

    UTF-8 turns 0xFF into U+FFFD. Windows decodes with a single-byte OEM page,
    which maps every byte, so there the same output decodes to characters
    instead and the assertion is only that it arrives.
    """
    fake_program("netimps-probe", stdout=b"ok \xff\xfe\n", stderr=b"\xff")
    result = _proc.run("netimps-probe", [], timeout=20)
    assert result.stdout.startswith("ok ") and len(result.stderr) == 1
    if sys.platform != "win32":
        assert "�" in result.stdout and "�" in result.stderr


@pytest.mark.skipif(sys.platform != "win32", reason="the OEM code page is Windows")
def test_windows_output_is_decoded_as_the_oem_code_page(fake_program):
    """A console program writes the OEM page: cp437 puts n-tilde at 0xA4.

    Measured against the real ``ping``, ``nslookup`` and ``tracert``, which each
    echoed a non-ASCII host name in the OEM page; UTF-8 and cp1252 mangle it.
    """
    fake_program("netimps-probe", stdout=b"host \xa4and\xa3")
    expected = b"\xa4and\xa3".decode("oem")
    assert _proc.run("netimps-probe", [], timeout=20).stdout == "host " + expected


def test_the_child_sees_the_c_locale_and_the_callers_environment(monkeypatch):
    """``LC_ALL=C`` is added to a copy of the environment, not substituted for it."""
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    monkeypatch.setenv("NETIMPS_PROBE", "kept")
    result = _proc.run(
        sys.executable,
        [
            "-c",
            "import os; print(os.environ['LC_ALL'], os.environ['NETIMPS_PROBE'], "
            "os.environ.get('EXTRA'))",
        ],
        timeout=20,
        env={"EXTRA": "added"},
    )
    assert result.stdout.split() == ["C", "kept", "added"]
    assert os.environ["LC_ALL"] == "de_DE.UTF-8", "the caller's environment is intact"


def test_stdin_is_closed():
    """A child that reads standard input sees end-of-file at once."""
    result = _proc.run(
        sys.executable,
        ["-c", "import sys; print(repr(sys.stdin.read()))"],
        timeout=20,
    )
    assert result.stdout.strip() == "''"


def test_a_cmd_shim_is_refused(fake_program, tmp_path):
    """A ``.bat`` or ``.cmd`` resolution re-parses its arguments through cmd.exe."""
    fake_program("netimps-probe")
    shim = tmp_path / "fake-bin" / "netimps-shim.cmd"
    shim.write_bytes(b"@echo off\n")
    shim.chmod(0o755)
    _proc.clear_cache()
    with pytest.raises(PermissionError, match="cmd.exe"):
        _proc.run("netimps-shim.cmd", [], timeout=20)


def test_the_lookup_follows_a_changed_path(fake_program, tmp_path, monkeypatch):
    """Where a program was found is cached per PATH, so a new PATH searches again."""
    fake_program("netimps-probe", stdout="first")
    assert _proc.run("netimps-probe", [], timeout=20).stdout == "first"
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(FileNotFoundError):
        _proc.run("netimps-probe", [], timeout=20)


def test_ping_finds_and_runs_a_fake_ping_with_the_argv_it_built(fake_program):
    """`netimps.ping` resolves `ping` from PATH and passes exactly its own argv.

    Nothing is patched: the fake is found by the same `shutil.which` lookup the
    real binary would be, and what it recorded is compared with what
    `_ping_command` builds for the same arguments.
    """
    import netimps

    # Private: the probe seams and the per-platform grammar are private.
    from netimps import _ping

    fake = fake_program(
        "ping", stdout="Reply from 127.0.0.1: bytes=32 time=1ms TTL=128\n"
    )
    result = netimps.ping("127.0.0.1", timeout=1.0)
    argv, _ = _ping._command._ping_command(
        "127.0.0.1", None, 1.0, None, None, None, False, [netimps.parse("127.0.0.1")]
    )
    assert bool(result) is True and result.ttl == 128
    assert fake.calls == [argv[1:]]
    assert argv[0] == "ping"


def _decoy_name():
    return "netimps-probe.exe" if sys.platform == "win32" else "netimps-probe"


def test_a_program_in_the_working_directory_is_never_taken(
    fake_program, tmp_path, monkeypatch
):
    """A same-named file beside the caller is not what ``PATH`` names.

    ``shutil.which`` searches the working directory first on Windows (measured
    on 3.9: ``which("pip")`` gave a ``pip.EXE`` in the working directory with
    only System32 on ``PATH``), so the runner searches the ``PATH`` entries.
    """
    fake = fake_program("netimps-probe", stdout="from path")
    here = tmp_path / "cwd"
    here.mkdir()
    decoy = here / _decoy_name()
    decoy.write_bytes(b"MZ not a program")
    decoy.chmod(0o755)
    monkeypatch.chdir(here)
    _proc.clear_cache()
    found = _proc._find("netimps-probe")
    assert os.path.isabs(found)
    assert os.path.normcase(os.path.dirname(found)) == os.path.normcase(
        str(fake.directory)
    )


def test_a_relative_path_entry_is_not_searched(tmp_path, monkeypatch):
    """``.`` or an empty entry on ``PATH`` would be the working directory again."""
    here = tmp_path / "cwd"
    here.mkdir()
    decoy = here / _decoy_name()
    decoy.write_bytes(b"x")
    decoy.chmod(0o755)
    monkeypatch.chdir(here)
    for entry in (".", "", os.curdir + os.sep, "cwd"):
        monkeypatch.setenv("PATH", entry + os.pathsep + str(tmp_path / "empty"))
        _proc.clear_cache()
        with pytest.raises(FileNotFoundError):
            _proc._find("netimps-probe")


def test_a_program_name_with_a_relative_directory_is_refused():
    """``./tool`` is a path, not a name to look up."""
    with pytest.raises(ValueError, match="bare"):
        _proc._find("." + os.sep + "netimps-probe")


def test_every_run_has_a_timeout():
    """``timeout=None`` would run unbounded; the runner refuses it."""
    with pytest.raises(TypeError, match="timeout"):
        _proc.run(sys.executable, ["-c", "pass"], timeout=None)
