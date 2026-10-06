"""``aretry`` and ``await_for_port`` on a real loop, on every loop type.

Both are sleep loops, so what matters is what a loop-bound caller cannot see:
the loop keeps running while they wait, no thread is started for an address
literal, a cancelled task leaves no socket and no task behind, and a deadline
bounds the whole wait. Loops are built directly, as in ``test_async_udp.py``:
on Windows the default is the Proactor loop and the selector loop is a
different mechanism for ``sock_connect``, so both are exercised.
"""

import asyncio
import functools
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

import netimps
from netimps import aretry, await_for_port, backoff_delays, bind, get_free_port

IS_WINDOWS = os.name == "nt"


def _loop_factories():
    factories = [("default", asyncio.new_event_loop)]
    if IS_WINDOWS:
        selector = getattr(asyncio, "SelectorEventLoop", None)
        proactor = getattr(asyncio, "ProactorEventLoop", None)
        if selector is not None:
            factories.append(("selector", selector))
        if proactor is not None:
            factories.append(("proactor", proactor))
    return factories


def _run(coro_factory, factory):
    loop = factory()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro_factory())
    finally:
        asyncio.set_event_loop(None)
        loop.close()


LOOPS = _loop_factories()
every_loop = pytest.mark.parametrize(
    "factory", [factory for _, factory in LOOPS], ids=[name for name, _ in LOOPS]
)


def _only_task():
    """True when nothing but the running task is left on the loop."""
    return asyncio.all_tasks() == {asyncio.current_task()}


def _threads():
    return {t.ident for t in threading.enumerate()}


@pytest.fixture
def closed_port():
    """A loopback port nothing listens on: a connect is refused at once."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def listener():
    server = bind("127.0.0.1", 0, kind=socket.SOCK_STREAM, listen=5)
    yield server.getsockname()[1]
    server.close()


# --------------------------------------------------------------------------- #
# aretry                                                                       #
# --------------------------------------------------------------------------- #


@every_loop
def test_aretry_returns_what_the_coroutine_returns(factory):
    async def body():
        async def call():
            return "ok"

        return await aretry(call)

    assert _run(body, factory) == "ok"


@every_loop
def test_aretry_waits_the_schedule_retry_would(factory):
    """The same delays as ``backoff_delays``, handed to ``on_retry`` and slept."""
    seen = []
    calls = []

    async def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise OSError("transient")
        return len(calls)

    async def body():
        started = time.monotonic()
        result = await aretry(
            flaky,
            attempts=4,
            delay=0.05,
            jitter=0.0,
            on_retry=lambda n, exc, wait: seen.append((n, type(exc), wait)),
        )
        return result, time.monotonic() - started

    result, elapsed = _run(body, factory)
    assert result == 3
    expected = list(backoff_delays(attempts=4, delay=0.05, jitter=0.0))
    assert seen == [(1, OSError, expected[0]), (2, OSError, expected[1])]
    assert elapsed >= expected[0] + expected[1] - 0.02


@every_loop
def test_aretry_reraises_the_last_error_unwrapped(factory):
    async def body():
        async def always():
            raise OSError("still broken")

        with pytest.raises(OSError, match="still broken"):
            await aretry(always, attempts=2, delay=0.0)

    _run(body, factory)


@every_loop
def test_aretry_does_not_retry_a_caller_bug(factory):
    calls = []

    async def body():
        async def bad():
            calls.append(1)
            raise ValueError("malformed")

        with pytest.raises(ValueError):
            await aretry(bad, attempts=5, delay=0.0)

    _run(body, factory)
    assert len(calls) == 1


@every_loop
def test_aretry_checks_its_arguments_before_calling(factory):
    calls = []

    async def body():
        async def call():
            calls.append(1)

        with pytest.raises(ValueError):
            await aretry(call, attempts=0)
        with pytest.raises(ValueError):
            await aretry(call, multiplier=0.5)

    _run(body, factory)
    assert calls == []


@every_loop
def test_aretry_refuses_a_callable_that_does_not_return_an_awaitable(factory):
    async def body():
        with pytest.raises(TypeError, match="awaitable"):
            await aretry(lambda: 1)

    _run(body, factory)


@every_loop
def test_the_loop_keeps_running_while_aretry_waits(factory):
    """The point of a coroutine: a sleep on a thread-less loop is not a stall."""
    ticks = []

    async def ticker():
        while True:
            ticks.append(1)
            await asyncio.sleep(0.01)

    async def body():
        tick = asyncio.ensure_future(ticker())
        before = _threads()
        calls = []

        async def flaky():
            calls.append(1)
            if len(calls) < 2:
                raise OSError("transient")

        await aretry(flaky, attempts=2, delay=0.3, jitter=0.0)
        during = _threads() - before
        tick.cancel()
        return during

    new_threads = _run(body, factory)
    assert len(ticks) >= 10, "the loop was blocked while aretry waited"
    assert new_threads == set()


@every_loop
def test_cancelling_aretry_during_its_wait_ends_it_at_once(factory):
    calls = []

    async def body():
        async def fails():
            calls.append(1)
            raise OSError("transient")

        task = asyncio.ensure_future(aretry(fails, attempts=5, delay=30.0, jitter=0.0))
        await asyncio.sleep(0.1)
        task.cancel()
        started = time.monotonic()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        return time.monotonic() - started, _only_task()

    elapsed, clean = _run(body, factory)
    assert elapsed < 1.0 and clean
    assert calls == [1], "a cancelled retry called again"


@every_loop
def test_cancelling_aretry_during_a_call_is_not_retried(factory):
    calls = []

    async def body():
        async def hangs():
            calls.append(1)
            await asyncio.sleep(3600)

        task = asyncio.ensure_future(aretry(hangs, attempts=5, delay=0.0))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return _only_task()

    assert _run(body, factory)
    assert calls == [1]


# --------------------------------------------------------------------------- #
# await_for_port                                                               #
# --------------------------------------------------------------------------- #


@every_loop
def test_await_for_port_is_true_for_a_listener_and_starts_no_thread(factory, listener):
    async def body():
        before = _threads()
        answer = await await_for_port("127.0.0.1", listener, deadline=5.0)
        return answer, _threads() - before, _only_task()

    answer, new_threads, clean = _run(body, factory)
    assert answer is True and new_threads == set() and clean


@every_loop
def test_await_for_port_reaches_ipv6_loopback(factory):
    try:
        server = bind("::1", 0, kind=socket.SOCK_STREAM, listen=5)
    except OSError:
        pytest.skip("this host has no IPv6 loopback")
    try:
        port = server.getsockname()[1]

        async def body():
            return await await_for_port("::1", port, deadline=5.0)

        assert _run(body, factory) is True
    finally:
        server.close()


@every_loop
def test_await_for_port_resolves_a_name(factory, listener):
    """``localhost`` resolves to ``::1`` first, where nothing listens and Windows
    takes about two seconds to refuse; the per-attempt ``timeout`` has to cover
    that, exactly as it must for ``wait_for_port``."""

    async def body():
        return await await_for_port("localhost", listener, deadline=10.0, timeout=5.0)

    assert _run(body, factory) is True


@every_loop
def test_await_for_port_is_false_for_a_refused_port_within_the_deadline(
    factory, closed_port
):
    async def body():
        started = time.monotonic()
        answer = await await_for_port(
            "127.0.0.1", closed_port, deadline=0.5, interval=0.05
        )
        return answer, time.monotonic() - started

    answer, elapsed = _run(body, factory)
    assert answer is False
    assert 0.4 <= elapsed < 0.5 + 1.0


@every_loop
def test_await_for_port_sees_a_service_that_comes_up_late(factory):
    port = get_free_port()
    holder = []

    async def body():
        async def start_later():
            await asyncio.sleep(0.4)
            holder.append(bind("127.0.0.1", port, kind=socket.SOCK_STREAM, listen=5))

        starter = asyncio.ensure_future(start_later())
        try:
            return await await_for_port("127.0.0.1", port, deadline=10.0, interval=0.05)
        finally:
            await starter

    try:
        assert _run(body, factory) is True
    finally:
        for server in holder:
            server.close()


@every_loop
def test_the_loop_keeps_running_while_await_for_port_waits(factory, closed_port):
    ticks = []

    async def body():
        async def ticker():
            while True:
                ticks.append(1)
                await asyncio.sleep(0.01)

        tick = asyncio.ensure_future(ticker())
        await await_for_port("127.0.0.1", closed_port, deadline=0.5, interval=0.2)
        tick.cancel()

    _run(body, factory)
    assert len(ticks) >= 20, "the loop was blocked while the port was awaited"


@every_loop
def test_an_out_of_range_port_raises_as_wait_for_port_does(factory):
    async def body():
        with pytest.raises(ValueError):
            await await_for_port("127.0.0.1", 70000, deadline=1.0)

    _run(body, factory)


def _hang_connect(loop, sockets):
    """Make every connect on ``loop`` hang, remembering each socket it was given."""

    async def hang(sock, address):
        sockets.append(sock)
        await asyncio.sleep(3600)

    loop.sock_connect = hang


@every_loop
def test_the_deadline_bounds_a_connect_that_never_answers(factory):
    """The wait ends at the deadline plus a second at most, with every socket closed."""
    sockets = []

    async def body():
        _hang_connect(asyncio.get_running_loop(), sockets)
        started = time.monotonic()
        answer = await await_for_port(
            "127.0.0.1", 9, deadline=0.6, timeout=30.0, interval=0.05
        )
        return answer, time.monotonic() - started, _only_task()

    answer, elapsed, clean = _run(body, factory)
    assert answer is False and clean
    assert elapsed < 0.6 + 1.0
    assert sockets and all(sock.fileno() == -1 for sock in sockets)


@every_loop
def test_cancelling_await_for_port_mid_connect_leaves_no_socket_and_no_task(factory):
    sockets = []

    async def body():
        _hang_connect(asyncio.get_running_loop(), sockets)
        task = asyncio.ensure_future(await_for_port("127.0.0.1", 9, deadline=60.0))
        await asyncio.sleep(0.2)
        assert sockets and sockets[0].fileno() != -1, "the connect was in progress"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        return _only_task()

    assert _run(body, factory)
    assert all(sock.fileno() == -1 for sock in sockets)


@every_loop
def test_cancelling_await_for_port_during_its_wait_leaves_no_task(factory, closed_port):
    async def body():
        task = asyncio.ensure_future(
            await_for_port("127.0.0.1", closed_port, deadline=60.0, interval=30.0)
        )
        await asyncio.sleep(0.3)
        task.cancel()
        started = time.monotonic()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        return time.monotonic() - started, _only_task()

    elapsed, clean = _run(body, factory)
    assert elapsed < 1.0 and clean


@every_loop
def test_await_for_port_keywords_are_wait_for_ports(factory):
    """``functools.partial`` is the form a caller hands to ``aretry``."""

    async def body():
        return await aretry(
            functools.partial(
                await_for_port, "127.0.0.1", 9, deadline=0.0, interval=0.01
            ),
            attempts=1,
        )

    assert _run(body, factory) is False


# --------------------------------------------------------------------------- #
# Import cost                                                                  #
# --------------------------------------------------------------------------- #


def test_the_coroutines_exist_without_asyncio_having_been_imported():
    """Defining a coroutine function imports nothing: asyncio arrives when one runs.

    A fresh interpreter, because pytest has already imported asyncio here.
    """
    code = (
        "import sys, netimps, inspect\n"
        "assert inspect.iscoroutinefunction(netimps.aretry)\n"
        "assert inspect.iscoroutinefunction(netimps.await_for_port)\n"
        "print('asyncio' in sys.modules)\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(path for path in sys.path if path)
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
