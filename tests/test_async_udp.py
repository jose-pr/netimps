"""`UDPEndpoint.arecv` / `.datagrams` on every asyncio loop type.

A **real loop** throughout, never a mock: the whole risk here is loop
integration, and the Windows default `ProactorEventLoop` has no `add_reader` at
all. Both loop types are exercised explicitly on Windows, because which one a
caller gets is the caller's choice -- some libraries require Proactor for
subprocesses -- so testing only the default would leave half the mechanism
unproven.

Loops are built directly rather than through `set_event_loop_policy`, which is
deprecated from 3.14 and slated for removal in 3.16.
"""

import asyncio
import os
import socket
import threading

import pytest

import netimps
from netimps import UDPEndpoint, bind

IS_WINDOWS = os.name == "nt"


def _loop_factories():
    """Every loop class worth testing on this platform, named."""
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
    """Run *coro_factory()* on a fresh loop from *factory*, then close it."""
    loop = factory()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro_factory())
    finally:
        asyncio.set_event_loop(None)
        loop.close()


LOOPS = _loop_factories()
LOOP_IDS = [name for name, _ in LOOPS]
LOOP_FACTORIES = [factory for _, factory in LOOPS]


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_arecv_delivers_a_datagram_with_pktinfo_on_every_loop(factory):
    """The point: ancillary data must survive, whichever loop is running.

    `ProactorEventLoop` raises `NotImplementedError` from `add_reader`, and its
    own `recvfrom` discards cmsgs -- so a naive async port would silently lose
    the arrival address on the Windows *default* loop.
    """

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        try:
            port = endpoint.socket.getsockname()[1]
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                task = asyncio.ensure_future(endpoint.arecv(1500))
                await asyncio.sleep(0.05)
                sender.sendto(b"payload", ("127.0.0.1", port))
                packet = await asyncio.wait_for(task, 10)
            finally:
                sender.close()
            return packet, endpoint.has_pktinfo
        finally:
            endpoint.close()

    packet, supports = _run(body, factory)
    assert packet.data == b"payload"
    assert packet.sender[0] == "127.0.0.1"
    assert packet.truncated is False
    if supports:
        assert packet.interface_index != 0, "the arrival interface was lost"
        assert packet.destination is not None


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_the_notifier_rearms_many_times(factory):
    """It must fire repeatedly, not once.

    `select` is level-triggered, so the thread path has to wait for each datagram
    to be consumed before selecting again -- get that wrong and this either spins
    a core or delivers exactly one packet.

    Deliberately a **ping-pong**: send one, await one, repeat. An earlier version
    fired 25 datagrams and then waited for all 25, which passed alone and timed
    out inside the full suite -- UDP is lossy by definition and a loaded run does
    overflow a default receive buffer, so requiring zero loss tested the host
    rather than the notifier. One in flight at a time removes the dependency
    without weakening what is being proven: 25 separate re-arms either happen or
    the test hangs.
    """
    rounds = 25

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        received = []
        try:
            port = endpoint.socket.getsockname()[1]
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for index in range(rounds):
                    task = asyncio.ensure_future(endpoint.arecv(1500))
                    await asyncio.sleep(0)
                    sender.sendto(b"n=%d" % index, ("127.0.0.1", port))
                    packet = await asyncio.wait_for(task, 10)
                    received.append(packet.data)
            finally:
                sender.close()
        finally:
            endpoint.close()
        return received

    received = _run(body, factory)
    assert received == [b"n=%d" % index for index in range(rounds)]


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_datagrams_is_an_async_iterator(factory):
    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        seen = []
        try:
            port = endpoint.socket.getsockname()[1]
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            async def drain():
                async for packet in endpoint.datagrams(1500):
                    seen.append(packet.data)
                    if len(seen) == 3:
                        return

            try:
                task = asyncio.ensure_future(drain())
                await asyncio.sleep(0.05)
                for index in range(3):
                    sender.sendto(b"i%d" % index, ("127.0.0.1", port))
                    # One at a time: three unacknowledged datagrams is little
                    # enough to be safe, but waiting costs nothing and makes the
                    # test independent of the receive buffer.
                    while len(seen) <= index and not task.done():
                        await asyncio.sleep(0.01)
                await asyncio.wait_for(task, 10)
            finally:
                sender.close()
        finally:
            endpoint.close()
        return seen

    assert _run(body, factory) == [b"i0", b"i1", b"i2"]


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_no_notifier_thread_survives_the_endpoint(factory):
    """On Windows the Proactor path owns a thread, and it must be joined.

    A leaked thread per endpoint is how a long-lived server quietly accumulates
    them, and a daemon thread will not keep the process alive to complain.
    """

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            task = asyncio.ensure_future(endpoint.arecv(1500))
            await asyncio.sleep(0.05)
            sender.sendto(b"x", ("127.0.0.1", port))
            await asyncio.wait_for(task, 10)
        finally:
            sender.close()
        endpoint.close()
        # Give a joined thread a moment to leave the enumeration.
        await asyncio.sleep(0.2)
        return [t.name for t in threading.enumerate() if "netimps-" in t.name]

    assert _run(body, factory) == []


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_a_closed_endpoint_refuses_to_start_a_notifier(factory):
    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        endpoint.close()
        with pytest.raises((RuntimeError, OSError, ValueError)):
            await endpoint.arecv(1500)

    _run(body, factory)


def test_arecv_does_not_disturb_the_synchronous_path():
    """The synchronous path is the one in use today; it must be untouched.

    Asserted by using both on one endpoint in one process: a timeout set before
    the first `arecv` is still the socket's timeout afterwards, and a
    synchronous `recv` still honours it.
    """

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        endpoint.socket.settimeout(5.0)
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            task = asyncio.ensure_future(endpoint.arecv(1500))
            await asyncio.sleep(0.05)
            sender.sendto(b"async", ("127.0.0.1", port))
            first = await asyncio.wait_for(task, 10)
            assert endpoint.socket.gettimeout() == 5.0
            # Now synchronously, on the same endpoint.
            sender.sendto(b"sync", ("127.0.0.1", port))
            second = endpoint.recv(1500)
        finally:
            sender.close()
            endpoint.close()
        return first.data, second.data

    assert _run(body, asyncio.new_event_loop) == (b"async", b"sync")


def test_netimps_does_not_import_asyncio():
    """`import netimps` must not pull asyncio in.

    Two reasons, and the first is not hypothetical: importing asyncio from
    `__init__` would force the import ordering that produced the `os.sysconf`
    crash earlier in this release. The second is that most of this package is
    value types, and a caller using those should not pay for an event-loop
    import.

    A fresh interpreter, because by the time a test body runs pytest has already
    imported asyncio itself.
    """
    import subprocess
    import sys

    code = (
        "import sys\n"
        "import netimps\n"
        "assert 'asyncio' not in sys.modules, "
        "'netimps imported asyncio at package import time'\n"
        "print('ok')\n"
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
    assert result.stdout.strip() == "ok"


@pytest.mark.skipif(not IS_WINDOWS, reason="add_reader exists on POSIX loops")
def test_the_proactor_loop_really_lacks_add_reader():
    """The premise of the whole design, pinned.

    If CPython ever gives Proactor an `add_reader`, the thread path becomes dead
    code and this test says so instead of it rotting unnoticed.
    """
    loop = asyncio.ProactorEventLoop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    try:
        with pytest.raises(NotImplementedError):
            loop.add_reader(sock.fileno(), lambda: None)
    finally:
        sock.close()
        loop.close()


# --------------------------------------------------------------------------- #
# Teardown and loop rebinding                                                 #
# --------------------------------------------------------------------------- #


def test_a_cancelled_arecv_unregisters_its_reader():
    """The most ordinary shutdown there is: cancel the receive task, then close.

    `_ready` unregisters only when it actually *fires*, so a task cancelled
    while awaiting used to leave the reader registered until the socket next
    became readable. Closing the socket first -- the usual order -- then leaves
    the loop polling a closed fd, and the selector raises on its next pass.

    Measured before the fix: `loop.remove_reader(fileno)` after a cancelled
    `arecv` returned **True**, meaning one was still registered. That return
    value is the assertion here, because it reports the leak directly rather
    than through a downstream symptom.
    """

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        fileno = endpoint.socket.fileno()
        try:
            task = asyncio.ensure_future(endpoint.arecv())
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            loop = asyncio.get_running_loop()
            # True would mean one was still registered.
            assert loop.remove_reader(fileno) is False
        finally:
            endpoint.close()

    selector = getattr(asyncio, "SelectorEventLoop", None)
    if selector is None:  # pragma: no cover - every supported platform has one
        pytest.skip("no SelectorEventLoop here")
    loop = selector()
    try:
        loop.run_until_complete(body())
    finally:
        loop.close()


def test_closing_the_socket_after_a_cancelled_arecv_is_quiet():
    """The symptom the leak caused, asserted end to end.

    A loop left watching a closed fd raises from the selector on its next poll,
    so the test is simply that the loop keeps running afterwards.
    """

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        task = asyncio.ensure_future(endpoint.arecv())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        endpoint.close()
        # Several passes through the selector with the socket already closed.
        for _ in range(5):
            await asyncio.sleep(0.01)
        return True

    selector = getattr(asyncio, "SelectorEventLoop", None)
    if selector is None:  # pragma: no cover - every supported platform has one
        pytest.skip("no SelectorEventLoop here")
    loop = selector()
    try:
        assert loop.run_until_complete(body()) is True
    finally:
        loop.close()


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_one_endpoint_can_be_served_by_two_successive_loops(factory):
    """`asyncio.run(serve())` twice, or a server stopped and restarted.

    The thread path captured its loop for the life of the thread, so the second
    loop got nothing and the thread died posting to a closed one. Measured
    before the fix on a `ProactorEventLoop`: the second exchange timed out while
    the daemon thread printed an unhandled "Event loop is closed" traceback to
    stderr -- a failure with no caller to report it to.

    Parametrised over both loop types because the selector path must keep
    working too; only the thread path had the bug, and only Windows defaults to
    the one with it.
    """
    endpoint = UDPEndpoint(bind("127.0.0.1", 0))
    port = endpoint.socket.getsockname()[1]

    async def one_exchange():
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            peer.sendto(b"ping", ("127.0.0.1", port))
        finally:
            peer.close()
        return (await asyncio.wait_for(endpoint.arecv(), timeout=5)).data

    try:
        for attempt in (1, 2):
            loop = factory()
            try:
                assert loop.run_until_complete(one_exchange()) == b"ping", attempt
            finally:
                loop.close()
    finally:
        endpoint.close()


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_rebinding_leaves_no_thread_behind(factory):
    """Retiring a thread must join it, not merely abandon it.

    A rebind that leaked a thread per loop would be a slow leak in exactly the
    shape that motivated the fix -- a server restarted repeatedly.
    """
    before = {t for t in threading.enumerate()}
    endpoint = UDPEndpoint(bind("127.0.0.1", 0))
    port = endpoint.socket.getsockname()[1]

    async def one_exchange():
        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            peer.sendto(b"ping", ("127.0.0.1", port))
        finally:
            peer.close()
        await asyncio.wait_for(endpoint.arecv(), timeout=5)

    try:
        for _ in range(3):
            loop = factory()
            try:
                loop.run_until_complete(one_exchange())
            finally:
                loop.close()
    finally:
        endpoint.close()

    leaked = [
        t
        for t in threading.enumerate()
        if t not in before and t.name == "netimps-readnotify" and t.is_alive()
    ]
    assert leaked == []


def _notifier_threads():
    return [t.name for t in threading.enumerate() if "netimps-" in t.name]


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_async_with_leaves_no_thread_behind(factory):
    """`async with` closes the endpoint, and the reader thread is gone on exit.

    No sleep between the exit and the check: `close()` joins the thread, and
    `aclose()` must wait for it too, so an endpoint that was awaited on never
    leaves the thread to be reaped later. On a Proactor loop the thread exists
    only because `arecv` started it, which is why the endpoint receives first.
    """

    async def body():
        sock = bind("127.0.0.1", 0)
        port = sock.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            async with UDPEndpoint(sock) as endpoint:
                task = asyncio.ensure_future(endpoint.arecv(1500))
                await asyncio.sleep(0.05)
                sender.sendto(b"x", ("127.0.0.1", port))
                packet = await asyncio.wait_for(task, 10)
        finally:
            sender.close()
        return packet.data, sock.fileno(), _notifier_threads()

    data, fileno, threads = _run(body, factory)
    assert data == b"x"
    assert fileno == -1, "the socket must be closed on exit"
    assert threads == []


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_async_with_closes_after_a_cancelled_arecv(factory):
    """The ordinary shutdown: cancel the receive task, leave the block."""

    async def body():
        async with UDPEndpoint(bind("127.0.0.1", 0)) as endpoint:
            task = asyncio.ensure_future(endpoint.arecv(1500))
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        return _notifier_threads()

    assert _run(body, factory) == []


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_close_and_aclose_are_complete_and_harmless_twice(factory):
    """Each is complete on return, and any order of repeats is a no-op."""

    async def body():
        results = []
        for first, second in (
            ("aclose", "aclose"),
            ("close", "close"),
            ("close", "aclose"),
            ("aclose", "close"),
        ):
            endpoint = UDPEndpoint(bind("127.0.0.1", 0))
            port = endpoint.socket.getsockname()[1]
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                task = asyncio.ensure_future(endpoint.arecv(1500))
                await asyncio.sleep(0.05)
                sender.sendto(b"x", ("127.0.0.1", port))
                await asyncio.wait_for(task, 10)
            finally:
                sender.close()
            for name in (first, second):
                outcome = getattr(endpoint, name)()
                if asyncio.iscoroutine(outcome):
                    await outcome
                # Complete on return: the socket is closed and the thread gone.
                results.append((name, endpoint.socket.fileno(), _notifier_threads()))
        return results

    for name, fileno, threads in _run(body, factory):
        assert fileno == -1, "%s left the socket open" % name
        assert threads == [], "%s left the reader thread running" % name


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_aclose_on_an_endpoint_that_never_awaited(factory):
    """No notifier was ever made, so only the socket is left to close."""

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        await endpoint.aclose()
        return endpoint.socket.fileno()

    assert _run(body, factory) == -1


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_aclose_waits_for_the_thread_without_blocking_the_loop(factory):
    """A slow-to-leave thread is waited for, and other tasks run meanwhile.

    `close()` joins on the calling thread, which from a coroutine freezes every
    other task for as long as the thread takes. The reader thread leaves in
    microseconds, so a stand-in that stays alive for 50 ms is what makes the
    wait observable: `aclose()` must outlast it, and a ticker task must keep
    advancing while it does.
    """
    import time

    from netimps._udp._notifier import ReadNotifier

    class SlowThread:
        def __init__(self):
            self.until = time.monotonic() + 0.05

        def is_alive(self):
            return time.monotonic() < self.until

        def join(self, timeout=None):  # pragma: no cover - aclose must not call it
            raise AssertionError("aclose() blocked on join()")

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        notifier = ReadNotifier(endpoint.socket)
        notifier_thread = notifier._thread = SlowThread()
        endpoint._notifier = notifier
        ticks = []

        async def ticker():
            while True:
                ticks.append(1)
                await asyncio.sleep(0)

        watcher = asyncio.ensure_future(ticker())
        await asyncio.sleep(0)
        await endpoint.aclose()
        # Judged by the stand-in's own clock reading: the 50 ms began when it
        # was built, a little before this coroutine could start a timer.
        outlasted = not notifier_thread.is_alive()
        watcher.cancel()
        with pytest.raises(asyncio.CancelledError):
            await watcher
        return outlasted, len(ticks), endpoint.socket.fileno()

    outlasted, ticks, fileno = _run(body, factory)
    assert outlasted, "aclose() returned before the thread had left"
    assert ticks > 3, "the loop was blocked while aclose() waited"
    assert fileno == -1


# --------------------------------------------------------------------------- #
# Closing under a pending receive, and the socket's mode                      #
# --------------------------------------------------------------------------- #


def _registered_readers(loop, fileno):
    """Whether *loop* still watches *fileno*, asked of the loop itself.

    ``remove_reader`` answers True exactly when a reader was registered, and
    removing it is the cleanup. Proactor loops have no readers to ask about.
    """
    try:
        return bool(loop.remove_reader(fileno))
    except NotImplementedError:
        return False


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_close_then_cancel_leaves_the_loop_usable_and_no_reader(factory):
    """Close under a pending `arecv`, then cancel the task: the loop survives.

    The reader used to be removed by the socket's *current* descriptor, which is
    -1 once the socket is closed, so the original stayed registered. A selector
    loop then polled a closed socket and died with ``WinError 10038`` out of
    ``run_until_complete``; elsewhere the next socket to reuse the descriptor
    number received nothing.
    """

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        fileno = endpoint.socket.fileno()
        task = asyncio.ensure_future(endpoint.arecv())
        await asyncio.sleep(0.1)
        endpoint.close()
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, RuntimeError):
            pass
        for _ in range(3):
            await asyncio.sleep(0.02)
        return fileno, _registered_readers(asyncio.get_running_loop(), fileno)

    loop = factory()
    try:
        asyncio.set_event_loop(loop)
        fileno, leaked = loop.run_until_complete(asyncio.wait_for(body(), 10))
    finally:
        asyncio.set_event_loop(None)
        loop.close()
    assert leaked is False
    assert _notifier_threads() == []


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_cancel_then_close_leaves_no_reader(factory):
    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        fileno = endpoint.socket.fileno()
        task = asyncio.ensure_future(endpoint.arecv())
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await endpoint.aclose()
        for _ in range(3):
            await asyncio.sleep(0.02)
        return _registered_readers(asyncio.get_running_loop(), fileno)

    assert _run(lambda: asyncio.wait_for(body(), 10), factory) is False
    assert _notifier_threads() == []


@pytest.mark.parametrize("closer", ["close", "aclose"])
@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_closing_from_another_task_ends_a_pending_arecv(factory, closer):
    """A task awaiting `arecv` gets what a closed endpoint raises, promptly."""

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        task = asyncio.ensure_future(endpoint.arecv())
        await asyncio.sleep(0.1)
        started = asyncio.get_running_loop().time()
        outcome = getattr(endpoint, closer)()
        if asyncio.iscoroutine(outcome):
            await outcome
        with pytest.raises(RuntimeError):
            await asyncio.wait_for(task, 0.5)
        return asyncio.get_running_loop().time() - started

    assert _run(body, factory) < 0.5
    assert _notifier_threads() == []


@pytest.mark.parametrize("closer", ["close", "aclose"])
@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_closing_from_another_task_ends_datagrams(factory, closer):
    """`async for` over `datagrams()` finishes within 0.5 s of the close."""

    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        seen = []

        async def drain():
            async for packet in endpoint.datagrams():
                seen.append(packet)

        task = asyncio.ensure_future(drain())
        await asyncio.sleep(0.1)
        outcome = getattr(endpoint, closer)()
        if asyncio.iscoroutine(outcome):
            await outcome
        await asyncio.wait_for(task, 0.5)
        return seen

    assert _run(body, factory) == []
    assert _notifier_threads() == []


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_arecv_leaves_the_sockets_timeout_alone(factory):
    """One `arecv` must not change the mode the synchronous half relies on.

    The socket's timeout was 5.0 before and 0.0 after, so the next `recv` with
    nothing queued raised `BlockingIOError` at once instead of waiting.
    """

    async def body():
        sock = bind("127.0.0.1", 0)
        sock.settimeout(0.4)
        endpoint = UDPEndpoint(sock)
        port = sock.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            task = asyncio.ensure_future(endpoint.arecv(1500))
            await asyncio.sleep(0.05)
            sender.sendto(b"async", ("127.0.0.1", port))
            first = await asyncio.wait_for(task, 10)
            after = sock.gettimeout()
            started = asyncio.get_running_loop().time()
            with pytest.raises(TimeoutError):
                endpoint.recv(1500)
            waited = asyncio.get_running_loop().time() - started
        finally:
            sender.close()
            endpoint.close()
        return first.data, after, waited

    data, after, waited = _run(body, factory)
    assert data == b"async"
    assert after == 0.4
    assert waited >= 0.3, "recv returned at once: the socket was left non-blocking"


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_a_blocking_socket_stays_blocking_after_arecv(factory):
    async def body():
        sock = bind("127.0.0.1", 0)
        sock.settimeout(None)
        endpoint = UDPEndpoint(sock)
        port = sock.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            task = asyncio.ensure_future(endpoint.arecv(1500))
            await asyncio.sleep(0.05)
            sender.sendto(b"x", ("127.0.0.1", port))
            await asyncio.wait_for(task, 10)
            return sock.gettimeout()
        finally:
            sender.close()
            endpoint.close()

    assert _run(body, factory) is None


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_asend_delivers_and_leaves_the_timeout_alone(factory):
    async def body():
        receiver = bind("127.0.0.1", 0)
        receiver.settimeout(5)
        sock = bind("127.0.0.1", 0)
        sock.settimeout(3.0)
        endpoint = UDPEndpoint(sock)
        try:
            port = receiver.getsockname()[1]
            sent = await endpoint.asend(b"hello", "127.0.0.1", port, src="127.0.0.1")
            plain = await endpoint.asend(b"hi", "127.0.0.1", port)
            got = [receiver.recvfrom(100)[0], receiver.recvfrom(100)[0]]
            return sent, plain, got, sock.gettimeout()
        finally:
            endpoint.close()
            receiver.close()

    assert _run(body, factory) == (5, 2, [b"hello", b"hi"], 3.0)


@pytest.mark.parametrize("factory", LOOP_FACTORIES, ids=LOOP_IDS)
def test_asend_waits_for_writability_when_the_buffer_is_full(factory, monkeypatch):
    """A send the kernel refuses with EWOULDBLOCK is retried once writable.

    A full UDP send buffer cannot be produced on loopback on demand, so the
    refusal is raised from the one call `asend` makes; the wait it then does is
    the real one, on the real socket.
    """
    calls = []
    real = UDPEndpoint.send

    def refuse_once(self, *args, **kwargs):
        calls.append(self.socket.gettimeout())
        if len(calls) == 1:
            raise BlockingIOError()
        return real(self, *args, **kwargs)

    monkeypatch.setattr(UDPEndpoint, "send", refuse_once)

    async def body():
        receiver = bind("127.0.0.1", 0)
        receiver.settimeout(5)
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        try:
            sent = await endpoint.asend(b"x", "127.0.0.1", receiver.getsockname()[1])
            return sent, receiver.recvfrom(10)[0], endpoint.socket.gettimeout()
        finally:
            endpoint.close()
            receiver.close()

    assert _run(body, factory) == (1, b"x", None)
    assert calls == [0.0, 0.0]


def test_asend_on_a_closed_endpoint_raises():
    async def body():
        endpoint = UDPEndpoint(bind("127.0.0.1", 0))
        endpoint.close()
        with pytest.raises(RuntimeError):
            await endpoint.asend(b"x", "127.0.0.1", 9)

    _run(body, asyncio.new_event_loop)
