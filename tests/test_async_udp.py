"""`UdpEndpoint.arecv` / `.datagrams` on every asyncio loop type.

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
from netimps import UdpEndpoint, bind

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
        endpoint = UdpEndpoint(bind("127.0.0.1", 0))
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
            return packet, endpoint.supports_pktinfo
        finally:
            endpoint.close()

    packet, supports = _run(body, factory)
    assert packet.data == b"payload"
    assert packet.sender[0] == "127.0.0.1"
    assert packet.truncated is False
    if supports:
        assert packet.interface_index != 0, "the arrival interface was lost"
        assert packet.local_address is not None


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
        endpoint = UdpEndpoint(bind("127.0.0.1", 0))
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
        endpoint = UdpEndpoint(bind("127.0.0.1", 0))
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
        endpoint = UdpEndpoint(bind("127.0.0.1", 0))
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
        endpoint = UdpEndpoint(bind("127.0.0.1", 0))
        endpoint.close()
        with pytest.raises((RuntimeError, OSError, ValueError)):
            await endpoint.arecv(1500)

    _run(body, factory)


def test_arecv_does_not_disturb_the_synchronous_path():
    """`recv()` is what pydhcp and pytftp use today; it must be untouched.

    Asserted by using both on one endpoint in one process: the async path sets
    the socket non-blocking, which a synchronous `recv` with a timeout has to
    keep tolerating.
    """

    async def body():
        endpoint = UdpEndpoint(bind("127.0.0.1", 0))
        port = endpoint.socket.getsockname()[1]
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            task = asyncio.ensure_future(endpoint.arecv(1500))
            await asyncio.sleep(0.05)
            sender.sendto(b"async", ("127.0.0.1", port))
            first = await asyncio.wait_for(task, 10)
            # Now synchronously, on the same endpoint.
            endpoint.socket.settimeout(5.0)
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
    value types, and a consumer using those should not pay for an event-loop
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
# Teardown and loop rebinding -- both found by a consumer reading the code     #
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
        endpoint = UdpEndpoint(bind("127.0.0.1", 0))
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
        endpoint = UdpEndpoint(bind("127.0.0.1", 0))
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
    endpoint = UdpEndpoint(bind("127.0.0.1", 0))
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
    endpoint = UdpEndpoint(bind("127.0.0.1", 0))
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
