"""`retry`, `backoff_delays` and `Backoff`: bounded retry with exponential back-off."""

import pytest

import netimps

# Private: the sleep and jitter seams are patched so no test waits.
from netimps import Backoff, _retry, backoff_delays, retry

# --------------------------------------------------------------------------- #
# retry / backoff_delays                                                      #
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    """Nothing here waits: a test that wants the waits records them itself."""
    monkeypatch.setattr(_retry, "_sleep", lambda _: None)


def test_retry_returns_on_first_success():
    calls = []
    assert retry(lambda: calls.append(1) or "ok") == "ok"
    assert len(calls) == 1


def test_retry_recovers_after_transient_failures():
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise OSError("transient")
        return "ok"

    assert retry(flaky, attempts=5) == "ok"
    assert len(calls) == 3


def test_retry_reraises_the_last_error_unwrapped():
    """The traceback must still point at the real problem."""

    def always_fails():
        raise OSError("still broken")

    with pytest.raises(OSError, match="still broken"):
        retry(always_fails, attempts=3)


def test_retry_does_not_retry_caller_bugs():
    calls = []

    def bad_call():
        calls.append(1)
        raise ValueError("malformed")

    with pytest.raises(ValueError):
        retry(bad_call, attempts=5)
    assert len(calls) == 1, "a ValueError will fail identically next time"


def test_retry_attempts_counts_total_calls():
    calls = []

    def failing():
        calls.append(1)
        raise OSError("no")

    with pytest.raises(OSError):
        retry(failing, attempts=1)
    assert len(calls) == 1, "attempts=1 means one call and no sleeping"


def test_retry_sleeps_with_growing_delays(monkeypatch):
    slept = []
    monkeypatch.setattr(_retry, "_sleep", slept.append)

    def failing():
        raise OSError("no")

    with pytest.raises(OSError):
        retry(
            failing,
            attempts=4,
            delay=1.0,
            multiplier=2.0,
            jitter=0,
        )
    assert slept == [1.0, 2.0, 4.0]


def test_retry_reports_each_attempt():
    seen = []

    def failing():
        raise OSError("no")

    with pytest.raises(OSError):
        retry(
            failing,
            attempts=3,
            delay=0.5,
            jitter=0,
            on_retry=lambda n, exc, wait: seen.append((n, wait)),
        )
    assert seen == [(1, 0.5), (2, 1.0)]


def test_backoff_delays_are_capped():
    delays = list(
        backoff_delays(attempts=8, delay=1.0, multiplier=10.0, max_delay=5.0, jitter=0)
    )
    assert max(delays) == 5.0
    assert len(delays) == 7  # attempts - 1


def test_backoff_jitter_only_shortens(monkeypatch):
    """Jitter must never push a delay past max_delay."""
    monkeypatch.setattr(_retry, "_random", lambda: 1.0)
    delays = list(
        backoff_delays(
            attempts=6,
            delay=4.0,
            multiplier=1.0,
            max_delay=4.0,
            jitter=0.5,
        )
    )
    assert all(0 <= d <= 4.0 for d in delays)
    assert all(d == pytest.approx(2.0) for d in delays)


@pytest.mark.parametrize(
    "kwargs",
    [{"attempts": 0}, {"delay": -1}, {"jitter": 1.5}, {"jitter": -0.1}],
)
def test_backoff_rejects_nonsense(kwargs):
    with pytest.raises(ValueError):
        list(backoff_delays(**kwargs))


# --------------------------------------------------------------------------- #
# The two symmetric jitter modes, and the stateful Backoff timer              #
# --------------------------------------------------------------------------- #


def _seeded(seed=42):
    import random

    return random.Random(seed).random


def _old_schedule(attempts, delay, multiplier, max_delay, jitter, rand):
    """Verbatim copy of the pre-change loop, to pin the default schedule."""
    current = delay
    for _ in range(attempts - 1):
        capped = min(current, max_delay)
        if jitter:
            capped -= capped * jitter * rand()
        yield capped
        current *= multiplier


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(attempts=5, delay=0.5, multiplier=2.0, max_delay=30.0, jitter=0.1),
        dict(attempts=8, delay=1.0, multiplier=3.0, max_delay=10.0, jitter=0.5),
        dict(attempts=4, delay=0.25, multiplier=2.0, max_delay=30.0, jitter=0.0),
        dict(attempts=1, delay=1.0, multiplier=2.0, max_delay=5.0, jitter=0.1),
    ],
)
def test_the_default_schedule_is_unchanged(kwargs, monkeypatch):
    """Adding the modes must not have moved the default by a float.

    Asserted against a copy of the old loop rather than against recorded
    numbers, so it keeps meaning something if the defaults are ever retuned --
    and including the `jitter=0` case, which must still draw no randomness.
    """
    monkeypatch.setattr(_retry, "_random", _seeded())
    assert list(backoff_delays(**kwargs)) == list(
        _old_schedule(rand=_seeded(), **kwargs)
    )


def test_jitter_seconds_is_absolute_and_spreads_both_ways(monkeypatch):
    """RFC 2131 §4.1: "randomized by the value of a uniform random number
    chosen from the range -1 to +1" -- seconds, not a fraction.

    The default mode can only ever *shorten*, so a DHCPv4 client could not use
    it, so neither DHCP standard could be expressed with it. Both signs
    occurring is the whole assertion; a mean near zero is the second half.
    """
    monkeypatch.setattr(_retry, "_random", _seeded(1))
    deltas = [
        value - 10.0
        for value in backoff_delays(
            attempts=401,
            delay=10.0,
            multiplier=1.0,
            max_delay=1000.0,
            jitter_seconds=1.0,
        )
    ]
    assert any(d > 0 for d in deltas), "never longer -- not symmetric"
    assert any(d < 0 for d in deltas), "never shorter"
    assert all(-1.0 <= d <= 1.0 for d in deltas), (min(deltas), max(deltas))
    assert abs(sum(deltas) / len(deltas)) < 0.1


def test_symmetric_makes_the_fractional_jitter_two_sided(monkeypatch):
    """RFC 8415 §15: `RT = 2*RTprev + RAND*RTprev`, RAND uniform in [-0.1, +0.1]."""
    monkeypatch.setattr(_retry, "_random", _seeded(3))
    fractions = [
        value / 10.0 - 1.0
        for value in backoff_delays(
            attempts=401,
            delay=10.0,
            multiplier=1.0,
            max_delay=1000.0,
            jitter=0.1,
            symmetric=True,
        )
    ]
    assert any(f > 0 for f in fractions)
    assert any(f < 0 for f in fractions)
    assert all(-0.1 <= f <= 0.1 for f in fractions), (min(fractions), max(fractions))
    assert abs(sum(fractions) / len(fractions)) < 0.01


def test_a_symmetric_delay_may_exceed_max_delay_because_the_rfcs_say_so(
    monkeypatch,
):
    """**The one place this diverges from the default mode's contract.**

    RFC 8415 applies its jitter *after* the cap -- `if RT > MRT: RT = MRT +
    RAND*MRT` -- and RFC 2131 randomises +/-1 s around its 64 s maximum. So in
    the symmetric modes `max_delay` caps the **base**, not the result.

    Clamping instead was the obvious reading, and it is wrong in a way that is
    invisible: measured, the spread *at the cap* became entirely negative with a
    mean of -0.024 rather than ~0, because every positive excursion was trimmed
    back to the ceiling. A backed-off client spends nearly all its time at the
    cap, so that is precisely where the symmetry has to survive -- clamping
    would silently reintroduce the synchronisation the mode is chosen to
    prevent.
    """
    monkeypatch.setattr(_retry, "_random", _seeded(7))
    values = list(
        backoff_delays(
            attempts=200,
            delay=64.0,
            multiplier=2.0,
            max_delay=64.0,
            jitter_seconds=1.0,
        )
    )
    assert any(v > 64.0 for v in values), "clamped at the cap -- symmetry lost"
    assert all(v <= 65.0 for v in values), max(values)
    assert all(v >= 0.0 for v in values)


def test_the_default_mode_still_treats_max_delay_as_a_hard_ceiling(
    monkeypatch,
):
    """The divergence above must not have leaked into the default."""
    monkeypatch.setattr(_retry, "_random", _seeded(11))
    values = list(
        backoff_delays(
            attempts=300,
            delay=1.0,
            multiplier=2.0,
            max_delay=5.0,
            jitter=0.1,
        )
    )
    assert all(0.0 <= v <= 5.0 for v in values), (min(values), max(values))


def test_no_mode_can_produce_a_negative_delay(monkeypatch):
    """A negative sleep is the failure the clamp at zero exists for."""
    for kwargs in (
        dict(jitter_seconds=100.0),
        dict(jitter=1.0, symmetric=True),
        dict(jitter=1.0),
    ):
        monkeypatch.setattr(_retry, "_random", _seeded(5))
        values = list(
            backoff_delays(
                attempts=200,
                delay=0.05,
                multiplier=1.0,
                max_delay=1000.0,
                **kwargs,
            )
        )
        assert all(v >= 0.0 for v in values), (kwargs, min(values))


def test_an_absolute_amplitude_is_capped_at_the_delay(monkeypatch):
    """Otherwise a sub-second delay loses its distribution entirely.

    With `delay=0.1` and a requested +/-1 s, an uncapped draw is negative about
    45% of the time and clamping at zero would pile all of that on a single
    value -- neither symmetric nor uniform, which is a silently wrong schedule
    rather than a refused one. Capping the amplitude at the delay keeps it
    both. For RFC 2131's real schedule the cap never engages: it starts at 4 s
    against a 1 s amplitude.
    """
    monkeypatch.setattr(_retry, "_random", _seeded(5))
    values = list(
        backoff_delays(
            attempts=201,
            delay=0.1,
            multiplier=1.0,
            max_delay=1000.0,
            jitter_seconds=1.0,
        )
    )
    assert all(0.0 <= v <= 0.2 + 1e-12 for v in values), (min(values), max(values))
    assert sum(1 for v in values if v == 0.0) == 0


def test_jitter_seconds_must_be_non_negative():
    with pytest.raises(ValueError, match="jitter_seconds"):
        list(backoff_delays(jitter_seconds=-1.0))


def test_retry_passes_the_new_modes_through(monkeypatch):
    """`retry` shares the schedule, so the modes have to reach it."""
    waits = []
    calls = []
    monkeypatch.setattr(_retry, "_sleep", waits.append)
    monkeypatch.setattr(_retry, "_random", _seeded(1))

    def flaky():
        calls.append(1)
        raise OSError("nope")

    with pytest.raises(OSError):
        netimps.retry(
            flaky,
            attempts=4,
            delay=10.0,
            multiplier=1.0,
            max_delay=1000.0,
            jitter_seconds=1.0,
        )
    assert len(calls) == 4
    assert all(9.0 <= w <= 11.0 for w in waits), waits


# --- Backoff: the stateful timer ------------------------------------------- #


def test_backoff_grows_on_advance_and_resets_on_progress():
    """The shape `backoff_delays` cannot express, and which every protocol
    client here had hand-rolled: a retransmission timer.

    A retransmission timer doubles to a ceiling on loss and returns to the base
    the moment the peer moves the transfer forward.
    """
    timer = Backoff(delay=1.0, multiplier=2.0, max_delay=8.0)
    assert timer.delay == 1.0
    assert timer.attempt == 0
    assert [timer.advance() for _ in range(5)] == [2.0, 4.0, 8.0, 8.0, 8.0]
    assert timer.attempt == 5
    assert timer.reset() == 1.0
    assert timer.attempt == 0
    assert timer.delay == 1.0


def test_backoff_delay_is_stable_between_advances(monkeypatch):
    """Arming a deadline, logging it and comparing against it must see one
    value. A property that re-jittered per read would be a trap for exactly
    the code this exists for.
    """
    monkeypatch.setattr(_retry, "_random", _seeded())
    timer = Backoff(delay=1.0, jitter=0.5, max_delay=30.0)
    first = timer.delay
    # Repeated reads must not re-draw.
    assert [timer.delay for _ in range(10)] == [first] * 10
    timer.advance()
    second = timer.delay
    assert [timer.delay for _ in range(10)] == [second] * 10
    # And the step really moved: the base doubled, so even with jitter the new
    # value cannot still be in the old step's range.
    assert second > first


def test_backoff_refuses_a_multiplier_that_would_shrink_the_wait():
    """A multiplier below 1 would make a session retransmit *faster* the worse
    the link got, which is always a bug; it is refused when the timer is built."""
    with pytest.raises(ValueError, match="multiplier"):
        Backoff(delay=1.0, multiplier=0.5, max_delay=8.0)
    timer = Backoff(delay=1.0, multiplier=1.0, max_delay=8.0)
    assert [timer.delay, timer.advance(), timer.advance()] == [1.0, 1.0, 1.0]


def test_backoff_refuses_a_ceiling_below_the_base():
    """`max_delay` under `delay` would shorten the very first wait below what
    the caller asked for, so it is refused rather than applied or floored."""
    with pytest.raises(ValueError, match="max_delay"):
        Backoff(delay=4.0, multiplier=2.0, max_delay=1.0)


def test_backoff_jitter_is_off_by_default_unlike_backoff_delays():
    """Deliberately the opposite default.

    Jitter desynchronises many clients retrying together; a point-to-point
    session retransmitting to one peer has no herd to avoid, and TFTP and TCP
    both specify plain doubling.
    """
    timer = Backoff(delay=1.0, multiplier=2.0, max_delay=100.0)
    assert [timer.delay, timer.advance(), timer.advance()] == [1.0, 2.0, 4.0]


def test_backoff_accepts_the_symmetric_modes_too(monkeypatch):
    """A DHCP client wants the timer *and* the RFC jitter."""
    monkeypatch.setattr(_retry, "_random", _seeded(9))
    timer = Backoff(
        delay=4.0,
        multiplier=2.0,
        max_delay=64.0,
        jitter_seconds=1.0,
    )
    seen = [timer.delay] + [timer.advance() for _ in range(6)]
    for value, base in zip(seen, [4, 8, 16, 32, 64, 64, 64]):
        assert abs(value - base) <= 1.0, (value, base)


def test_backoff_rejects_nonsense_arguments():
    with pytest.raises(ValueError, match="delay"):
        Backoff(delay=-1.0)
    with pytest.raises(ValueError, match="jitter"):
        Backoff(jitter=2.0)
    with pytest.raises(ValueError, match="jitter_seconds"):
        Backoff(jitter_seconds=-0.5)


def test_backoff_repr_is_useful_in_a_log():
    timer = Backoff(delay=1.0, multiplier=2.0, max_delay=8.0)
    timer.advance()
    text = repr(timer)
    assert "Backoff(" in text and "attempt=1" in text


# --------------------------------------------------------------------------- #
# retry, backoff_delays and Backoff: one rule set, checked when it is passed  #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "arguments",
    [
        dict(multiplier=0.5),
        dict(multiplier=-2),
        dict(delay=-1.0),
        dict(delay=4.0, max_delay=1.0),
        dict(jitter=2.0),
        dict(jitter_seconds=-1.0),
        dict(delay=float("nan")),
    ],
)
def test_the_three_entry_points_refuse_the_same_arguments(arguments):
    """``backoff_delays`` was lazy, so a bad argument surfaced at the first
    ``next()``; ``Backoff`` silently floored what the other two accepted."""
    with pytest.raises(ValueError):
        netimps.backoff_delays(3, **arguments)
    with pytest.raises(ValueError):
        netimps.Backoff(**arguments)
    called = []
    with pytest.raises(ValueError):
        netimps.retry(lambda: called.append(1), **arguments)
    assert called == []


@pytest.mark.parametrize("attempts", [0, -1])
def test_attempts_below_one_raise_when_passed(attempts):
    with pytest.raises(ValueError, match="attempts"):
        netimps.backoff_delays(attempts)
    called = []
    with pytest.raises(ValueError, match="attempts"):
        netimps.retry(lambda: called.append(1), attempts)
    assert called == []


def test_backoff_delays_and_backoff_agree_on_every_valid_schedule():
    for delay, multiplier, ceiling in [
        (1.0, 2.0, 8.0),
        (4.0, 1.0, 4.0),
        (0.5, 3.0, 30.0),
    ]:
        schedule = list(
            netimps.backoff_delays(
                6, delay, multiplier=multiplier, max_delay=ceiling, jitter=0
            )
        )
        timer = netimps.Backoff(delay, multiplier=multiplier, max_delay=ceiling)
        seen = [timer.delay]
        for _ in range(4):
            seen.append(timer.advance())
        assert seen == schedule


def test_a_multiplier_of_one_is_a_constant_delay():
    assert list(netimps.backoff_delays(4, 2.0, multiplier=1.0, jitter=0)) == [2.0] * 3


def test_retry_hooks_are_annotated():
    import inspect

    # Private: the sleep and jitter seams are patched so no test waits.
    from netimps import _retry

    assert "_sleep" in _retry.__annotations__
    assert "_random" in _retry.__annotations__
    assert inspect.signature(netimps.retry).return_annotation != "Any"
