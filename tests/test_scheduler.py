from src.wazuh_health.scheduler import Job, Scheduler


class _FakeClock:
    def __init__(self, start=0.0):
        self._t = start
    def time(self): return self._t
    def advance(self, s): self._t += s


def test_scheduler_runs_due_jobs_in_order():
    clock = _FakeClock()
    calls = []
    sched = Scheduler(clock=clock, jitter_seconds=0)
    sched.add(Job(name="a", interval_seconds=10, callback=lambda: calls.append("a")))
    sched.add(Job(name="b", interval_seconds=20, callback=lambda: calls.append("b")))
    sched.tick()
    clock.advance(11)
    sched.tick()
    clock.advance(11)
    sched.tick()
    assert calls.count("a") == 3
    assert calls.count("b") == 1


def test_scheduler_skips_not_due_jobs():
    clock = _FakeClock()
    calls = []
    sched = Scheduler(clock=clock, jitter_seconds=0)
    sched.add(Job(name="x", interval_seconds=60, callback=lambda: calls.append(1)))
    sched.tick()
    clock.advance(5)
    sched.tick()
    assert len(calls) == 1
