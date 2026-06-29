"""Tests for the engagement engine: budget, loop detector, tracer, and the run loop."""
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[3] / "engine"
sys.path.insert(0, str(ENGINE))

import budget as bd           # noqa: E402
import loop_detector as ld    # noqa: E402
import tracer as tr           # noqa: E402
import engine as eng          # noqa: E402


def clk():
    box = {"t": 0.0}
    return box, (lambda: box["t"])


# --------------------------------------------------------- budget
def test_budget_step_cap():
    box, c = clk()
    b = bd.Budget(max_steps=3, max_seconds=1e9, min_steps=1, clock=c)
    for _ in range(3):
        assert b.exhausted()[0] is False
        b.tick()
    assert b.exhausted()[0] is True and "step budget" in b.exhausted()[1]


def test_budget_time_cap():
    box, c = clk()
    b = bd.Budget(max_steps=1000, max_seconds=60, min_steps=0, clock=c)
    assert b.exhausted()[0] is False
    box["t"] = 61
    assert b.exhausted()[0] is True and "time budget" in b.exhausted()[1]


def test_budget_min_steps_gates_finish():
    box, c = clk()
    b = bd.Budget(min_steps=3, clock=c)
    assert b.can_finish() is False
    for _ in range(3):
        b.tick()
    assert b.can_finish() is True


# --------------------------------------------------------- loop detector
def test_loop_detector_trips_at_max_repeats():
    d = ld.LoopDetector(window=12, max_repeats=3)
    assert d.observe("a") is False
    assert d.observe("a") is False
    assert d.observe("a") is True            # 3rd time
    assert d.observe("b") is False


def test_loop_detector_window_evicts():
    d = ld.LoopDetector(window=3, max_repeats=3)
    d.observe("a"); d.observe("x"); d.observe("y")  # 'a' about to fall out of window
    assert d.observe("a") is False           # only 1 'a' in the 3-wide window now
    assert d.count("a") == 1


# --------------------------------------------------------- tracer
def test_tracer_record_events_resume(tmp_path):
    t = tr.Tracer(str(tmp_path / "trace.jsonl"))
    t.record("step_done", step_id="s1")
    t.record("step_done", step_id="s2")
    assert t.completed_step_ids() == {"s1", "s2"}
    t2 = tr.Tracer(str(tmp_path / "trace.jsonl"))   # re-open continues seq
    ev = t2.record("note")
    assert ev["seq"] == 3
    assert len(t2.events()) == 3


# --------------------------------------------------------- engine run loop
def _plan(n):
    return [{"id": f"s{i}", "action": "note", "phase": f"p{i}", "text": f"t{i}"} for i in range(n)]


def engine_for(plan, tmp_path, max_steps=50, loop=None):
    box, c = clk()
    b = bd.Budget(max_steps=max_steps, max_seconds=1e9, min_steps=1, clock=c)
    t = tr.Tracer(str(tmp_path / "trace.jsonl"))
    return eng.Engine(plan, tracer=t, budget=b, loop_detector=loop, bump_path=str(tmp_path / "bump.txt")), t


def test_engine_runs_all_steps(tmp_path):
    e, t = engine_for(_plan(4), tmp_path)
    summary = e.run()
    assert summary["finished"] is True and summary["steps"] == 4
    done = [ev for ev in t.events() if ev["type"] == "step_done"]
    assert {ev["step_id"] for ev in done} == {"s0", "s1", "s2", "s3"}


def test_engine_halts_on_budget(tmp_path):
    e, t = engine_for(_plan(5), tmp_path, max_steps=2)
    summary = e.run()
    assert summary["steps"] == 2
    assert any(ev["type"] == "halted" for ev in t.events())


def test_engine_loop_detection_skips(tmp_path):
    # all steps share signature note:: (same action/target/phase) -> loop trips, later steps skipped
    plan = [{"id": f"s{i}", "action": "note", "phase": "P", "text": "x"} for i in range(6)]
    e, t = engine_for(plan, tmp_path, loop=ld.LoopDetector(window=12, max_repeats=3))
    e.run()
    done = [ev for ev in t.events() if ev["type"] == "step_done"]
    loops = [ev for ev in t.events() if ev["type"] == "loop_detected"]
    assert len(done) == 2 and len(loops) == 4     # first 2 run, rest detected as loop


def test_engine_resume_skips_completed(tmp_path):
    plan = _plan(3)
    e1, t = engine_for(plan, tmp_path, max_steps=2)
    e1.run()                                      # s0,s1 done; s2 halted
    assert t.completed_step_ids() == {"s0", "s1"}
    e2, _ = engine_for(plan, tmp_path, max_steps=50)
    e2.run(resume=True)
    skipped = [ev for ev in t.events() if ev["type"] == "step_skipped_resume"]
    assert {ev["step_id"] for ev in skipped} == {"s0", "s1"}
    assert "s2" in t.completed_step_ids()


def test_engine_consumes_bump(tmp_path):
    e, t = engine_for(_plan(2), tmp_path)
    (tmp_path / "bump.txt").write_text("also test the staging host", encoding="utf-8")
    e.run()
    bumps = [ev for ev in t.events() if ev["type"] == "operator_bump"]
    assert bumps and "staging" in bumps[0]["text"]
    assert (tmp_path / "bump.txt").read_text() == ""     # consumed


def test_engine_step_error_does_not_crash(tmp_path):
    @eng.action("boom")
    def _boom(ctx, step):
        raise RuntimeError("kaboom")
    plan = [{"id": "s0", "action": "boom", "phase": "P"}, {"id": "s1", "action": "note", "phase": "Q"}]
    e, t = engine_for(plan, tmp_path)
    e.run()
    assert any(ev["type"] == "step_error" for ev in t.events())
    assert "s1" in t.completed_step_ids()                # run continued past the error


# --------------------------------------------------------- plan builder
def test_plan_from_workflow_follows_next():
    wf = {"phases": {
        "scope": {"skills": ["recon-osint"], "next": "recon", "gate": {"required": ["auth"]}},
        "recon": {"skills": ["recon-osint"], "next": "report"},
        "report": {"skills": ["threat-hunting"]},
        "orphan": {"skills": ["x"]},
    }}
    plan = eng.plan_from_workflow(wf, target="acme.com")
    ids = [s["id"] for s in plan]
    assert ids[0] == "scope_check"                       # scope_check inserted (target given)
    assert "phase:scope" in ids and "phase:recon" in ids and "phase:report" in ids
    assert "recall:recon" in ids                         # recall inserted at recon
    assert "phase:orphan" not in ids                     # not reachable via next
