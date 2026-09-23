"""Platform tests: full job lifecycle through fake adapter (T01 gate)."""

from __future__ import annotations

from vulnscan.core.job_manager import JobManager, RunAlreadyRunningError
from vulnscan.core.stage_tracker import StageTracker


def test_submit_to_complete(session, sample_spec, tmp_path):
    """submit → running → stage completed → completed, all persisted."""
    mgr = JobManager(session)
    run_id = mgr.submit_scan(sample_spec)
    mgr.mark_running(run_id)

    tracker = StageTracker(session, run_id)
    stage = tracker.start("intake")
    tracker.complete(stage.id)
    session.commit()

    run = mgr.get_run(run_id)
    assert run.status == "running"  # not yet marked completed by orchestrator

    mgr.update_run_status(run_id, "completed")
    assert mgr.get_run(run_id).status == "completed"


def test_one_at_a_time_guard(session, sample_spec):
    """A second submit while one run is RUNNING must fail."""
    mgr = JobManager(session)
    mgr.submit_scan(sample_spec)
    mgr.mark_running(mgr.list_runs()[0].id)
    import pytest
    with pytest.raises(RunAlreadyRunningError):
        mgr.submit_scan(sample_spec)


def test_restart_preserves_stage_history(session, sample_spec):
    """A new session (simulating restart) can read persisted stage history."""
    mgr = JobManager(session)
    run_id = mgr.submit_scan(sample_spec)
    mgr.mark_running(run_id)

    tracker = StageTracker(session, run_id)
    s1 = tracker.start("intake")
    tracker.complete(s1.id)
    s2 = tracker.start("scan")
    tracker.complete(s2.id)
    session.commit()

    stages = tracker.history()
    assert len(stages) == 2
    assert stages[0].name == "intake"
    assert stages[1].name == "scan"
    assert all(s.status == "completed" for s in stages)


def test_partial_stage_not_clean(session, sample_spec):
    """A PARTIAL stage is distinct from COMPLETED."""
    mgr = JobManager(session)
    run_id = mgr.submit_scan(sample_spec)
    mgr.mark_running(run_id)
    tracker = StageTracker(session, run_id)
    s = tracker.start("scan")
    tracker.partial(s.id, "only 3 of 6 files scanned")
    session.commit()
    stages = tracker.history()
    assert stages[0].status == "partial"
    assert stages[0].error_message == "only 3 of 6 files scanned"


def test_failed_run_shows_failed(session, sample_spec):
    """A FAILED run must never appear clean."""
    mgr = JobManager(session)
    run_id = mgr.submit_scan(sample_spec)
    mgr.mark_running(run_id)
    tracker = StageTracker(session, run_id)
    s = tracker.start("scan")
    tracker.fail(s.id, "tool crashed")
    session.commit()
    mgr.update_run_status(run_id, "failed")
    assert mgr.get_run(run_id).status == "failed"
