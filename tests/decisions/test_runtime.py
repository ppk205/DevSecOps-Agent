"""QR-21 and QR-12: cancellable inference, real batching and exact state hashes."""

import hashlib
import json
import sys
import threading
import time

import pytest

from tests.decisions.test_batching import BatchAgent, _finding
from vulnscan.contracts.decision import DecisionStatus
from vulnscan.core.stdio_worker import JSONWorker
from vulnscan.decisions import laya
from vulnscan.decisions.batching import triage_many_batched
from vulnscan.decisions.laya import LayaDecisionBackend
from vulnscan.decisions.state import build_evidence_state, model_state
from vulnscan.decisions.triage import build_triage_questions
from vulnscan.scanners.process import ScanCancelled


def test_production_backend_uses_one_batch_call():
    agent = BatchAgent()
    # Test double receives canonical metadata, so it does not depend on run IDs.
    agent.predict_batch = lambda states, questions, **kwargs: [
        {
            "answers": __import__("tests.decisions.test_batching", fromlist=["_answers"])._answers(
                "unused"
            )
        }
        for _ in states
    ]
    calls = []
    original = agent.predict_batch
    agent.predict_batch = lambda states, questions, **kwargs: (
        calls.append(states) or original(states, questions, **kwargs)
    )
    backend = LayaDecisionBackend(
        agent_loader=lambda: agent, model_id="custom/checkpoint", model_revision="test-revision"
    )
    outcomes = triage_many_batched(
        [_finding("F-0"), _finding("F-1")], backend, build_triage_questions(), batch_size=4
    )
    assert len(calls) == 1 and len(calls[0]) == 2
    assert all(o.result.model_id == "custom/checkpoint" for o in outcomes)
    assert all(o.result.model_revision == "test-revision" for o in outcomes)
    assert agent.single_calls == 0


def test_qr21_missing_laya_does_not_start_a_worker_for_each_finding(mocker):
    availability = mocker.patch.object(laya.importlib.util, "find_spec", return_value=None)
    call = mocker.patch.object(laya._process_worker, "call")
    backend = LayaDecisionBackend()

    outcomes = triage_many_batched(
        [_finding(f"F-{i}") for i in range(8)], backend, build_triage_questions(), batch_size=1
    )

    assert len(outcomes) == 8
    assert all(o.result.status is DecisionStatus.UNAVAILABLE for o in outcomes)
    assert all(o.result.error_code == "dependency_unavailable" for o in outcomes)
    assert all(o.route.route == "baseline_fallback" for o in outcomes)
    assert all(o.result.state_hash for o in outcomes)
    availability.assert_called_once_with("laya")
    call.assert_not_called()


def test_qr21_child_dependency_failure_is_retained_for_later_batches(mocker):
    worker = mocker.Mock(spec=JSONWorker)
    worker.call.side_effect = ImportError("missing model dependency")
    backend = LayaDecisionBackend(worker=worker)

    outcomes = triage_many_batched(
        [_finding(f"F-{i}") for i in range(8)], backend, build_triage_questions(), batch_size=1
    )

    assert all(o.result.error_code == "dependency_unavailable" for o in outcomes)
    worker.call.assert_called_once()


def test_qr21_transient_timeout_allows_a_later_worker_call(mocker):
    from tests.decisions.test_batching import _answers

    worker = mocker.Mock(spec=JSONWorker)
    worker.call.side_effect = [
        TimeoutError("deadline exceeded"),
        {"rows": [{"answers": _answers("unused")}], "model_revision": "test", "device": "cpu"},
    ]
    backend = LayaDecisionBackend(worker=worker)

    outcomes = triage_many_batched(
        [_finding("F-0"), _finding("F-1")], backend, build_triage_questions(), batch_size=1
    )

    assert outcomes[0].result.error_code == "timeout"
    assert outcomes[1].result.status is DecisionStatus.COMPLETED
    assert worker.call.call_count == 2


def test_hash_is_of_the_exact_bounded_inference_payload():
    envelope = build_evidence_state(
        {"evidence": "x" * 10000, "labels": "hidden", "private_key": "key", "run_id": "secret-run"}
    )
    payload = model_state(envelope)
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert len(canonical) <= 1500
    assert hashlib.sha256(canonical.encode()).hexdigest() == envelope["state_hash"]
    assert "run_id" not in payload
    assert "hidden" not in canonical and '"key"' not in canonical


def test_worker_deadline_terminates_child_and_allows_restart():
    worker = JSONWorker([sys.executable, "-c", "import time; time.sleep(60)"])
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        worker.call("predict", {}, timeout=0.1)
    assert time.monotonic() - started < 3
    assert worker.process is None


def test_worker_cancel_terminates_child():
    cancel = threading.Event()
    timer = threading.Timer(0.1, cancel.set)
    worker = JSONWorker([sys.executable, "-c", "import time; time.sleep(60)"])
    timer.start()
    try:
        with pytest.raises(ScanCancelled):
            worker.call("predict", {}, timeout=10, cancelled=cancel.is_set)
        assert worker.process is None
    finally:
        timer.cancel()
        worker.close()
