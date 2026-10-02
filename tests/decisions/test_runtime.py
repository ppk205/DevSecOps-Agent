"""QR-21 and QR-12: cancellable inference, real batching and exact state hashes."""

import hashlib
import json
import sys
import threading
import time

import pytest

from tests.decisions.test_batching import BatchAgent, _finding
from vulnscan.core.stdio_worker import JSONWorker
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
