from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from vulnscan.contracts.decision import (
    DecisionAnswer,
    DecisionQuestion,
    DecisionRequest,
    DecisionResult,
    DecisionStatus,
    DecisionType,
)
from vulnscan.decisions.laya import LayaDecisionBackend
from vulnscan.decisions.router import DecisionRouter


class FakeLaya:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def predict(self, state: dict[str, Any], questions: dict[str, Any], **kwargs: Any) -> Any:
        self.calls.append((state, questions))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _question(name: str = "route") -> DecisionQuestion:
    return DecisionQuestion(
        name=name,
        type=DecisionType.CHOICE,
        instructions="Choose the next analysis route.",
        criteria={"verify": "Run targeted verification."},
    )


def _request() -> DecisionRequest:
    return DecisionRequest(
        state={"finding_id": "f-1", "cwe_category": "CWE-89", "secret": "[REDACTED]"},
        questions={"route": _question()},
    )


def test_laya_backend_normalizes_typed_answers() -> None:
    fake = FakeLaya(
        {
            "answers": {
                "route": {
                    "type": "choice",
                    "choice": "verify",
                    "probabilities": {"verify": 0.84, "human_review": 0.16},
                    "confidence": 0.84,
                }
            }
        }
    )
    backend = LayaDecisionBackend(agent_loader=lambda: fake, model_id="test/laya")

    result = backend.predict(_request())

    assert isinstance(result, DecisionResult)
    assert result.status is DecisionStatus.COMPLETED
    assert result.model_id == "test/laya"
    assert result.answers["route"].choice == "verify"
    assert result.answers["route"].probabilities["verify"] == pytest.approx(0.84)
    assert result.input_truncated is False


def test_laya_backend_reports_unavailable_without_raising() -> None:
    backend = LayaDecisionBackend(
        agent_loader=lambda: (_ for _ in ()).throw(ImportError("no laya"))
    )

    result = backend.predict(_request())

    assert result.status is DecisionStatus.UNAVAILABLE
    assert result.error_code == "dependency_unavailable"
    assert result.answers == {}


def test_laya_backend_accepts_a_separate_worker_environment(monkeypatch, mocker) -> None:
    from vulnscan.decisions import laya as backend_module

    monkeypatch.delenv("LAYA_DEVICE", raising=False)
    monkeypatch.setattr(backend_module, "_WORKER_PYTHON", "separate-python")
    mocker.patch.object(backend_module.importlib.util, "find_spec", return_value=None)
    call = mocker.patch.object(
        backend_module._process_worker,
        "call",
        return_value={
            "rows": [{"answers": {"route": {"choice": "verify", "confidence": 0.84}}}],
            "model_revision": "test-revision",
            "device": "cuda:0",
        },
    )

    result = LayaDecisionBackend().predict(_request())

    assert call.call_args.args[1]["device"] == "auto"
    assert result.status is DecisionStatus.COMPLETED
    assert result.device == "cuda:0"


def test_laya_backend_marks_malformed_output_incomplete() -> None:
    backend = LayaDecisionBackend(
        agent_loader=lambda: FakeLaya({"answers": {"route": {"type": "choice"}}})
    )

    result = backend.predict(_request())

    assert result.status is DecisionStatus.INCOMPLETE
    assert result.error_code == "malformed_output"
    assert result.answers == {}


def test_state_envelope_redacts_secret_values_and_is_bounded() -> None:
    state = {
        "finding_id": "f-1",
        "message": "Authorization: Bearer sk-live-123456789",
        "nested": {"api_key": "sk-live-987654321"},
        "padding": "x" * 10_000,
    }

    from vulnscan.decisions.state import build_evidence_state

    envelope = build_evidence_state(state)

    assert envelope["message"].startswith("Authorization: ")
    assert "[REDACTED]" in envelope["message"]
    assert envelope["nested"] == {"api_key": "[REDACTED]"}
    assert len(envelope["state_text"]) < 2_000
    assert envelope["input_truncated"] is True


def test_router_uses_route_and_keeps_laya_advisory() -> None:
    result = DecisionResult(
        status=DecisionStatus.COMPLETED,
        model_id="test/laya",
        model_revision=None,
        device="cpu",
        answers={
            "route": DecisionAnswer(
                name="route",
                type=DecisionType.CHOICE,
                choice="cross_file_analysis",
                probabilities={"cross_file_analysis": 0.91},
                confidence=0.91,
            )
        },
        latency_ms=4.2,
        input_truncated=False,
        state_hash="abc",
        question_set_version="questions-1",
        created_at=datetime.now(UTC),
    )

    decision = DecisionRouter().route(
        request=_request(),
        result=result,
        final_status="unresolved",
    )

    assert decision.route == "cross_file_analysis"
    assert decision.affects_finding_status is False
    assert decision.final_status == "unresolved"


def test_router_falls_back_on_unavailable() -> None:
    result = DecisionResult(
        status=DecisionStatus.UNAVAILABLE,
        model_id="test/laya",
        model_revision=None,
        device="cpu",
        answers={},
        latency_ms=0,
        input_truncated=False,
        state_hash="abc",
        question_set_version="questions-1",
        error_code="dependency_unavailable",
        created_at=datetime.now(UTC),
    )

    decision = DecisionRouter().route(
        request=_request(),
        result=result,
        final_status="unresolved",
    )

    assert decision.route == "baseline_fallback"
    assert decision.affects_finding_status is False
    assert decision.final_status == "unresolved"


def test_laya_backend_env_dir_overrides_default_checkpoint(
    tmp_path,
    monkeypatch,  # type: ignore[no-untyped-def]
) -> None:
    """LAYA_MODEL_DIR points the backend at a trained local checkpoint."""
    from vulnscan.decisions.protocol import MODEL_ID, MODEL_REVISION

    monkeypatch.setenv("LAYA_MODEL_DIR", str(tmp_path))
    backend = LayaDecisionBackend()
    assert backend.model_id == str(tmp_path)
    assert backend.model_revision is None
    monkeypatch.delenv("LAYA_MODEL_DIR")
    backend = LayaDecisionBackend()
    assert backend.model_id == MODEL_ID
    assert backend.model_revision == MODEL_REVISION


def test_laya_backend_ignores_missing_env_dir(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A stale LAYA_MODEL_DIR falls back to the hub checkpoint, never crashes."""
    from vulnscan.decisions.protocol import MODEL_ID

    monkeypatch.setenv("LAYA_MODEL_DIR", "/definitely/not/here")
    backend = LayaDecisionBackend()
    assert backend.model_id == MODEL_ID


class TestResolveDevice:
    def test_unknown_and_empty_fall_back_to_cpu(self):
        from vulnscan.decisions.model_worker import _device_candidates

        assert _device_candidates("") == ("cpu",)
        assert _device_candidates("unknown") == ("cpu",)
        assert _device_candidates("cpu") == ("cpu",)

    def test_cuda_honored_only_with_cuda_torch(self):
        from vulnscan.decisions.model_worker import _device_candidates

        try:
            import torch
        except ImportError:
            assert _device_candidates("cuda") == ("cpu",)
        else:
            expected = ("cuda", "cpu") if torch.cuda.is_available() else ("cpu",)
            assert _device_candidates("cuda") == expected
            assert _device_candidates("CUDA") == expected

    def test_default_device_and_overrides(self, monkeypatch):
        monkeypatch.delenv("LAYA_DEVICE", raising=False)
        assert LayaDecisionBackend().device == "auto"
        monkeypatch.setenv("LAYA_DEVICE", "vulkan")
        assert LayaDecisionBackend(device="auto").device == "vulkan"
        assert LayaDecisionBackend(device="cpu").device == "cpu"

    @pytest.mark.parametrize(
        ("cuda", "vulkan", "failures", "expected"),
        [
            (True, True, {}, ["cuda"]),
            (False, True, {}, ["vulkan"]),
            (False, False, {}, ["cpu"]),
            (True, True, {"cuda": "fallback"}, ["cuda", "vulkan"]),
            (True, True, {"cuda": "predict_fallback"}, ["cuda", "vulkan"]),
            (True, True, {"cuda": "load", "vulkan": "predict"}, ["cuda", "vulkan", "cpu"]),
        ],
    )
    def test_auto_worker_uses_supported_devices_in_priority_order(
        self, tmp_path, monkeypatch, cuda, vulkan, failures, expected
    ):
        from vulnscan.decisions import model_worker

        class Agent:
            def __init__(self, device):
                self.device = device

            def predict_batch(self, *args, **kwargs):
                if failures.get(self.device) == "predict":
                    raise NotImplementedError("unsupported operator on this backend")
                if failures.get(self.device) == "predict_fallback":
                    self.device = "cpu"
                return []

            def __exit__(self, *args):
                pass

        loads = []

        def load(path, *, device):
            loads.append(device)
            if failures.get(device) == "load":
                raise RuntimeError("cannot load on this backend")
            return Agent("cpu" if failures.get(device) == "fallback" else device)

        modules = {
            "torch": SimpleNamespace(
                cuda=SimpleNamespace(is_available=lambda: cuda),
                is_vulkan_available=lambda: vulkan,
            ),
            "laya": SimpleNamespace(load=load),
        }
        with monkeypatch.context() as patch:
            patch.setattr(model_worker.importlib, "import_module", modules.__getitem__)
            request = {
                "version": model_worker.PROTOCOL_VERSION,
                "id": "test",
                "method": "predict_batch",
                "params": {
                    "model_id": str(tmp_path),
                    "device": "auto",
                    "states": [{}],
                    "questions": {},
                    "max_input_tokens": 1,
                },
            }
            stdin = io.BytesIO(json.dumps(request).encode() + b"\n")
            stdout = io.BytesIO()
            patch.setattr(model_worker.sys, "stdin", SimpleNamespace(buffer=stdin))
            patch.setattr(model_worker.sys, "stdout", SimpleNamespace(buffer=stdout))
            model_worker.main()

        reply = json.loads(stdout.getvalue())
        assert loads == expected
        assert reply["ok"] is True
        assert reply["result"]["device"] == expected[-1]
