"""Project-specific Laya training with separate validation/calibration/test data.

The model sequence and scoring primitives follow the Apache-2.0 Laya 0.3.20
training API. GPU modules are imported only for an explicit training run.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
import random
from pathlib import Path
from typing import Any

from vulnscan.decisions.protocol import (
    INPUT_FORMAT_VERSION,
    MODEL_ID,
    MODEL_REVISION,
    QUESTION_SET_VERSION,
)
from vulnscan.decisions.state import build_evidence_state, model_state
from vulnscan.decisions.triage import build_triage_questions


def read_dataset(
    root: Path, include_test: bool = False
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if (
        manifest.get("input_format_version") != INPUT_FORMAT_VERSION
        or manifest.get("question_set_version") != QUESTION_SET_VERSION
    ):
        raise ValueError("Dataset input/question versions do not match this runtime")
    splits: dict[str, list[dict[str, Any]]] = {}
    expected_questions = {
        name: {
            "type": question.type.value,
            "instructions": question.instructions,
            "criteria": question.criteria,
        }
        for name, question in build_triage_questions().items()
    }
    for name in ("train", "validation", "calibration", "test"):
        if name == "test" and not include_test:
            continue
        raw = (root / f"{name}.jsonl").read_bytes()
        if hashlib.sha256(raw).hexdigest() != manifest["checksums"][name]:
            raise ValueError("Dataset checksum mismatch: " + name)
        rows = [json.loads(line) for line in raw.splitlines() if line]
        if not rows:
            raise ValueError("Every split must contain reviewed examples")
        for row in rows:
            if row["questions"] != expected_questions:
                raise ValueError("Training questions differ from the frozen question set")
            if row["state"] != model_state(build_evidence_state(row["state"])):
                raise ValueError("Training input is not the canonical redacted runtime input")
        splits[name] = rows
    return splits, manifest


def encode(
    rows: list[dict[str, Any]], tokenizer: Any, config: dict[str, Any], common: Any
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in rows:
        for name, question in row["questions"].items():
            qtype, criteria = question["type"], question.get("criteria", {})
            options = (
                list(criteria)
                if qtype == "choice"
                else ["false", "true"]
                if qtype == "noul"
                else [str(i) for i in range(len(criteria))]
            )
            target = [float(row["gold"][name]["probabilities"][option]) for option in options]
            if (
                not target
                or any(not 0 <= value <= 1 for value in target)
                or not math.isclose(sum(target), 1.0, abs_tol=1e-6)
            ):
                raise ValueError("Invalid gold probability distribution")
            ids, markers = common.build_sequence(
                tokenizer,
                row["state"],
                {
                    "t": qtype,
                    "ins": question["instructions"],
                    "crit": criteria,
                },
                config["max_len"],
                config["head_max_len"],
            )
            if len(markers) != len(target):
                raise ValueError("Training sequence lost answer markers; check context limits")
            items.append(
                {
                    "ids": ids,
                    "markers": markers,
                    "target": target,
                    "qtype": common.QTYPES[qtype],
                    "name": name,
                }
            )
    return items


def collate(items: list[dict[str, Any]], pad: int, torch: Any, device: Any) -> dict[str, Any]:
    n, length, options = (
        len(items),
        max(len(i["ids"]) for i in items),
        max(len(i["markers"]) for i in items),
    )
    batch = {
        "ids": torch.full((n, length), pad, dtype=torch.long),
        "attention": torch.zeros((n, length), dtype=torch.long),
        "markers": torch.zeros((n, options), dtype=torch.long),
        "mask": torch.zeros((n, options), dtype=torch.bool),
        "target": torch.zeros((n, options), dtype=torch.float32),
        "qtype": torch.tensor([i["qtype"] for i in items]),
    }
    for index, item in enumerate(items):
        length, options = len(item["ids"]), len(item["markers"])
        batch["ids"][index, :length] = torch.tensor(item["ids"])
        batch["attention"][index, :length] = 1
        batch["markers"][index, :options] = torch.tensor(item["markers"])
        batch["mask"][index, :options] = True
        batch["target"][index, :options] = torch.tensor(item["target"])
    return {name: tensor.to(device) for name, tensor in batch.items()}


def forward(model: Any, batch: dict[str, Any]) -> tuple[Any, Any]:
    logits, actions = model(
        batch["ids"], batch["attention"], batch["markers"], batch["mask"], batch["qtype"]
    )
    return logits.float().masked_fill(~batch["mask"], -1e4), actions


def measure(
    model: Any,
    items: list[dict[str, Any]],
    tokenizer: Any,
    torch: Any,
    device: Any,
    microbatch: int,
) -> tuple[float, list[tuple[int, Any, Any]]]:
    model.eval()
    total, losses = 0, 0.0
    predictions: list[tuple[int, Any, Any]] = []
    with torch.no_grad():
        for offset in range(0, len(items), microbatch):
            chunk = items[offset : offset + microbatch]
            batch = collate(chunk, tokenizer.pad_token_id, torch, device)
            with torch.autocast("cuda", dtype=torch.float16):
                logits, _ = forward(model, batch)
            losses += float(-(batch["target"] * torch.log_softmax(logits, -1)).sum())
            total += len(chunk)
            for i, item in enumerate(chunk):
                k = len(item["target"])
                predictions.append(
                    (item["qtype"], logits[i, :k].cpu(), batch["target"][i, :k].cpu())
                )
    return losses / total, predictions


def fit_temperatures(predictions: list[tuple[int, Any, Any]], torch: Any) -> list[float]:
    temperatures: list[float] = []
    for qtype in range(3):
        selected = [(z, gold) for kind, z, gold in predictions if kind == qtype]
        if not selected:
            raise ValueError("Calibration data must include all three question types")
        log_temperature = torch.zeros(1, requires_grad=True)
        optimizer = torch.optim.LBFGS([log_temperature], lr=0.1, max_iter=100)

        def closure(
            optimizer: Any = optimizer,
            log_temperature: Any = log_temperature,
            selected: Any = selected,
        ) -> Any:
            optimizer.zero_grad()
            scale = log_temperature.exp().clamp(0.5, 5.0)
            loss = torch.stack(
                [-(gold * torch.log_softmax(z / scale, -1)).sum() for z, gold in selected]
            ).mean()
            loss.backward()
            return loss

        optimizer.step(closure)
        temperatures.append(float(log_temperature.exp().clamp(0.5, 5.0).detach()))
    return temperatures


def train(
    args: argparse.Namespace, splits: dict[str, list[dict[str, Any]]], manifest: dict[str, Any]
) -> None:
    torch = importlib.import_module("torch")
    common = importlib.import_module("laya.common")
    if not torch.cuda.is_available():
        raise ValueError("Training requires a CUDA GPU; use the Kaggle notebook")
    rank, world = int(os.environ.get("LOCAL_RANK", "0")), int(os.environ.get("WORLD_SIZE", "1"))
    device = torch.device("cuda", rank)
    torch.cuda.set_device(rank)
    random.seed(args.seed)
    torch.manual_seed(args.seed)
    if world > 1:
        torch.distributed.init_process_group("nccl")
    hub = importlib.import_module("huggingface_hub")
    transformers = importlib.import_module("transformers")
    safetensors = importlib.import_module("safetensors.torch")
    root = Path(hub.snapshot_download(repo_id=MODEL_ID, revision=MODEL_REVISION))
    config = json.loads((root / "rl_agent_config.json").read_text())
    config["max_len"] = 512
    config["amp_dtype"] = "fp16"
    tokenizer = transformers.AutoTokenizer.from_pretrained(str(root / "tokenizer"))
    model = common.build_model(config, encoder_dir=str(root / "encoder"))
    model.load_state_dict(safetensors.load_file(str(root / "model.safetensors")), strict=True)
    model.encoder.gradient_checkpointing_enable(
        gradient_checkpointing_kwargs={"use_reentrant": False}
    )
    model.head_checkpointing = True
    model.to(device)
    wrapped = (
        torch.nn.parallel.DistributedDataParallel(
            model, device_ids=[rank], find_unused_parameters=True
        )
        if world > 1
        else model
    )
    items = encode(splits["train"], tokenizer, config, common)
    validation = encode(splits["validation"], tokenizer, config, common)
    calibration = encode(splits["calibration"], tokenizer, config, common)
    sampler = torch.utils.data.distributed.DistributedSampler(
        items, num_replicas=world, rank=rank, shuffle=True, seed=args.seed
    )
    optimizer = torch.optim.AdamW(
        [
            {
                "params": [
                    p for name, p in model.named_parameters() if name.startswith("encoder.")
                ],
                "lr": 2.5e-5,
            },
            {
                "params": [
                    p for name, p in model.named_parameters() if not name.startswith("encoder.")
                ],
                "lr": 1e-4,
            },
        ],
        weight_decay=0.01,
    )
    scaler = torch.amp.GradScaler("cuda")
    best, stale = float("inf"), 0
    args.out.mkdir(parents=True, exist_ok=True)
    for epoch in range(args.epochs):
        sampler.set_epoch(epoch)
        indices = list(sampler)
        chunks = [indices[i : i + args.microbatch] for i in range(0, len(indices), args.microbatch)]
        wrapped.train()
        optimizer.zero_grad(set_to_none=True)
        for step, indices_chunk in enumerate(chunks):
            batch = collate(
                [items[i] for i in indices_chunk], tokenizer.pad_token_id, torch, device
            )
            with torch.autocast("cuda", dtype=torch.float16):
                logits, actions = forward(wrapped, batch)
            # Proper-score policy gradient over four noisy distributions, with
            # cross-entropy guidance as in the upstream RLCD training recipe.
            mask, target = batch["mask"], batch["target"]
            sigma = 0.4 + (0.1 - 0.4) * epoch / max(1, args.epochs - 1)
            noise = torch.randn((4,) + logits.shape, device=device) * sigma * mask
            noise = (noise - noise.sum(-1, keepdim=True) / mask.sum(-1, keepdim=True)) * mask
            samples = logits.detach().unsqueeze(0) + noise
            with torch.no_grad():
                probabilities = torch.softmax(samples.masked_fill(~mask, -1e4), -1)
                reward = common.proper_reward(
                    probabilities, target.unsqueeze(0), batch["qtype"], mask, w_sph=0.75, w_rps=1.0
                )
                advantage = (reward - reward.mean(0, keepdim=True)) / (reward.std() + 1e-6)
            log_density = -(((samples - logits.unsqueeze(0)) ** 2) * mask).sum(-1) / (2 * sigma**2)
            policy_loss = -(advantage * log_density).mean()
            supervised = -(target * torch.log_softmax(logits, -1)).sum(-1).mean()
            group_start = step // args.accumulation * args.accumulation
            group_size = min(args.accumulation, len(chunks) - group_start)
            loss = (policy_loss + supervised + 0.0 * actions.sum()) / group_size
            scaler.scale(loss).backward()
            if (step + 1) % args.accumulation == 0 or step + 1 == len(chunks):
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
                optimizer.zero_grad(set_to_none=True)
        if world > 1:
            torch.distributed.barrier()
        value = torch.zeros(1, device=device)
        if rank == 0:
            validation_loss, _ = measure(
                model, validation, tokenizer, torch, device, args.microbatch
            )
            value[0] = validation_loss
            print(json.dumps({"epoch": epoch + 1, "validation_loss": validation_loss}), flush=True)
        if world > 1:
            torch.distributed.broadcast(value, src=0)
        improved = float(value[0]) < best
        if improved:
            best, stale = float(value[0]), 0
            if rank == 0:
                safetensors.save_file(
                    {
                        name: tensor.detach().half().contiguous().cpu()
                        for name, tensor in model.state_dict().items()
                    },
                    str(args.out / "model.safetensors"),
                )
        else:
            stale += 1
        if stale >= 2:
            break
    if world > 1:
        torch.distributed.barrier()
    if rank == 0:
        del optimizer, scaler
        model.load_state_dict(
            safetensors.load_file(str(args.out / "model.safetensors")), strict=True
        )
        _, predictions = measure(model, calibration, tokenizer, torch, device, args.microbatch)
        config["temperature"] = fit_temperatures(predictions, torch)
        config.pop("temperature_by_options", None)
        config["fine_tuned"] = True
        config["training"] = {
            "base_revision": MODEL_REVISION,
            "input_format_version": INPUT_FORMAT_VERSION,
            "question_set_version": QUESTION_SET_VERSION,
            "seed": args.seed,
            "validation_loss": best,
            "peak_gpu_mib": round(torch.cuda.max_memory_allocated(device) / 1024**2, 1),
        }
        (args.out / "rl_agent_config.json").write_text(json.dumps(config, indent=2))
        model.encoder.config.save_pretrained(str(args.out / "encoder"))
        tokenizer.save_pretrained(str(args.out / "tokenizer"))
        (args.out / "dataset-manifest.json").write_text(json.dumps(manifest, indent=2))
        hashes = {
            file.relative_to(args.out).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
            for file in args.out.rglob("*")
            if file.is_file()
        }
        (args.out / "checksums.json").write_text(json.dumps(hashes, indent=2))
    if world > 1:
        torch.distributed.barrier()
        torch.distributed.destroy_process_group()


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Laya on reviewed project triage decisions")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("artifacts/laya-trained"))
    parser.add_argument("--mode", choices=("validate", "train"), default="validate")
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--microbatch", type=int, default=2)
    parser.add_argument("--accumulation", type=int, default=16)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if min(args.epochs, args.microbatch, args.accumulation) < 1 or args.epochs > 4:
        parser.error("positive batch settings and 1–4 epochs are required")
    splits, manifest = read_dataset(args.data)
    if args.mode == "train":
        train(args, splits, manifest)
    else:
        print(json.dumps({"validated": True, "counts": manifest["counts"]}, indent=2))


if __name__ == "__main__":
    main()
