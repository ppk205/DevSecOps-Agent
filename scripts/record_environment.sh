#!/usr/bin/env bash
# Record the exact environment and model state needed to reproduce T09/T10.
#
# Run from the repo root. Writes to evidence/environment/ and is safe to re-run.
set -euo pipefail

VENV="${VENV:-.venv}"
PY="$VENV/Scripts/python.exe"
OUT="evidence/environment"

mkdir -p "$OUT"

echo "== interpreter =="
"$PY" -VV

echo "== model + device =="
"$PY" - <<'PYEOF'
import json
import laya
import torch

report = {
    "laya_version": getattr(laya, "__version__", "unknown"),
    "torch_version": torch.__version__,
    "cuda_available": torch.cuda.is_available(),
    "cuda_device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
    "cuda_total_mib": (
        round(torch.cuda.get_device_properties(0).total_memory / 1024 / 1024)
        if torch.cuda.is_available()
        else None
    ),
}
print(json.dumps(report, indent=2))
PYEOF

echo "== config checksum =="
for f in config/laya.json; do
  if [ -f "$f" ]; then
    sha256sum "$f"
  fi
done

echo "== model revision pin =="
"$PY" - <<'PYEOF'
import json
from vulnscan.decisions.protocol import (
    CONTRACT_VERSION,
    MODEL_ID,
    MODEL_LICENSE,
    MODEL_REVISION,
    QUESTION_SET_VERSION,
    VERIFIED_DEPENDENCIES,
)

print(
    json.dumps(
        {
            "contract_version": CONTRACT_VERSION,
            "question_set_version": QUESTION_SET_VERSION,
            "model_id": MODEL_ID,
            "model_revision": MODEL_REVISION,
            "model_license": MODEL_LICENSE,
            "verified_dependencies": VERIFIED_DEPENDENCIES,
        },
        indent=2,
    )
)
PYEOF

echo "== frozen wheel set =="
"$PY" -m pip freeze | grep -viE "^-e |^devsecops-agent" | sort > "$OUT/pip-freeze.txt"
wc -l < "$OUT/pip-freeze.txt"

echo "wrote $OUT/pip-freeze.txt"
