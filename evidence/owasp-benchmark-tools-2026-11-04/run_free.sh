#!/bin/bash
set -u
REPO="/mnt/d/phuc/Code Project/DevSecOps-Agent"
PY="$REPO/.venv-linux/bin/python"
BIN="$REPO/.venv-linux/bin"
OUT=~/scan-results/owasp-2026-11-04
mkdir -p "$OUT"
cd "$REPO" || exit 1
export PYTHONPATH="$REPO/src" DEVSECOPS_NATIVE=python
echo '{"schema_version":1,"tools":["native-hunt"],"timeout":3000}' > "$OUT/native-cfg.json"
"$PY" --version; "$BIN/semgrep" --version; ls "$BIN" | grep -E '^(bandit|gitleaks|njsscan)$' | tr '\n' ' '; echo
for pair in "BenchmarkJava p/java" "BenchmarkPython p/python"; do
  set -- $pair; t=$1; pack=$2; T=~/scan-targets/$t
  s=$(date +%s)
  "$PY" -m vulnscan.cli.main scan-run --checkout "$T" --config "$OUT/native-cfg.json" --mode deterministic --no-laya --no-ai-review --no-ai-report --out "$OUT/$t-native" --db-path "$OUT/$t-native.db" --allow-dirty --json > "$OUT/$t-native.stdout" 2> "$OUT/$t-native.stderr"
  rc=$?; e=$(date +%s); echo "native $t exit=$rc seconds=$((e-s))"
  s=$(date +%s)
  "$BIN/semgrep" scan --config "$pack" --metrics=off --json --quiet --timeout 30 --output "$OUT/$t-semgrep.json" "$T" > /dev/null 2> "$OUT/$t-semgrep.stderr"
  rc=$?; e=$(date +%s); echo "semgrep $t $pack exit=$rc seconds=$((e-s))"
done
if [ -x "$BIN/bandit" ]; then
  s=$(date +%s); "$BIN/bandit" -r ~/scan-targets/BenchmarkPython/testcode -f json -o "$OUT/BenchmarkPython-bandit.json" -q 2> "$OUT/bandit.stderr"; rc=$?; e=$(date +%s); echo "bandit exit=$rc seconds=$((e-s))"
fi
"$BIN/semgrep" scan --version >/dev/null; echo DONE
