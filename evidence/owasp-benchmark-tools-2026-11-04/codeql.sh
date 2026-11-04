#!/bin/bash
set -u
mkdir -p ~/tools && cd ~/tools || exit 1
if [ ! -x codeql/codeql ]; then
  curl -fsSL -o bundle.tgz https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz || exit 2
  tar xzf bundle.tgz && rm -f bundle.tgz
fi
CQ=~/tools/codeql/codeql; $CQ version | head -1
OUT=~/scan-results/owasp-2026-11-04; mkdir -p "$OUT/codeql"; cd "$OUT/codeql" || exit 1
s=$(date +%s); $CQ database create java-db --language=java --build-mode=none --source-root ~/scan-targets/BenchmarkJava --overwrite --ram=4500 --threads=4 > java-create.log 2>&1; echo "java db exit=$? sec=$(( $(date +%s)-s ))"
s=$(date +%s); $CQ database analyze java-db codeql/java-queries:codeql-suites/java-security-extended.qls --format=sarif-latest --output=java.sarif --ram=4500 --threads=4 > java-analyze.log 2>&1; echo "java analyze exit=$? sec=$(( $(date +%s)-s ))"
s=$(date +%s); $CQ database create py-db --language=python --source-root ~/scan-targets/BenchmarkPython --overwrite --ram=4500 --threads=4 > py-create.log 2>&1; echo "py db exit=$? sec=$(( $(date +%s)-s ))"
s=$(date +%s); $CQ database analyze py-db codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest --output=py.sarif --ram=4500 --threads=4 > py-analyze.log 2>&1; echo "py analyze exit=$? sec=$(( $(date +%s)-s ))"
echo DONE
