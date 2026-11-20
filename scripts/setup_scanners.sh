#!/usr/bin/env bash
# Check and guide user-space installation of the 5 DevSecOps-Agent scanner tools:
#   1. Semgrep CE (Python venv via uv)
#   2. CodeQL CLI bundle
#   3. OWASP Dependency-Check (plus zero-install OSV.dev fallback)
#   4. Gitleaks
#   5. Trivy + SpotBugs/FindSecBugs
set -euo pipefail

BIN_DIR="${DEVSECOPS_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"

echo "=== DevSecOps-Agent Scanner Environment Check ==="
check_bin() {
  local name="$1"
  local hint="$2"
  if command -v "$name" >/dev/null 2>&1; then
    echo "  [OK]      $name -> $(command -v "$name")"
  else
    echo "  [MISSING] $name -> $hint"
  fi
}

check_bin "semgrep"          "Install via: uv sync --extra scanners"
check_bin "codeql"           "Download bundle: https://github.com/github/codeql-cli-binaries/releases (extract & add to PATH)"
check_bin "dependency-check" "Download CLI: https://github.com/jeremylong/DependencyCheck/releases (or rely on built-in OSV.dev fallback)"
check_bin "gitleaks"         "Download binary: https://github.com/gitleaks/gitleaks/releases -> copy to $BIN_DIR/gitleaks"
check_bin "trivy"            "Download binary: https://github.com/aquasecurity/trivy/releases -> copy to $BIN_DIR/trivy"
check_bin "spotbugs"         "Download SpotBugs + FindSecBugs (Java bytecode audit): https://spotbugs.github.io/"

echo ""
echo "Tip: Run 'uv run devsecops-agent tool-scan capabilities' for JSON diagnostics."
