#!/usr/bin/env bash
# Check and optionally install (--install) the 5 DevSecOps-Agent scanner tools in user space:
#   1. Semgrep CE (Python venv via uv)
#   2. CodeQL CLI bundle
#   3. OWASP Dependency-Check (plus zero-install OSV.dev fallback)
#   4. Gitleaks
#   5. Trivy + SpotBugs/FindSecBugs
set -euo pipefail

BIN_DIR="${DEVSECOPS_BIN_DIR:-$HOME/.local/bin}"
INSTALL_ROOT="${DEVSECOPS_SCANNERS_DIR:-$HOME/.local/share/scanners}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_BIN="$REPO_ROOT/.venv/bin"
mkdir -p "$BIN_DIR" "$INSTALL_ROOT"

get_asset_url() {
  local repo="$1"
  local pattern="$2"
  curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | python3 -c "
import json, re, sys
data = json.load(sys.stdin)
for a in data.get('assets', []):
    if re.search(r'${pattern}', a['name']):
        print(a['browser_download_url'])
        break
"
}

if [[ "${1:-}" == "--install" ]]; then
  echo "=== Installing DevSecOps-Agent 5 Scanner Tool Groups into $INSTALL_ROOT ==="
  mkdir -p "$VENV_BIN"

  if ! command -v gitleaks >/dev/null 2>&1 && [[ ! -x "$VENV_BIN/gitleaks" ]]; then
    echo "-> Installing Gitleaks..."
    GL_URL=$(get_asset_url "gitleaks/gitleaks" "linux_x64\.tar\.gz$")
    curl -fsSL "$GL_URL" -o /tmp/gitleaks.tar.gz
    mkdir -p "$INSTALL_ROOT/gitleaks"
    tar -xzf /tmp/gitleaks.tar.gz -C "$INSTALL_ROOT/gitleaks"
    ln -sf "$INSTALL_ROOT/gitleaks/gitleaks" "$BIN_DIR/gitleaks"
    ln -sf "$INSTALL_ROOT/gitleaks/gitleaks" "$VENV_BIN/gitleaks"
    rm -f /tmp/gitleaks.tar.gz
  fi

  if ! command -v trivy >/dev/null 2>&1 && [[ ! -x "$VENV_BIN/trivy" ]]; then
    echo "-> Installing Trivy..."
    TRIVY_URL=$(get_asset_url "aquasecurity/trivy" "Linux-64bit\.tar\.gz$")
    curl -fsSL "$TRIVY_URL" -o /tmp/trivy.tar.gz
    mkdir -p "$INSTALL_ROOT/trivy"
    tar -xzf /tmp/trivy.tar.gz -C "$INSTALL_ROOT/trivy"
    ln -sf "$INSTALL_ROOT/trivy/trivy" "$BIN_DIR/trivy"
    ln -sf "$INSTALL_ROOT/trivy/trivy" "$VENV_BIN/trivy"
    rm -f /tmp/trivy.tar.gz
  fi

  if ! command -v spotbugs >/dev/null 2>&1 && [[ ! -x "$VENV_BIN/spotbugs" ]]; then
    echo "-> Installing SpotBugs + FindSecBugs..."
    SB_URL=$(get_asset_url "spotbugs/spotbugs" "^spotbugs-[0-9.]+\.tgz$")
    curl -fsSL "$SB_URL" -o /tmp/spotbugs.tgz
    mkdir -p "$INSTALL_ROOT/spotbugs"
    tar -xzf /tmp/spotbugs.tgz -C "$INSTALL_ROOT/spotbugs" --strip-components=1
    rm -f /tmp/spotbugs.tgz
    FSB_ZIP_URL=$(get_asset_url "find-sec-bugs/find-sec-bugs" "findsecbugs-cli.*\.zip$")
    curl -fsSL "$FSB_ZIP_URL" -o /tmp/fsb.zip
    mkdir -p /tmp/fsb_extract
    unzip -q -o /tmp/fsb.zip -d /tmp/fsb_extract
    cp /tmp/fsb_extract/lib/findsecbugs-plugin-*.jar "$INSTALL_ROOT/findsecbugs.jar"
    cp "$INSTALL_ROOT/findsecbugs.jar" "$INSTALL_ROOT/spotbugs/plugin/findsecbugs-plugin.jar"
    rm -rf /tmp/fsb.zip /tmp/fsb_extract
    cat <<EOF > "$BIN_DIR/spotbugs"
#!/usr/bin/env bash
args=()
for a in "\$@"; do
  if [ "\$a" = "/opt/findsecbugs.jar" ] && [ ! -f "/opt/findsecbugs.jar" ]; then
    args+=("$INSTALL_ROOT/findsecbugs.jar")
  else
    args+=("\$a")
  fi
done
exec "$INSTALL_ROOT/spotbugs/bin/spotbugs" "\${args[@]}"
EOF
    chmod +x "$BIN_DIR/spotbugs"
    cp "$BIN_DIR/spotbugs" "$VENV_BIN/spotbugs"
  fi

  if ! command -v dependency-check >/dev/null 2>&1 && [[ ! -x "$VENV_BIN/dependency-check" ]]; then
    echo "-> Installing OWASP Dependency-Check..."
    ODC_URL=$(get_asset_url "dependency-check/DependencyCheck" "release\.zip$")
    curl -fsSL "$ODC_URL" -o /tmp/odc.zip
    unzip -q -o /tmp/odc.zip -d "$INSTALL_ROOT"
    rm -f /tmp/odc.zip
    ln -sf "$INSTALL_ROOT/dependency-check/bin/dependency-check.sh" "$BIN_DIR/dependency-check"
    ln -sf "$INSTALL_ROOT/dependency-check/bin/dependency-check.sh" "$VENV_BIN/dependency-check"
  fi

  if ! command -v codeql >/dev/null 2>&1 && [[ ! -x "$VENV_BIN/codeql" ]]; then
    echo "-> Installing CodeQL CLI Bundle..."
    CQL_URL=$(get_asset_url "github/codeql-action" "codeql-bundle-linux64\.tar\.gz$")
    curl -fsSL "$CQL_URL" -o /tmp/codeql-bundle.tar.gz
    tar -xzf /tmp/codeql-bundle.tar.gz -C "$INSTALL_ROOT"
    rm -f /tmp/codeql-bundle.tar.gz
    ln -sf "$INSTALL_ROOT/codeql/codeql" "$BIN_DIR/codeql"
    ln -sf "$INSTALL_ROOT/codeql/codeql" "$VENV_BIN/codeql"
  fi
fi

export PATH="$VENV_BIN:$BIN_DIR:$PATH"
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
check_bin "codeql"           "Install via: bash scripts/setup_scanners.sh --install"
check_bin "dependency-check" "Install via: bash scripts/setup_scanners.sh --install"
check_bin "gitleaks"         "Install via: bash scripts/setup_scanners.sh --install"
check_bin "trivy"            "Install via: bash scripts/setup_scanners.sh --install"
check_bin "spotbugs"         "Install via: bash scripts/setup_scanners.sh --install"

echo ""
echo "Tip: Run 'uv run devsecops-agent tool-scan capabilities' for JSON diagnostics."
