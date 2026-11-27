import type {
  GeneralSettings,
  KeyEntry,
  ScannerOptions,
  ToolHealth,
  UsageSummary,
} from "../api/types";

/** Fixture Phase 2 đơn định: tools, settings, keys, usage. */

const fast = ["semgrep", "native-hunt", "gitleaks"];
export const MOCK_SCANNER_PROFILES: ScannerOptions["profiles"] = {
  fast,
  full: [...fast, "trivy", "owasp-dependency-check"],
};

export const MOCK_TOOLS: ToolHealth[] = [
  {
    tool: "native-hunt",
    binary: "native-hunt",
    path: "built-in",
    available: true,
    version: "0.2.0",
    hint: null,
  },
  ...["semgrep", "gitleaks", "trivy", "owasp-dependency-check", "codeql"].map((tool) => ({
    tool,
    binary: tool,
    path: null,
    available: false,
    version: null,
    hint: `Install ${tool} on PATH`,
  })),
];

export const MOCK_GENERAL: GeneralSettings = {
  timezone: "Asia/Saigon",
  timeout: 600,
  max_files: 100000,
  output_dir: "artifacts",
  fail_on: "high",
  profile: "fast",
};

export const MOCK_KEYS: KeyEntry[] = [
  {
    profile: "kios-free",
    label: "KiosAPI free",
    base_url: "https://kiosapi.com/v1",
    api_key_env: "KIOS_API_KEY",
    models: ["north-mini-code", "beam-free"],
    default_model: "north-mini-code",
    configured: true,
    masked: "••••8901",
  },
];

export const MOCK_USAGE: UsageSummary = {
  requests: 14,
  prompt_tokens: 41_050,
  completion_tokens: 7_160,
  total_tokens: 48_210,
  run_count: 3,
};
