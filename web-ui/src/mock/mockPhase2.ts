import type {
  GeneralSettings,
  KeyEntry,
  ToolHealth,
  UsageSummary,
} from "../api/types";

/** Deterministic Phase 2 fixtures: tools, settings, keys, usage. */

export const MOCK_TOOLS: ToolHealth[] = [
  {
    tool: "semgrep",
    binary: "semgrep",
    path: "/usr/local/bin/semgrep",
    available: true,
    version: "1.178.0",
    hint: null,
  },
  {
    tool: "gitleaks",
    binary: "gitleaks",
    path: "/usr/local/bin/gitleaks",
    available: true,
    version: "8.18.4",
    hint: null,
  },
  {
    tool: "spotbugs",
    binary: "spotbugs",
    path: null,
    available: false,
    version: null,
    hint: "Install spotbugs on PATH",
  },
  {
    tool: "owasp-dependency-check",
    binary: "dependency-check",
    path: null,
    available: false,
    version: null,
    hint: "Install dependency-check on PATH",
  },
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
  total_budget: 50.0,
  total_spent: 3.42,
  available: 46.58,
  by_provider: { "kios-free": 3.42 },
  run_count: 3,
};
