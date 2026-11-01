/** EN strings dictionary (Phase 1). VI lands in Phase 6. */
export const en = {
  app: {
    name: "PIT WALL",
    tagline: "Local vulnerability scan console",
    footerNote: "Single-user local console · timestamps Asia/Saigon by default",
  },
  nav: {
    home: "Home",
    newScan: "New Scan",
    live: "Live Pipeline",
    findings: "Findings",
    reports: "Reports",
    logs: "Logs",
    apiKeys: "API Keys",
  },
  common: {
    loading: "Loading…",
    retry: "Retry",
    cancel: "Cancel",
    close: "Close",
    viewAll: "View all",
    mockBadge: "Mock mode — no backend",
    emptyTitle: "Nothing here yet",
    emptyBody: "Start a scan or adjust the filters to populate this view.",
  },
  home: {
    title: "Mission control",
    subtitle: "Recent scans, gate posture, and where to go next.",
  },
  newScan: {
    title: "New scan",
    subtitle: "Point at a repository checkout and launch the pipeline.",
  },
  live: {
    title: "Live pipeline",
    subtitle: "Stage progress and the event rail, as it happens.",
  },
  findings: {
    title: "Findings",
    subtitle: "Grouped, verified, and ready for review.",
  },
  reports: {
    title: "Reports",
    subtitle: "Generate, preview, and download run artifacts.",
  },
  logs: {
    title: "Logs",
    subtitle: "Stage output and the persisted event stream.",
  },
  apiKeys: {
    title: "API keys",
    subtitle: "Provider profiles for this machine. Secrets never leave it.",
  },
  styleguide: {
    title: "Styleguide",
    subtitle: "Tokens, type, components, charts. Hidden route — not in nav.",
  },
} as const;

export type Strings = typeof en;
