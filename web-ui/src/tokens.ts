/** PIT WALL design tokens — BMW M dark. No BMW logos/wordmark anywhere. */
export const tokens = {
  color: {
    canvas: "#000000",
    surfaceSoft: "#0d0d0d",
    surfaceCard: "#1a1a1a",
    surfaceElevated: "#262626",
    carbon: "#2b2b2b",
    hairline: "#3c3c3c",
    ink: "#ffffff",
    body: "#bbbbbb",
    // WCAG AA on canvas/soft/card/elevated (4.74:1 worst case on #262626).
    muted: "#909090",
    mBlueLight: "#0066b1",
    mBlueDark: "#1c69d4",
    mRed: "#e22718",
    electricBlue: "#0653b6",
    warning: "#f4b400",
    success: "#0fa336",
  },
  stripe: ["#0066b1", "#1c69d4", "#e22718"] as const,
  radius: { none: 0, iconButton: 48 } as const,
  maxWidth: 1440,
  sectionGap: 96,
  motionMs: { fast: 150, base: 200, slow: 250 } as const,
} as const;

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type VerificationState =
  | "confirmed"
  | "unresolved"
  | "rejected"
  | "unprocessed";

export const severityColor: Record<Severity, string> = {
  critical: tokens.color.mRed,
  high: tokens.color.mRed,
  medium: tokens.color.warning,
  low: tokens.color.mBlueDark,
  info: tokens.color.muted,
};

export const verificationColor: Record<VerificationState, string> = {
  confirmed: tokens.color.mRed,
  unresolved: tokens.color.warning,
  rejected: tokens.color.muted,
  unprocessed: tokens.color.mBlueDark,
};
