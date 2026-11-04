import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { CvssSummary } from "../CvssSummary";

it("labels Base and contextual scores separately without approving metric assumptions", () => {
  render(<CvssSummary cvss={{ vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P", base_score: 9.3, overall_score: 8.9, nomenclature: "CVSS-BT", calculation_source: "FIRST CVSS v4.0", metric_assumptions_verified: false }} />);
  expect(screen.getByText("Base: 9.3")).toBeInTheDocument();
  expect(screen.getByText("CVSS-BT: 8.9")).toBeInTheDocument();
  expect(screen.getByText(/does not verify metric assumptions/)).toBeInTheDocument();
});

it("keeps zero distinct from an unscored vector and identifies legacy provenance", () => {
  const view = render(<CvssSummary cvss={{ vector: "legacy", base_score: 0 }} />);
  expect(screen.getByText("Base: 0")).toBeInTheDocument();
  expect(screen.getByText(/Legacy score/)).toBeInTheDocument();
  view.rerender(<CvssSummary cvss={{ vector: "incomplete", base_score: null }} />);
  expect(screen.getByText("Unscored")).toBeInTheDocument();
});
