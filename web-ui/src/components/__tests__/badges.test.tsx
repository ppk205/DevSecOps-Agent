import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge } from "../SeverityBadge";
import { VerificationBadge } from "../VerificationBadge";

describe("SeverityBadge", () => {
  it("renders the critical label in ink with an M-red chip (WCAG AA on soft)", () => {
    render(<SeverityBadge severity="critical" />);
    const badge = screen.getByTestId("severity-critical");
    expect(badge).toHaveTextContent("Critical");
    // Label text is ink (4.5:1+ on bg-soft); the brand color lives on the chip.
    expect(badge.style.color).toBe("");
    expect(badge.className).toContain("text-ink");
    const chip = badge.querySelector("span[aria-hidden]");
    expect(chip?.getAttribute("style")).toContain("rgb(226, 39, 24)");
  });

  it("renders all five severities", () => {
    const { unmount } = render(
      <>
        <SeverityBadge severity="high" />
        <SeverityBadge severity="medium" />
        <SeverityBadge severity="low" />
        <SeverityBadge severity="info" />
      </>,
    );
    expect(screen.getByTestId("severity-high")).toBeInTheDocument();
    expect(screen.getByTestId("severity-medium")).toBeInTheDocument();
    expect(screen.getByTestId("severity-low")).toBeInTheDocument();
    expect(screen.getByTestId("severity-info")).toBeInTheDocument();
    unmount();
  });
});

describe("VerificationBadge", () => {
  it("renders the confirmed state", () => {
    render(<VerificationBadge state="confirmed" />);
    expect(screen.getByTestId("verification-confirmed")).toHaveTextContent("Confirmed");
  });
});
