import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge } from "../SeverityBadge";
import { VerificationBadge } from "../VerificationBadge";

describe("SeverityBadge", () => {
  it("renders the critical label in M red", () => {
    render(<SeverityBadge severity="critical" />);
    const badge = screen.getByTestId("severity-critical");
    expect(badge).toHaveTextContent("Critical");
    expect(badge.style.color).toBe("rgb(226, 39, 24)");
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
