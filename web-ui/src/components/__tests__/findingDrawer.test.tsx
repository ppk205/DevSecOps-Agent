import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { FindingDrawer } from "../FindingDrawer";

vi.stubEnv("VITE_MOCK", "1");

function renderDrawer() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const props = { runId: 7, onClose: vi.fn(), onPrev: vi.fn(), onNext: vi.fn() };
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <FindingDrawer findingId="mock-f-001" hasPrev={false} hasNext {...props} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return props;
}

describe("FindingDrawer (mock mode)", () => {
  it("shows assessment, evidence, and claim-vs-check sections", async () => {
    renderDrawer();
    expect(await screen.findByText("AI assessment")).toBeInTheDocument();
    expect(await screen.findByText("Claim vs check")).toBeInTheDocument();
    expect(await screen.findByText("Taint path")).toBeInTheDocument();
  });

  it("toggles raw JSON with the V key", async () => {
    renderDrawer();
    await screen.findByText("AI assessment");
    expect(screen.queryByText(/"finding_id"/)).not.toBeInTheDocument();
    fireEvent.keyDown(window, { key: "v" });
    expect(await screen.findByText(/"finding_id"/)).toBeInTheDocument();
  });
});
