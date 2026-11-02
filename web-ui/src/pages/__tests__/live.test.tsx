import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../../App";

vi.stubEnv("VITE_MOCK", "1");

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Phase 3 live pipeline (mock mode)", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_MOCK", "1");
  });

  it("renders the 8-node rail with a running stage", async () => {
    renderAt("/live");
    for (const node of [
      "stage-intake",
      "stage-model_hunt",
      "stage-scanners",
      "stage-laya_batch_routing",
      "stage-laya_verification",
      "stage-targeted_deep_analysis",
      "stage-independent_validation",
      "stage-final_report",
    ]) {
      expect(await screen.findByTestId(node, {}, { timeout: 5000 })).toBeInTheDocument();
    }
    expect(await screen.findByText("RUNNING", {}, { timeout: 8000 })).toBeInTheDocument();
  });

  it("shows the AI panel with NOW ANALYZING and a CVSS proposal", async () => {
    renderAt("/live");
    expect(await screen.findByTestId("now-analyzing", {}, { timeout: 8000 })).toBeInTheDocument();
    const vectors = await screen.findAllByTestId("cvss-vector", {}, { timeout: 8000 });
    expect(vectors.length).toBeGreaterThan(0);
    expect(vectors[0]).toHaveTextContent("CVSS:4.0");
  });

  it("renders confirmed-first results with counters and the claim table", async () => {
    renderAt("/live");
    expect(await screen.findByTestId("results-counters", {}, { timeout: 8000 })).toBeInTheDocument();
    const first = await screen.findByTestId("live-finding-mock-f-001", {}, { timeout: 8000 });
    expect(first).toBeInTheDocument();
    expect(await screen.findByText(/Claim vs verification/, {}, { timeout: 8000 })).toBeInTheDocument();
    expect(await screen.findByTestId("queue-progress", {}, { timeout: 8000 })).toBeInTheDocument();
  });

  it("supports click-to-filter and the timeline scrubber", async () => {
    renderAt("/live");
    // Wait for the scripted rail to load before scrubbing.
    await screen.findByText(/checkout verified/, {}, { timeout: 8000 });
    const node = await screen.findByTestId("stage-scanners", {}, { timeout: 8000 });
    fireEvent.click(node);
    expect(node).toHaveAttribute("aria-pressed", "true");
    expect(await screen.findByTestId("normalization-counter", {}, { timeout: 8000 })).toHaveTextContent("→");
    const timeline = await screen.findByLabelText("Timeline scrubber", {}, { timeout: 8000 });
    fireEvent.change(timeline, { target: { value: "5" } });
    expect(await screen.findByTestId("timeline-cursor", {}, { timeout: 8000 })).toHaveTextContent("#5");
  });

  it("streams scripted events into the log dock", async () => {
    renderAt("/live");
    await screen.findByText(/checkout verified/, {}, { timeout: 8000 });
    const dock = await screen.findByTestId("log-dock", {}, { timeout: 8000 });
    expect(dock.textContent ?? "").toContain("intake");
  });
});
