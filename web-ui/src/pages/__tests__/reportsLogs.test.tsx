import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../../App";

vi.stubEnv("VITE_MOCK", "1");

function renderAt(
  path: string,
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } }),
) {
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Reports page (mock mode)", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_MOCK", "1");
  });

  it("lists formats with download and generate actions", async () => {
    renderAt("/reports");
    expect(await screen.findByText("Generate, preview, and download run artifacts.")).toBeInTheDocument();
    expect(await screen.findByText("csv", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findAllByText("Download", {}, { timeout: 5000 })).not.toHaveLength(0);
    expect(await screen.findAllByText("Generate", {}, { timeout: 5000 })).not.toHaveLength(0);
    expect(await screen.findAllByText("Copy CLI command", {}, { timeout: 5000 })).not.toHaveLength(0);
  });

  it("shows the compare panel with per-scanner tables", async () => {
    renderAt("/reports");
    expect(await screen.findByText("Compare scans", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByText("Per scanner", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByText("Export comparison as HTML", {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("shows recorded benchmark metrics, no cost and the original run report (FR-63, FR-66)", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
    const reference = {
      run_id: 6,
      scenario: "A1",
      profile: "fast",
      commit: "abc123",
      model: "test-model",
      review_limit: 10,
      max_model_requests: 20,
      status: "completed",
      gate: "pass",
      duration_seconds: 20,
      scanners: [{ tool: "semgrep", status: "completed", eligible_units: 10, analyzed_units: 9, skipped_units: 1 }],
      requests: 8,
      completed_requests: 7,
      failed_requests: 1,
      http_attempts: 9,
      prompt_tokens: 1000,
      completion_tokens: 200,
      total_tokens: 1200,
      reviewed: 7,
      validated: 6,
      laya_devices: [],
      laya_timeouts: 0,
      comparable: false,
      comparison_reason: null,
      savings: null,
    };
    const laya = {
      ...reference,
      run_id: 7,
      scenario: "A3",
      review_limit: 5,
      max_model_requests: 12,
      duration_seconds: 10,
      stage_durations: [{ name: "scan", status: "completed", duration_seconds: 2.5 }],
      laya_devices: ["cpu"],
      laya_timeouts: 1,
      limitations: ["Laya timed out on one finding."],
      comparable: true,
      savings: { duration_percent: 50, requests_percent: null, tokens_percent: null },
    };
    client.setQueryData(["compare", 7, 6], {
      baseline: 7,
      scans: [],
      by_scanner: [],
      by_cwe: [],
      new: [],
      fixed: [],
      changed: [],
      benchmark: { reference_run_id: 6, rows: [laya, reference] },
    });

    renderAt("/reports", client);
    const benchmark = await screen.findByRole("region", { name: "Benchmark" });
    const referenceCard = within(benchmark).getByRole("article", { name: "A1 · #6" });
    expect(within(benchmark).queryByText(/cost/i)).not.toBeInTheDocument();
    expect(within(referenceCard).getByText("HTTP attempts").nextElementSibling).toHaveTextContent("9 / 20");
    expect(within(referenceCard).getByText(/semgrep.*9\/10.*1 skipped/)).toBeInTheDocument();
    const layaCard = within(benchmark).getByRole("article", { name: "A3 · #7" });
    expect(within(layaCard).getByText("Laya timeouts").nextElementSibling).toHaveTextContent("1");
    expect(within(layaCard).getByText("Laya timed out on one finding.")).toBeVisible();
    fireEvent.click(within(layaCard).getByText("Stage timings"));
    expect(within(layaCard).getByText(/scan.*completed.*2.5 s/)).toBeVisible();
    expect(within(layaCard).getByText("50%")).toBeInTheDocument();
    fireEvent.click(within(referenceCard).getByRole("button", { name: "Open run #6 report" }));
    expect(screen.getByLabelText("Scan")).toHaveValue("6");
  });
});

describe("Logs page (mock mode)", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_MOCK", "1");
  });

  it("streams lines with filters and actions", async () => {
    renderAt("/logs");
    expect(await screen.findByText("Stage output and the persisted event stream.")).toBeInTheDocument();
    expect(await screen.findByLabelText("Level", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByLabelText("Source", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByLabelText("Search (regex)", {}, { timeout: 5000 })).toBeInTheDocument();
    // Các dòng log mock stream đến so le nhau; thanh tiến trình phát lại 10 dòng.
    expect(await screen.findByText(/checkout verified at 9f3ac41/, {}, { timeout: 8000 })).toBeInTheDocument();
    expect(await screen.findByText("Pause", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByText("Copy", {}, { timeout: 5000 })).toBeInTheDocument();
  });
});
