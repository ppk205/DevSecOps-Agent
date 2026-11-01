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

describe("Phase 2 pages (mock mode, standalone)", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_MOCK", "1");
  });

  it("home renders hero, KPIs, charts, tool strip, 8 steps, history, CTA", async () => {
    renderAt("/");
    expect(await screen.findByText("FIND. VERIFY. SHIP SECURE.", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByText("Latest scan", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText("Findings by severity")).toBeInTheDocument();
    expect(screen.getByText("Top CWEs")).toBeInTheDocument();
    expect(await screen.findByRole("list", { name: "Scanner health" }, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText("semgrep")).toBeInTheDocument();
    expect(screen.getByText("How it works")).toBeInTheDocument();
    expect(screen.getByText("Scan history")).toBeInTheDocument();
    expect(screen.getByText("Ready to ship secure?")).toBeInTheDocument();
  });

  it("new scan renders TUI-mirror form, disabled DEEP, review panel, CLI command", async () => {
    renderAt("/scans/new");
    expect(await screen.findByText("Scan profile", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/github\.com\/org/)).toBeInTheDocument();
    expect(screen.getAllByText("Scanners").length).toBeGreaterThan(0);
    const deep = screen.getByRole("radio", { name: /DEEP/ });
    expect(deep).toBeDisabled();
    expect(screen.getByRole("switch", { name: "AI review" })).toBeInTheDocument();
    expect(screen.getByText("Equivalent CLI command")).toBeInTheDocument();
    expect(screen.getByText(/devsecops-agent scan/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start scan" })).toBeInTheDocument();
  });

  it("new scan start queues a run and shows the confirmation", async () => {
    renderAt("/scans/new");
    const start = await screen.findByRole("button", { name: "Start scan" }, { timeout: 5000 });
    fireEvent.click(start);
    expect(await screen.findByText(/Scan queued #8/, {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("keys page renders provider, scanners, usage, general sections masked", async () => {
    renderAt("/keys");
    expect(await screen.findByText("AI provider", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText("Scanner tools")).toBeInTheDocument();
    expect(screen.getByText("Usage & budget")).toBeInTheDocument();
    expect(screen.getByText("General")).toBeInTheDocument();
    // Masked last-4 from the fixture; the full secret never ships in mock data.
    expect(await screen.findByText("••••8901", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.queryByText(/sk-/)).not.toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Paste a new key/)).toHaveAttribute("type", "password");
    expect(screen.getByText("$3.42")).toBeInTheDocument();
  });
});
