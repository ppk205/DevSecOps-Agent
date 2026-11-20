import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../../App";
import { mockApi } from "../../mock/mockClient";

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
    expect(screen.getByText("native-hunt")).toBeInTheDocument();
    expect(screen.getByText("How it works")).toBeInTheDocument();
    expect(screen.getByText("Scan history")).toBeInTheDocument();
    expect(screen.getByText("Ready to ship secure?")).toBeInTheDocument();
  });

  it("new scan renders TUI-mirror form, selectable DEEP, hunt switch, review panel, CLI command", async () => {
    renderAt("/scans/new");
    expect(await screen.findByText("Scan profile", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/github\.com\/org/)).toBeInTheDocument();
    expect(screen.getAllByText("Scanners").length).toBeGreaterThan(0);
    const deep = screen.getByRole("radio", { name: /DEEP/ });
    expect(deep).not.toBeDisabled();
    fireEvent.click(deep);
    expect(deep).toHaveAttribute("aria-checked", "true");
    fireEvent.click(screen.getByRole("switch", { name: "Allow cloud model" }));
    expect(screen.getByRole("switch", { name: "AI review" })).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Model hunt" })).toBeInTheDocument();
    expect(screen.getByText("Equivalent CLI command")).toBeInTheDocument();
    expect(screen.getByText(/devsecops-agent scan/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Start scan" })).toBeInTheDocument();
  });

  it("new scan keeps model stages off until the cloud model is allowed", async () => {
    const spy = vi.spyOn(mockApi, "createScan");
    renderAt("/scans/new");
    const start = await screen.findByRole("button", { name: "Start scan" }, { timeout: 5000 });
    expect(screen.queryByRole("switch", { name: "Model hunt" })).not.toBeInTheDocument();
    expect(screen.getByText(/--mode deterministic/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("switch", { name: "Laya routing" }));
    fireEvent.change(screen.getByLabelText(/Pinned commit/), { target: { value: "abc123" } });
    fireEvent.change(screen.getByLabelText("Fail the gate at"), { target: { value: "critical" } });
    fireEvent.click(start);
    await waitFor(() =>
      expect(spy).toHaveBeenLastCalledWith(
        expect.objectContaining({
          mode: "deterministic",
          ai_review: false,
          ai_report: false,
          laya: false,
          fail_on: "critical",
          allow_cloud_model: false,
          commit_sha: "abc123",
          provider_profile: null,
        }),
      ),
    );

    await screen.findByText(/Scan queued/, {}, { timeout: 5000 });
    fireEvent.click(screen.getByRole("switch", { name: "Allow cloud model" }));
    expect(screen.getByRole("switch", { name: "AI report" })).toHaveAttribute("aria-checked", "true");
    fireEvent.change(screen.getByLabelText("Provider profile"), { target: { value: "omni" } });
    fireEvent.click(start);
    await waitFor(() =>
      expect(spy).toHaveBeenLastCalledWith(
        expect.objectContaining({
          mode: "hunt",
          ai_review: true,
          ai_report: true,
          allow_cloud_model: true,
          provider_profile: "omni",
        }),
      ),
    );
    expect(screen.getByText(/--provider omni/)).toBeInTheDocument();
  });

  it("new scan start queues a run and shows the confirmation", async () => {
    renderAt("/scans/new");
    const start = await screen.findByRole("button", { name: "Start scan" }, { timeout: 5000 });
    fireEvent.click(start);
    expect(await screen.findByText(/Scan queued #8/, {}, { timeout: 5000 })).toBeInTheDocument();
  });

  it("shows backend profile defaults and submits only deliberate scanner overrides", async () => {
    const spy = vi.spyOn(mockApi, "createScan");
    renderAt("/scans/new");
    expect(await screen.findByRole("switch", { name: "semgrep" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByRole("switch", { name: "trivy" })).toHaveAttribute("aria-checked", "false");
    expect(screen.queryByRole("switch", { name: "spotbugs" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("radio", { name: /DEEP/ }));
    expect(screen.getByRole("switch", { name: "trivy" })).toHaveAttribute("aria-checked", "true");
    expect(screen.getByText(/devsecops-agent scan-run.*--profile full/)).toBeInTheDocument();
    const start = screen.getByRole("button", { name: "Start scan" });
    fireEvent.click(start);
    await waitFor(() => expect(spy).toHaveBeenLastCalledWith(expect.objectContaining({ profile: "full", tools: null })));
    await screen.findByText(/Scan queued/);

    fireEvent.click(screen.getByRole("switch", { name: "trivy" }));
    expect(screen.queryByText(/devsecops-agent scan-run/)).not.toBeInTheDocument();
    fireEvent.click(start);
    await waitFor(() => expect(spy).toHaveBeenLastCalledWith(expect.objectContaining({
      profile: "full", tools: ["semgrep", "native-hunt", "gitleaks", "owasp-dependency-check"],
    })));
    spy.mockRestore();
  });

  it("keys page renders provider, scanners, usage, general sections masked", async () => {
    renderAt("/keys");
    expect(await screen.findByText("AI provider", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.getByText("Scanner tools")).toBeInTheDocument();
    expect(screen.getByText("Usage & budget")).toBeInTheDocument();
    expect(screen.getByText("General")).toBeInTheDocument();
    // 4 ký tự cuối đã che từ fixture; secret đầy đủ không bao giờ được gửi trong dữ liệu mock.
    expect(await screen.findByText("••••8901", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.queryByText(/sk-/)).not.toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Paste a new key/)).toHaveAttribute("type", "password");
    expect(screen.getByText("$3.42")).toBeInTheDocument();
  });
});
