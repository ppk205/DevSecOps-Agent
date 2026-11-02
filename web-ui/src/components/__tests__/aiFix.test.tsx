import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { applyFix, fetchFixes, fetchKeys, requestFix } from "../../api/client";
import { FindingDrawer } from "../FindingDrawer";
import { FixProposals, FixStatusChip } from "../FixProposals";
import { FindingsPage } from "../../pages/FindingsPage";

vi.mock("../../api/client", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../api/client")>();
  return {
    ...orig,
    requestFix: vi.fn(() => Promise.resolve({ accepted: true, run_id: 7 })),
    fetchKeys: vi.fn(() =>
      Promise.resolve([
        {
          profile: "kios-free",
          label: "KiosAPI free",
          base_url: "https://kiosapi.com/v1",
          api_key_env: "KIOS_API_KEY",
          models: ["north-mini-code"],
          default_model: "north-mini-code",
          configured: true,
          masked: "••••8901",
        },
      ]),
    ),
    fetchFixes: vi.fn(() =>
      Promise.resolve({
        run_id: 7,
        proposals: [
          {
            id: "fix-mock-f-001",
            finding_id: "mock-f-001",
            status: "proposed",
            diff: "--- a/mock-f-001\n+++ b/mock-f-001\n- vulnerable\n+ remediated",
            model: "north-mini-code",
            error: null,
            overlay_path: null,
            verification: null,
          },
          {
            id: "fix-applied-1",
            finding_id: "mock-f-002",
            status: "applied",
            diff: "--- a/mock-f-002\n+++ b/mock-f-002",
            model: "north-mini-code",
            error: null,
            overlay_path: "overlays/run-7/fix-applied-1.patch",
            verification: { fixed: true, detail: "Re-scan: taint path removed." },
          },
          {
            id: "fix-verified-1",
            finding_id: "mock-f-003",
            status: "verified",
            diff: "--- a/mock-f-003\n+++ b/mock-f-003",
            model: "north-mini-code",
            error: null,
            overlay_path: "overlays/run-7/fix-verified-1.patch",
            verification: { fixed: true, detail: "Confirmed fixed on rebuild." },
          },
          {
            id: "fix-failed-1",
            finding_id: "mock-f-004",
            status: "failed",
            diff: "--- a/mock-f-004\n+++ b/mock-f-004",
            model: "north-mini-code",
            error: "patch did not apply",
            overlay_path: null,
            verification: null,
          },
        ],
      }),
    ),
    applyFix: vi.fn((runId: number, proposalId: string) =>
      Promise.resolve({
        id: proposalId,
        status: "applied",
        overlay_path: `overlays/run-${runId}/${proposalId}.patch`,
        verification: { fixed: true, detail: "Re-scan: taint path removed." },
      }),
    ),
  };
});

const mockedRequestFix = vi.mocked(requestFix);
const mockedFetchKeys = vi.mocked(fetchKeys);
const mockedFetchFixes = vi.mocked(fetchFixes);
const mockedApplyFix = vi.mocked(applyFix);

function queryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderDrawer() {
  return render(
    <QueryClientProvider client={queryClient()}>
      <MemoryRouter>
        <FindingDrawer
          findingId="mock-f-001"
          runId={7}
          onClose={vi.fn()}
          onPrev={vi.fn()}
          onNext={vi.fn()}
          hasPrev={false}
          hasNext
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AI fix UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("drawer renders a Propose fix button that posts that finding_id", async () => {
    renderDrawer();
    const button = await screen.findByRole("button", { name: "Propose fix" });
    expect(button).toBeInTheDocument();
    fireEvent.click(button);
    await waitFor(() =>
      expect(mockedRequestFix).toHaveBeenCalledWith(7, { finding_ids: ["mock-f-001"] }),
    );
    expect(await screen.findByText("Fix requested.")).toBeInTheDocument();
  });

  it("drawer cloud consent is explicit and resets after one request", async () => {
    renderDrawer();
    const consent = await screen.findByRole("checkbox", { name: /allow cloud model/i });
    expect(consent).not.toBeChecked();
    fireEvent.click(consent);
    fireEvent.click(screen.getByRole("button", { name: "Propose fix" }));
    await waitFor(() =>
      expect(mockedRequestFix).toHaveBeenCalledWith(7, {
        finding_ids: ["mock-f-001"],
        allow_cloud_model: true,
      }),
    );
    await waitFor(() => expect(consent).not.toBeChecked());
  });

  it("fix-all posts null ids with the first key profile as default", async () => {
    render(
      <QueryClientProvider client={queryClient()}>
        <MemoryRouter>
          <FindingsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const fixAll = await screen.findByRole("button", { name: "Fix all" });
    fireEvent.click(fixAll);
    await waitFor(() => expect(mockedFetchKeys).toHaveBeenCalled());
    await waitFor(() =>
      expect(mockedRequestFix).toHaveBeenCalledWith(7, {
        finding_ids: null,
        provider_profile: "kios-free",
      }),
    );
  });

  it("fix-all sends cloud permission only after checking consent", async () => {
    render(
      <QueryClientProvider client={queryClient()}>
        <MemoryRouter><FindingsPage /></MemoryRouter>
      </QueryClientProvider>,
    );
    const consent = await screen.findByRole("checkbox", { name: /allow cloud model/i });
    expect(consent).not.toBeChecked();
    fireEvent.click(consent);
    fireEvent.click(screen.getByRole("button", { name: "Fix all" }));
    await waitFor(() =>
      expect(mockedRequestFix).toHaveBeenCalledWith(7, {
        finding_ids: null,
        provider_profile: "kios-free",
        allow_cloud_model: true,
      }),
    );
    await waitFor(() => expect(consent).not.toBeChecked());
  });

  it("status chips render green/yellow/red variants", () => {
    const { rerender } = render(<FixStatusChip status="verified" />);
    expect(screen.getByTestId("fix-status-verified")).toHaveTextContent("Verified");
    rerender(<FixStatusChip status="proposed" />);
    expect(screen.getByTestId("fix-status-proposed")).toHaveTextContent("Proposed");
    rerender(<FixStatusChip status="applied" />);
    expect(screen.getByTestId("fix-status-applied")).toHaveTextContent("Applied");
    rerender(<FixStatusChip status="failed" />);
    expect(screen.getByTestId("fix-status-failed")).toHaveTextContent("Failed");
  });

  it("proposals view lists diffs, Apply posts apply, verification and error text show", async () => {
    render(
      <QueryClientProvider client={queryClient()}>
        <FixProposals runId={7} />
      </QueryClientProvider>,
    );
    expect(await screen.findByTestId("fix-proposal-fix-mock-f-001")).toBeInTheDocument();
    // Diff in <pre>
    const pres = document.querySelectorAll("pre");
    expect(pres.length).toBeGreaterThan(0);
    expect(pres[0].textContent).toContain("remediated");
    // Verification detail + error text
    expect(screen.getByText(/taint path removed/)).toBeInTheDocument();
    expect(screen.getByText(/patch did not apply/)).toBeInTheDocument();
    // Apply button posts apply
    const applyButtons = screen.getAllByRole("button", { name: "Apply" });
    expect(applyButtons.length).toBeGreaterThan(0);
    fireEvent.click(applyButtons[0]);
    await waitFor(() =>
      expect(mockedApplyFix).toHaveBeenCalledWith(7, "fix-mock-f-001"),
    );
    expect(mockedFetchFixes).toHaveBeenCalled();
  });
});
