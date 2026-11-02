import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ackNotification, fixDiffUrl } from "../../api/client";
import { NotificationsBell } from "../NotificationsBell";
import { FixProposals } from "../FixProposals";

vi.mock("../../api/client", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../../api/client")>();
  return {
    ...orig,
    fetchNotifications: vi.fn(() =>
      Promise.resolve({
        notifications: [
          {
            id: 1,
            run_id: 7,
            kind: "scan_completed",
            message: "Scan #7 completed — gate pass.",
            is_read: false,
            created_at: "2026-11-02T00:00:00+00:00",
          },
          {
            id: 2,
            run_id: 7,
            kind: "gate_failed",
            message: "Scan #7 gate failed.",
            is_read: true,
            created_at: "2026-11-02T00:00:00+00:00",
          },
        ],
        unread: 1,
      }),
    ),
    ackNotification: vi.fn((id: number) =>
      Promise.resolve({
        id,
        run_id: 7,
        kind: "scan_completed",
        message: "Scan #7 completed — gate pass.",
        is_read: true,
        created_at: "2026-11-02T00:00:00+00:00",
      }),
    ),
    fetchFixes: vi.fn(() =>
      Promise.resolve({
        run_id: 7,
        proposals: [
          {
            id: "11",
            finding_id: "f-001",
            status: "proposed",
            diff: "--- a/f\n+++ b/f\n- x\n+ y",
            model: "m",
            error: null,
            overlay_path: null,
            verification: null,
          },
          {
            id: "12",
            finding_id: "f-002",
            status: "verified",
            diff: "--- a/g\n+++ b/g\n- x\n+ y",
            model: "m",
            error: null,
            overlay_path: "overlays/12.patch",
            verification: { fixed: true, detail: "Confirmed fixed on rebuild." },
          },
          {
            id: "13",
            finding_id: "f-003",
            status: "failed",
            diff: "--- a/h\n+++ b/h",
            model: "m",
            error: "patch did not apply",
            overlay_path: null,
            verification: null,
          },
        ],
      }),
    ),
  };
});

const mockedAck = vi.mocked(ackNotification);

function queryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderBell() {
  return render(
    <QueryClientProvider client={queryClient()}>
      <MemoryRouter>
        <NotificationsBell />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("NotificationsBell", () => {
  it("shows the unread count and opens a panel with ack", async () => {
    renderBell();
    expect(await screen.findByTestId("notifications-unread")).toHaveTextContent("1");
    fireEvent.click(screen.getByTestId("notifications-bell"));
    expect(await screen.findByTestId("notifications-panel")).toBeInTheDocument();
    expect(screen.getByTestId("notification-1")).toHaveTextContent("Scan #7 completed");
    // Read notification has no ack button; unread one does.
    expect(screen.queryByTestId("notification-ack-2")).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId("notification-ack-1"));
    await waitFor(() => expect(mockedAck).toHaveBeenCalledWith(1));
  });
});

describe("fix .diff download", () => {
  it("builds the download URL per proposal", () => {
    expect(fixDiffUrl(7, 11)).toMatch(/scans\/7\/fixes\/11\/download$/);
  });

  it("renders a Download .diff link on proposed/verified proposals only", async () => {
    render(
      <QueryClientProvider client={queryClient()}>
        <MemoryRouter>
          <FixProposals runId={7} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const proposed = await screen.findByTestId("fix-download-11");
    expect(proposed.getAttribute("href")).toMatch(/scans\/7\/fixes\/11\/download$/);
    const verified = screen.getByTestId("fix-download-12");
    expect(verified.getAttribute("href")).toMatch(/scans\/7\/fixes\/12\/download$/);
    expect(screen.queryByTestId("fix-download-13")).not.toBeInTheDocument();
  });
});
