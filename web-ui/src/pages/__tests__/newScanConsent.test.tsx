import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const createScan = vi.fn();

vi.mock("../../api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../api/client")>();
  return {
    ...actual,
    createScan: (...args: unknown[]) => createScan(...args),
    fetchScans: async () => [],
    fetchTools: async () => ({ tools: [] }),
    fetchUsage: async () => ({ available: 0, spent: 0, budget: 0 }),
    fetchKeys: async () => [],
  };
});

import { NewScanPage } from "../NewScanPage";

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/scans/new"]}>
        <NewScanPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("New scan consent checkbox", () => {
  beforeEach(() => {
    createScan.mockReset();
    createScan.mockResolvedValue({ run_id: 1, status: "queued", profile: "fast" });
  });

  it("sends allow_cloud_model false unless the box is ticked", async () => {
    renderPage();
    fireEvent.click(screen.getByRole("switch", { name: "AI review" }));
    const box = screen.getByRole("checkbox", {
      name: "Allow code excerpts to leave this machine (cloud provider)",
    });
    expect(box).not.toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));
    await waitFor(() => expect(createScan).toHaveBeenCalledTimes(1));
    expect(createScan.mock.calls[0][0]).toMatchObject({
      allow_cloud_model: false,
      ai_review: true,
    });
  });

  it("sends allow_cloud_model true only after ticking", async () => {
    renderPage();
    fireEvent.click(screen.getByRole("switch", { name: "AI review" }));
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: "Allow code excerpts to leave this machine (cloud provider)",
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Start scan" }));
    await waitFor(() => expect(createScan).toHaveBeenCalled());
    expect(createScan.mock.calls[0][0]).toMatchObject({ allow_cloud_model: true });
  });

  it("shows the consent box only when AI review or hunt is selected", () => {
    renderPage();
    expect(
      screen.queryByRole("checkbox", {
        name: "Allow code excerpts to leave this machine (cloud provider)",
      }),
    ).toBeNull();
    fireEvent.click(screen.getByRole("switch", { name: "Model hunt" }));
    expect(
      screen.getByRole("checkbox", {
        name: "Allow code excerpts to leave this machine (cloud provider)",
      }),
    ).toBeInTheDocument();
  });
});
