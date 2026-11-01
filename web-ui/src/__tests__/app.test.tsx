import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";

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

describe("App shell (mock mode, no backend)", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_MOCK", "1");
  });

  it("renders the 7-item topnav", () => {
    renderAt("/");
    for (const label of ["Home", "New Scan", "Live Pipeline", "Findings", "Reports", "Logs", "API Keys"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it("renders home with the mock scan once loaded", async () => {
    renderAt("/");
    expect(await screen.findByText("Mission control")).toBeInTheDocument();
    expect(await screen.findByText("Gate posture", {}, { timeout: 5000 })).toBeInTheDocument();
    const runCells = await screen.findAllByText(
      (_, el) => el?.textContent === "#7",
      {},
      { timeout: 5000 },
    );
    expect(runCells.length).toBeGreaterThan(0);
  });

  it("renders the hidden styleguide with tokens and components", async () => {
    renderAt("/styleguide");
    expect(await screen.findByText("Styleguide")).toBeInTheDocument();
    expect(screen.getByText(/mBlueLight/)).toBeInTheDocument();
    expect(screen.getByText("M stripe (divider/rail only)")).toBeInTheDocument();
  });

  it("renders the findings table from the scripted mock run", async () => {
    renderAt("/findings");
    expect(await screen.findByText("mock-f-001")).toBeInTheDocument();
  });
});
