import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
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
    expect(await screen.findByLabelText("Search", {}, { timeout: 5000 })).toBeInTheDocument();
    // Streamed mock lines arrive staggered; the rail replays 10 lines.
    expect(await screen.findByText(/checkout verified at 9f3ac41/, {}, { timeout: 8000 })).toBeInTheDocument();
    expect(await screen.findByText("Pause", {}, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByText("Copy", {}, { timeout: 5000 })).toBeInTheDocument();
  });
});
