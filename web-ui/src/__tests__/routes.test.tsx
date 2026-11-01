import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
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

const ROUTES: [string, RegExp][] = [
  ["/", /Mission control/],
  ["/scans/new", /New scan/],
  ["/live", /Live pipeline/],
  ["/findings", /Grouped, verified/],
  ["/reports", /Generate, preview/],
  ["/logs", /persisted event stream/],
  ["/keys", /never leave it/],
];

describe("Phase 6 acceptance: all 7 nav destinations reachable", () => {
  for (const [path, marker] of ROUTES) {
    it(`renders ${path}`, async () => {
      const { unmount } = renderAt(path);
      expect(await screen.findByText(marker, {}, { timeout: 8000 })).toBeInTheDocument();
      unmount();
    });
  }

  it("unknown routes fall back to Not found", async () => {
    renderAt("/nope");
    expect(await screen.findByText("Not found", {}, { timeout: 5000 })).toBeInTheDocument();
  });
});
