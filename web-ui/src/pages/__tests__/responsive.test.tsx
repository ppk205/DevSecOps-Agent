import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
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

function srcFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      // Shipped code only: test files may name the patterns they forbid.
      if (entry !== "__tests__") srcFiles(full, out);
    } else if (/\.(tsx?|css)$/.test(entry)) out.push(full);
  }
  return out;
}

describe("Phase 6 responsive + motion", () => {
  it("live page ships mobile tabs and collapsing grids", async () => {
    const { container } = renderAt("/live");
    await screen.findByTestId("stage-intake", {}, { timeout: 8000 });
    // Mobile-only tab strip for the 3-column layout collapse.
    const mobileTabs = container.querySelector('[role="tablist"][aria-label="Live sections"]');
    expect(mobileTabs).not.toBeNull();
    expect(mobileTabs?.className).toContain("md:hidden");
    // Stage rail collapses 8 -> 4 -> 2 columns.
    const rail = screen.getByTestId("stage-intake").closest('[role="list"]');
    expect(rail?.className).toContain("grid-cols-2");
    expect(rail?.className).toContain("sm:grid-cols-4");
    expect(rail?.className).toContain("lg:grid-cols-8");
    // AI panel is hidden on mobile unless its tab is active.
    const aiSection = screen.getByText("AI agent panel").closest("section");
    expect(aiSection?.className).toContain("hidden");
    expect(aiSection?.className).toContain("md:block");
  });

  it("findings table scrolls horizontally instead of breaking layout", async () => {
    const { container } = renderAt("/findings");
    await screen.findByText("mock-f-001", {}, { timeout: 8000 });
    const scroller = container.querySelector(".card.overflow-x-auto");
    expect(scroller).not.toBeNull();
  });

  it("topnav scrolls horizontally on narrow screens", () => {
    const { container } = renderAt("/");
    const nav = container.querySelector('nav[aria-label="Primary"]');
    expect(nav?.className).toContain("overflow-x-auto");
  });

  it("motion budget: 150-250ms ease-out only, single sweep, reduced-motion honored", () => {
    const root = join(process.cwd(), "src");
    const texts = srcFiles(root).map((f) => readFileSync(f, "utf8"));
    // No tailwind animate utilities, no shimmer/pulse keyframes anywhere.
    for (const text of texts) {
      expect(text).not.toMatch(/animate-(spin|ping|pulse|bounce)/);
      expect(text.toLowerCase()).not.toContain("shimmer");
    }
    // No duration-* outside the 150-250ms budget.
    const durations = new Set<string>();
    for (const text of texts) {
      for (const m of text.matchAll(/duration-(\d+)/g)) durations.add(m[1]);
    }
    expect(durations.size).toBeGreaterThan(0);
    for (const d of durations) {
      const ms = Number(d);
      expect(ms, `duration-${d}`).toBeGreaterThanOrEqual(150);
      expect(ms, `duration-${d}`).toBeLessThanOrEqual(250);
    }
    // No non-ease-out timing functions.
    for (const text of texts) {
      expect(text).not.toMatch(/ease-(in|linear)/);
    }
    // Stage sweep runs once; reduced-motion kills animation/transition.
    const css = readFileSync(join(root, "styles.css"), "utf8");
    expect(css).toMatch(/animation:\s*pitwall-scan 200ms ease-out 1/);
    expect(css).not.toMatch(/animation:[^;]*infinite/);
    expect(css).toContain("prefers-reduced-motion");
  });
});
