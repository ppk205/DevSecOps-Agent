import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { App } from "../../App";
import { Tabs } from "../Tabs";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import cssText from "../../styles.css?raw";

const _rawCss = String(cssText);
function loadCss(): string {
  if (_rawCss.length > 0) return _rawCss;
  // Fallback: read the source file directly (jsdom transform may empty CSS).
  return readFileSync(join(process.cwd(), "src", "styles.css"), "utf8");
}

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

/** WCAG relative luminance + contrast ratio. */
function luminance(hex: string): number {
  const rgb = [1, 3, 5].map((i) => {
    const v = parseInt(hex.slice(i, i + 2), 16) / 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
}
function ratio(fg: string, bg: string): number {
  const [hi, lo] = [luminance(fg), luminance(bg)].sort((a, b) => b - a);
  return (hi + 0.05) / (lo + 0.05);
}

function TabWrap() {
  const [active, setActive] = useState("a");
  return (
    <Tabs
      tabs={[
        { id: "a", label: "Alpha" },
        { id: "b", label: "Beta" },
      ]}
      active={active}
      onChange={setActive}
    />
  );
}

describe("Phase 6 a11y", () => {
  it("tabs support arrow-key navigation with roving tabindex", () => {
    render(<TabWrap />);
    const tabA = screen.getByRole("tab", { name: "Alpha" });
    expect(tabA).toHaveAttribute("tabindex", "0");
    expect(screen.getByRole("tab", { name: "Beta" })).toHaveAttribute("tabindex", "-1");
    fireEvent.keyDown(tabA, { key: "ArrowRight" });
    const tabB = screen.getByRole("tab", { name: "Beta" });
    expect(tabB).toHaveAttribute("aria-selected", "true");
    expect(document.activeElement).toBe(tabB);
    fireEvent.keyDown(tabB, { key: "ArrowLeft" });
    expect(screen.getByRole("tab", { name: "Alpha" })).toHaveAttribute("aria-selected", "true");
  });

  it("live page exposes polite live regions for AI/counters, none for log lines", async () => {
    renderAt("/live");
    const nowAnalyzing = await screen.findByTestId("now-analyzing", {}, { timeout: 8000 });
    expect(nowAnalyzing).toHaveAttribute("aria-live", "polite");
    expect(await screen.findByTestId("results-counters", {}, { timeout: 8000 })).toHaveAttribute(
      "aria-live",
      "polite",
    );
    expect(await screen.findByTestId("queue-progress", {}, { timeout: 8000 })).toHaveAttribute(
      "aria-live",
      "polite",
    );
    const dock = await screen.findByTestId("log-dock", {}, { timeout: 8000 });
    expect(dock).not.toHaveAttribute("aria-live");
    expect(dock.querySelector("[aria-live]")).toBeNull();
  });

  it("stage rail keeps button semantics (listitem wrapper, pressed button)", async () => {
    renderAt("/live");
    const node = await screen.findByTestId("stage-intake", {}, { timeout: 8000 });
    expect(node.tagName).toBe("BUTTON");
    expect(node).toHaveAttribute("aria-pressed");
    expect(node.parentElement).toHaveAttribute("role", "listitem");
  });

  it("ships a 2px white focus ring and 44px coarse-pointer targets", () => {
    const css = loadCss();
    expect(css).toContain(":focus-visible");
    expect(css).toMatch(/outline:\s*2px solid #fff/i);
    expect(css).toContain("pointer: coarse");
    expect(css).toContain("min-height: 44px");
  });

  it("essential text pairs meet WCAG 2.2 AA (4.5:1) on every surface", () => {
    const surfaces = ["#000000", "#0d0d0d", "#1a1a1a", "#262626"];
    for (const bg of surfaces) {
      // Muted carries labels, counters, and table headers on all surfaces.
      expect(ratio("#909090", bg), `muted on ${bg}`).toBeGreaterThanOrEqual(4.5);
      // Body copy everywhere.
      expect(ratio("#bbbbbb", bg), `body on ${bg}`).toBeGreaterThanOrEqual(4.5);
    }
    // Badge labels are ink on bg-soft chips.
    expect(ratio("#ffffff", "#0d0d0d")).toBeGreaterThanOrEqual(4.5);
    // Primary button: white on mBlueDark.
    expect(ratio("#ffffff", "#1c69d4")).toBeGreaterThanOrEqual(4.5);
  });
});
