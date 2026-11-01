import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { en } from "../en";
import { LANG_KEY, LanguageProvider, useLang, useStrings } from "../lang";
import { vi } from "../vi";

function keysOf(value: unknown, prefix = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, i) => keysOf(item, `${prefix}[${i}]`));
  }
  if (typeof value === "object" && value !== null) {
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) =>
      keysOf(v, prefix ? `${prefix}.${k}` : k),
    );
  }
  return [prefix];
}

function Probe() {
  const t = useStrings();
  const { lang, setLang } = useLang();
  return (
    <div>
      <span data-testid="nav-home">{t.nav.home}</span>
      <span data-testid="lang">{lang}</span>
      <button onClick={() => setLang("vi")}>to-vi</button>
      <button onClick={() => setLang("en")}>to-en</button>
    </div>
  );
}

describe("i18n dictionaries", () => {
  const store = new Map<string, string>();
  beforeEach(() => {
    store.clear();
    const stub = {
      getItem: (k: string) => (store.has(k) ? (store.get(k) as string) : null),
      setItem: (k: string, v: string) => {
        store.set(k, v);
      },
      removeItem: (k: string) => {
        store.delete(k);
      },
      clear: () => store.clear(),
    };
    Object.defineProperty(window, "localStorage", { value: stub, configurable: true });
    document.documentElement.lang = "en";
  });

  it("vi mirrors en key-for-key (same paths, same array lengths)", () => {
    expect(keysOf(vi).sort()).toEqual(keysOf(en).sort());
  });

  it("brand headlines stay UPPERCASE in both languages", () => {
    for (const dict of [en, vi]) {
      expect(dict.home.heroTitle).toBe(dict.home.heroTitle.toUpperCase());
      expect(dict.home.heroTitle.length).toBeGreaterThan(0);
    }
    expect(en.app.name).toBe("PIT WALL");
    expect(vi.app.name).toBe("PIT WALL");
  });

  it("falls back to EN without a provider", () => {
    render(<Probe />);
    expect(screen.getByTestId("nav-home")).toHaveTextContent("Home");
  });

  it("toggles EN↔VI, persists, and follows the lang attribute", async () => {
    render(
      <LanguageProvider>
        <Probe />
      </LanguageProvider>,
    );
    expect(screen.getByTestId("nav-home")).toHaveTextContent("Home");
    fireEvent.click(screen.getByText("to-vi"));
    expect(screen.getByTestId("nav-home")).toHaveTextContent("Trang chủ");
    expect(screen.getByTestId("lang")).toHaveTextContent("vi");
    expect(window.localStorage.getItem(LANG_KEY)).toBe("vi");
    expect(document.documentElement.lang).toBe("vi");
    fireEvent.click(screen.getByText("to-en"));
    expect(screen.getByTestId("nav-home")).toHaveTextContent("Home");
    expect(document.documentElement.lang).toBe("en");
  });
});
