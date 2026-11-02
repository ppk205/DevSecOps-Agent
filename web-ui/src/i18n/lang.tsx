import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { en, type Strings } from "./en";
import { vi } from "./vi";

export type Lang = "en" | "vi";

export const LANG_KEY = "pitwall.lang";

const DICTS: Record<Lang, Strings> = { en, vi };

function initialLang(): Lang {
  try {
    return window.localStorage.getItem(LANG_KEY) === "vi" ? "vi" : "en";
  } catch {
    return "en";
  }
}

/**
 * Language state: EN/VI toggle persisted to localStorage.
 * `document.documentElement.lang` follows the toggle for AT/SEO.
 * Without a provider (unit tests), everything falls back to EN.
 */
const LangCtx = createContext<{ lang: Lang; setLang: (l: Lang) => void }>({
  lang: "en",
  setLang: () => {},
});

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang);
  const setLang = useCallback((next: Lang) => {
    setLangState(next);
    try {
      window.localStorage.setItem(LANG_KEY, next);
    } catch {
      // Private mode etc. — language still applies for the session.
    }
  }, []);
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);
  return <LangCtx.Provider value={{ lang, setLang }}>{children}</LangCtx.Provider>;
}

export function useLang(): { lang: Lang; setLang: (l: Lang) => void } {
  return useContext(LangCtx);
}

/** Reactive dictionary: re-renders the caller on EN↔VI toggle. */
export function useStrings(): Strings {
  const { lang } = useContext(LangCtx);
  return DICTS[lang] ?? en;
}
