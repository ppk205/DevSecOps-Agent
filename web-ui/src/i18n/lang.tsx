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
 * Trạng thái ngôn ngữ: chuyển đổi EN/VI được lưu vào localStorage.
 * `document.documentElement.lang` đi theo chuyển đổi này phục vụ AT/SEO.
 * Khi không có provider (unit test), mọi thứ chuyển về dự phòng EN.
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
      // Chế độ riêng tư v.v. — ngôn ngữ vẫn được áp dụng cho phiên.
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

/** Từ điển phản ứng (reactive): re-render nơi gọi khi chuyển đổi EN↔VI. */
export function useStrings(): Strings {
  const { lang } = useContext(LangCtx);
  return DICTS[lang] ?? en;
}
