import { NavLink, Outlet } from "react-router-dom";
import { isMock } from "../mock/mockClient";
import { NotificationsBell } from "../components/NotificationsBell";
import { StripeDivider } from "../components/StripeDivider";
import { useLang, useStrings } from "../i18n/lang";

/**
 * PIT WALL shell: 64px black topnav with 7 nav items,
 * 4px M-stripe progress rail, content, footer.
 */
export function Shell() {
  const en = useStrings();
  const { lang, setLang } = useLang();
  const NAV: { to: string; label: string }[] = [
    { to: "/", label: en.nav.home },
    { to: "/scans/new", label: en.nav.newScan },
    { to: "/live", label: en.nav.live },
    { to: "/findings", label: en.nav.findings },
    { to: "/reports", label: en.nav.reports },
    { to: "/logs", label: en.nav.logs },
    { to: "/keys", label: en.nav.apiKeys },
  ];
  return (
    <div className="flex min-h-screen flex-col bg-canvas">
      <header className="bg-canvas">
        <nav aria-label="Primary" className="mx-auto flex h-16 max-w-pitwall items-center gap-2 overflow-visible px-6">
          <NavLink to="/" className="label-m mr-8 shrink-0 text-sm text-ink no-underline">
            PIT&nbsp;WALL
          </NavLink>
          <div className="flex min-w-0 flex-1 items-center gap-2 overflow-x-auto">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `label-m shrink-0 px-3 py-2 text-xs no-underline transition-colors duration-150 ease-out ${
                  isActive ? "text-ink" : "text-muted hover:text-body"
                }`
              }
              style={({ isActive }) =>
                isActive ? { boxShadow: "inset 0 -2px 0 #e22718" } : undefined
              }
            >
              {item.label}
            </NavLink>
          ))}
          </div>
          <div className="ml-auto flex shrink-0 items-center gap-3">
            <NotificationsBell />
            <div role="group" aria-label={en.shell.language} className="flex items-center border border-hairline">
              {(["en", "vi"] as const).map((code) => (
                <button
                  key={code}
                  type="button"
                  aria-pressed={lang === code}
                  onClick={() => setLang(code)}
                  className={`label-m px-2 py-1.5 text-[11px] transition-colors duration-150 ease-out ${
                    lang === code ? "bg-elevated text-ink" : "text-muted hover:text-body"
                  }`}
                >
                  {code.toUpperCase()}
                </button>
              ))}
            </div>
            {isMock && (
              <span className="label-m border border-warning px-2 py-1 text-[10px] text-warning">
                {en.common.mockBadge}
              </span>
            )}
            <a
              href="/"
              className="label-m text-[10px] text-muted no-underline transition-colors hover:text-body"
              title={en.shell.legacyTitle}
            >
              {en.app.legacyUi}
            </a>
          </div>
        </nav>
        <StripeDivider />
      </header>

      <main className="mx-auto w-full max-w-pitwall flex-1 px-6 py-12">
        <Outlet />
      </main>

      <footer className="border-t border-hairline">
        <div className="mx-auto flex max-w-pitwall flex-wrap items-center gap-x-6 gap-y-2 px-6 py-5 text-xs text-muted">
          <span className="label-m text-[11px] text-body">PIT WALL</span>
          <span>{en.app.footerNote}</span>
          <span className="ml-auto">Contract v1 · Phase 1 foundation</span>
        </div>
      </footer>
    </div>
  );
}
