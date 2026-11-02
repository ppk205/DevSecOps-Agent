import type { KeyboardEvent } from "react";

export interface Tab {
  id: string;
  label: string;
}

interface TabsProps {
  tabs: Tab[];
  active: string;
  onChange: (id: string) => void;
}

/**
 * APG tablist arrow-key behavior, shared by Tabs and the inline
 * tablists (live mobile tabs, findings origin tabs).
 */
export function onTabListKeyDown(
  e: KeyboardEvent<HTMLElement>,
  ids: string[],
  active: string,
  onChange: (id: string) => void,
) {
  if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "Home" && e.key !== "End") return;
  e.preventDefault();
  const i = Math.max(0, ids.indexOf(active));
  const next =
    e.key === "ArrowRight"
      ? ids[(i + 1) % ids.length]
      : e.key === "ArrowLeft"
        ? ids[(i - 1 + ids.length) % ids.length]
        : e.key === "Home"
          ? ids[0]
          : ids[ids.length - 1];
  onChange(next);
  const list = e.currentTarget.parentElement;
  list?.querySelector<HTMLElement>(`[data-tab="${next}"]`)?.focus();
}

export function Tabs({ tabs, active, onChange }: TabsProps) {
  const ids = tabs.map((t) => t.id);
  return (
    <div role="tablist" className="flex gap-8 border-b border-hairline">
      {tabs.map((tab) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            role="tab"
            data-tab={tab.id}
            aria-selected={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.id)}
            onKeyDown={(e) => onTabListKeyDown(e, ids, active, onChange)}
            className={`label-m pb-3 text-xs transition-colors duration-150 ease-out ${
              selected ? "text-ink" : "text-muted hover:text-body"
            }`}
            style={selected ? { boxShadow: "inset 0 -2px 0 #e22718" } : undefined}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}
