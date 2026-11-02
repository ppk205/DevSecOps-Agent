import { useState } from "react";
import { useStrings } from "../../i18n/lang";

export function CommandMenu({ query, onSelect, onClose }: { query: string; onSelect: (command: string) => void; onClose: () => void }) {
  const s = useStrings().remote;
  const [selected, setSelected] = useState(-1);
  const items = Object.entries(s.commandDescriptions).filter(([name, description]) => `${name} ${description}`.toLowerCase().includes(query.toLowerCase()));
  return <section aria-label={s.commands} className="border border-hairline bg-card p-3" onKeyDown={(e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); onClose(); }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); setSelected((old) => old < 0 ? 0 : (old + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length); }
    if (e.key === "Enter" && e.target === e.currentTarget) { e.preventDefault(); if (selected >= 0 && items[selected]) onSelect(items[selected][0]); }
  }} tabIndex={0}>
    <h3 className="label-m text-sm text-ink">{s.commands}</h3>
    <p className="mb-2 text-xs text-muted">{s.commandHint}</p>
    <ul className="grid max-h-60 gap-1 overflow-auto sm:grid-cols-2">{items.map(([name, description], index) => <li key={name}>
      <button type="button" className={`w-full p-2 text-left text-sm hover:bg-elevated ${selected === index ? "outline outline-2 outline-white" : ""}`} onFocus={() => setSelected(index)} onClick={() => onSelect(name)}>
        <span className="font-mono text-ink">/{name}</span> <span className="text-muted">{description}</span>
      </button>
    </li>)}</ul>
  </section>;
}
