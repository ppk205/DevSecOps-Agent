export interface Tab {
  id: string;
  label: string;
}

interface TabsProps {
  tabs: Tab[];
  active: string;
  onChange: (id: string) => void;
}

export function Tabs({ tabs, active, onChange }: TabsProps) {
  return (
    <div role="tablist" className="flex gap-8 border-b border-hairline">
      {tabs.map((tab) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            role="tab"
            aria-selected={selected}
            onClick={() => onChange(tab.id)}
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
