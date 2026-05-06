import { useRef, type KeyboardEvent, type ReactNode } from "react";
import "./Tabs.css";

export interface Tab {
  id: string;
  label: string;
}

export interface TabsProps {
  tabs: Tab[];
  activeTab: string;
  onTabChange: (tabId: string) => void;
  children?: ReactNode;
  className?: string;
}

export function Tabs({
  tabs,
  activeTab,
  onTabChange,
  children,
  className,
}: TabsProps) {
  const classes = ["tabs", className].filter(Boolean).join(" ");
  const tablistRef = useRef<HTMLDivElement>(null);

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    if (tabs.length === 0) return;
    e.preventDefault();
    const idx = tabs.findIndex((t) => t.id === activeTab);
    const base = idx === -1 ? 0 : idx;
    const next =
      e.key === "ArrowRight"
        ? (base + 1) % tabs.length
        : (base - 1 + tabs.length) % tabs.length;
    const nextTab = tabs[next];
    onTabChange(nextTab.id);
    tablistRef.current
      ?.querySelector<HTMLButtonElement>(`[data-tab-id="${nextTab.id}"]`)
      ?.focus();
  };

  return (
    <div className={classes}>
      <div
        ref={tablistRef}
        className="tabs-list"
        role="tablist"
        onKeyDown={handleKeyDown}
      >
        {tabs.map((tab) => {
          const selected = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={`tab-${tab.id}`}
              data-tab-id={tab.id}
              aria-selected={selected}
              aria-controls={`tabpanel-${tab.id}`}
              tabIndex={selected ? 0 : -1}
              className={`tabs-tab ${selected ? "tabs-tab--active" : ""}`}
              onClick={() => onTabChange(tab.id)}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
      {children && (
        <div
          id={`tabpanel-${activeTab}`}
          className="tabs-content"
          role="tabpanel"
          aria-labelledby={`tab-${activeTab}`}
          tabIndex={0}
        >
          {children}
        </div>
      )}
    </div>
  );
}
