import type { ReactNode } from "react";
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

  return (
    <div className={classes}>
      <div className="tabs-list" role="tablist">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={activeTab === tab.id}
            className={`tabs-tab ${activeTab === tab.id ? "tabs-tab--active" : ""}`}
            onClick={() => onTabChange(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {children && (
        <div className="tabs-content" role="tabpanel">
          {children}
        </div>
      )}
    </div>
  );
}
