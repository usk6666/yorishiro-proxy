import { useMemo, useState } from "react";
import { Badge } from "../../components/ui/Badge.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import type { TechnologiesResult, HostTechnologies } from "../../lib/mcp/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Map technology category to a human-readable display label. */
function categoryLabel(category: string): string {
  switch (category) {
    case "web_server": return "Server";
    case "framework": return "Framework";
    case "language": return "Language";
    case "cms": return "CMS";
    case "cdn": return "CDN";
    case "waf": return "WAF";
    case "js_framework": return "JS Framework";
    default: return category;
  }
}

/** Map technology category to a badge variant. */
function categoryVariant(category: string): "default" | "success" | "warning" | "danger" | "info" {
  switch (category) {
    case "web_server": return "info";
    case "framework": return "success";
    case "language": return "warning";
    case "cms": return "danger";
    case "cdn": return "info";
    case "waf": return "danger";
    case "js_framework": return "success";
    default: return "default";
  }
}

/** Map confidence level to a badge variant. */
function confidenceVariant(confidence: string): "default" | "success" | "warning" | "danger" | "info" {
  switch (confidence) {
    case "high": return "success";
    case "medium": return "warning";
    case "low": return "default";
    default: return "default";
  }
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface TechnologiesWidgetProps {
  data: TechnologiesResult | null;
  loading: boolean;
  error: Error | null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function TechnologiesWidget({ data, loading, error }: TechnologiesWidgetProps) {
  const [hostFilter, setHostFilter] = useState("");
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());

  const filteredHosts = useMemo(() => {
    if (!data?.hosts) return [];
    if (!hostFilter.trim()) return data.hosts;
    const lower = hostFilter.toLowerCase();
    return data.hosts.filter((h) => h.host.toLowerCase().includes(lower));
  }, [data, hostFilter]);

  const toggleHost = (host: string) => {
    setExpandedHosts((prev) => {
      const next = new Set(prev);
      if (next.has(host)) {
        next.delete(host);
      } else {
        next.add(host);
      }
      return next;
    });
  };

  if (loading && !data) {
    return (
      <div className="dashboard-section">
        <h2 className="dashboard-section-title">Technologies</h2>
        <div className="dashboard-empty">
          <Spinner size="sm" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard-section">
        <h2 className="dashboard-section-title">Technologies</h2>
        <div className="dashboard-empty">
          <span className="dashboard-card-error">Failed to load technologies</span>
        </div>
      </div>
    );
  }

  if (!data || data.count === 0) {
    return (
      <div className="dashboard-section">
        <h2 className="dashboard-section-title">Technologies</h2>
        <div className="dashboard-empty">No technologies detected yet.</div>
      </div>
    );
  }

  return (
    <div className="dashboard-section">
      <h2 className="dashboard-section-title">Technologies</h2>

      {data.count > 1 && (
        <div className="dashboard-tech-filter">
          <Input
            placeholder="Filter by hostname..."
            value={hostFilter}
            onChange={(e) => setHostFilter(e.target.value)}
          />
        </div>
      )}

      {filteredHosts.length === 0 ? (
        <div className="dashboard-empty">No hosts match the filter.</div>
      ) : (
        <div className="dashboard-tech-hosts">
          {filteredHosts.map((hostEntry) => (
            <HostAccordion
              key={hostEntry.host}
              hostEntry={hostEntry}
              expanded={expandedHosts.has(hostEntry.host)}
              onToggle={() => toggleHost(hostEntry.host)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// HostAccordion sub-component
// ---------------------------------------------------------------------------

interface HostAccordionProps {
  hostEntry: HostTechnologies;
  expanded: boolean;
  onToggle: () => void;
}

function HostAccordion({ hostEntry, expanded, onToggle }: HostAccordionProps) {
  // Group technologies by category for display
  const grouped = useMemo(() => {
    const map = new Map<string, typeof hostEntry.technologies>();
    for (const tech of hostEntry.technologies) {
      const existing = map.get(tech.category);
      if (existing) {
        existing.push(tech);
      } else {
        map.set(tech.category, [tech]);
      }
    }
    return map;
  }, [hostEntry]);

  return (
    <div className="dashboard-tech-host">
      <button
        type="button"
        className="dashboard-tech-host-header"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        <span className={`dashboard-tech-chevron ${expanded ? "dashboard-tech-chevron--open" : ""}`}>
          {"\u25B6"}
        </span>
        <span className="dashboard-tech-hostname">{hostEntry.host}</span>
        <Badge variant="default">{hostEntry.technologies.length} tech</Badge>
      </button>

      {expanded && (
        <div className="dashboard-tech-host-body">
          {Array.from(grouped.entries()).map(([category, techs]) => (
            <div key={category} className="dashboard-tech-category-group">
              <div className="dashboard-tech-category-label">
                <Badge variant={categoryVariant(category)}>{categoryLabel(category)}</Badge>
              </div>
              <div className="dashboard-tech-items">
                {techs.map((tech, index) => (
                  <div key={`${tech.name}-${tech.category}-${tech.version ?? index}`} className="dashboard-tech-item">
                    <span className="dashboard-tech-name">
                      {tech.name}
                      {tech.version && (
                        <span className="dashboard-tech-version">{tech.version}</span>
                      )}
                    </span>
                    <Badge variant={confidenceVariant(tech.confidence)}>
                      {tech.confidence}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
