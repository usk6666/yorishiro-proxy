import { describe, expect, it } from "vitest";
import type { AnomalyEntry, FlowDetailResult } from "../../lib/mcp/types";

/**
 * Helper to create a minimal FlowDetailResult for testing.
 */
function makeFlow(
  overrides: Partial<FlowDetailResult> = {},
): FlowDetailResult {
  return {
    id: "test-id",
    conn_id: "conn-1",
    protocol: "HTTP/1.x",
    flow_type: "unary",
    state: "complete",
    method: "GET",
    url: "http://example.com/",
    request_headers: null,
    request_body: "",
    request_body_encoding: "",
    response_status_code: 200,
    response_headers: null,
    response_body: "",
    response_body_encoding: "",
    request_body_truncated: false,
    response_body_truncated: false,
    timestamp: "2025-01-01T00:00:00Z",
    duration_ms: 100,
    message_count: 1,
    ...overrides,
  };
}

/**
 * Simulates the anomaly display logic from FlowDetailPage.
 * Filters smuggling:* keys from tags when anomalies are present.
 */
function filterNonSmugglingTags(
  tags?: Record<string, string>,
): [string, string][] {
  if (!tags) return [];
  return Object.entries(tags).filter(([key]) => !key.startsWith("smuggling:"));
}

// ---------------------------------------------------------------------------
// Anomaly field null guards
// ---------------------------------------------------------------------------

describe("Anomaly display null guards", () => {
  it("handles undefined anomalies", () => {
    const flow = makeFlow({ anomalies: undefined });
    expect(flow.anomalies).toBeUndefined();
    // Simulates the null guard: flowData.anomalies && flowData.anomalies.length > 0
    const shouldDisplay = !!(flow.anomalies && flow.anomalies.length > 0);
    expect(shouldDisplay).toBe(false);
  });

  it("handles empty anomalies array", () => {
    const flow = makeFlow({ anomalies: [] });
    const shouldDisplay = !!(flow.anomalies && flow.anomalies.length > 0);
    expect(shouldDisplay).toBe(false);
  });

  it("displays anomalies when present", () => {
    const anomalies: AnomalyEntry[] = [
      { type: "CLTE", detail: "CL/TE conflict" },
    ];
    const flow = makeFlow({ anomalies });
    const shouldDisplay = !!(flow.anomalies && flow.anomalies.length > 0);
    expect(shouldDisplay).toBe(true);
    expect(flow.anomalies![0].type).toBe("CLTE");
    expect(flow.anomalies![0].detail).toBe("CL/TE conflict");
  });
});

// ---------------------------------------------------------------------------
// Anomaly types
// ---------------------------------------------------------------------------

describe("Anomaly types", () => {
  it("supports all known anomaly types", () => {
    const types = [
      "CLTE",
      "DuplicateCL",
      "AmbiguousTE",
      "InvalidTE",
      "HeaderInjection",
      "ObsFold",
    ];
    const anomalies: AnomalyEntry[] = types.map((t) => ({
      type: t,
      detail: `${t} detected`,
    }));
    const flow = makeFlow({ anomalies });
    expect(flow.anomalies).toHaveLength(6);
    for (let i = 0; i < types.length; i++) {
      expect(flow.anomalies![i].type).toBe(types[i]);
    }
  });

  it("handles anomaly with empty detail", () => {
    const anomalies: AnomalyEntry[] = [{ type: "ObsFold", detail: "" }];
    const flow = makeFlow({ anomalies });
    expect(flow.anomalies![0].detail).toBe("");
  });
});

// ---------------------------------------------------------------------------
// Tag filtering (smuggling:* hidden when anomalies displayed)
// ---------------------------------------------------------------------------

describe("Tag filtering for anomaly display", () => {
  it("filters smuggling:* tags from display", () => {
    const tags: Record<string, string> = {
      "smuggling:cl_te_conflict": "true",
      "smuggling:warnings": "CL/TE conflict",
      error: "timeout",
      streaming_type: "sse",
    };
    const filtered = filterNonSmugglingTags(tags);
    expect(filtered).toHaveLength(2);
    expect(filtered.map(([k]) => k).sort()).toEqual([
      "error",
      "streaming_type",
    ]);
  });

  it("returns empty array for undefined tags", () => {
    const filtered = filterNonSmugglingTags(undefined);
    expect(filtered).toHaveLength(0);
  });

  it("returns all tags when no smuggling keys", () => {
    const tags: Record<string, string> = {
      error: "timeout",
    };
    const filtered = filterNonSmugglingTags(tags);
    expect(filtered).toHaveLength(1);
    expect(filtered[0][0]).toBe("error");
  });

  it("returns empty when only smuggling tags", () => {
    const tags: Record<string, string> = {
      "smuggling:cl_te_conflict": "true",
      "smuggling:warnings": "test",
    };
    const filtered = filterNonSmugglingTags(tags);
    expect(filtered).toHaveLength(0);
  });
});
