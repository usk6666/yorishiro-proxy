/**
 * USK-1185: request_timeout_ms / client_idle_timeout_ms accept 0
 * (disabled) or 100-600000. The Settings card validates through
 * parseClientTimeoutMs and the Dashboard renders through
 * formatClientTimeoutMs.
 */

import { describe, expect, it } from "vitest";
import { formatClientTimeoutMs, parseClientTimeoutMs } from "./clientTimeouts.js";

describe("parseClientTimeoutMs", () => {
  it.each([
    ["0", 0],
    ["100", 100],
    ["60000", 60000],
    ["600000", 600000],
  ])("accepts %s", (raw, want) => {
    expect(parseClientTimeoutMs(raw, "Request timeout")).toEqual({ value: want });
  });

  it.each(["1", "99", "-1", "600001", "", "abc"])("rejects %s", (raw) => {
    const got = parseClientTimeoutMs(raw, "Request timeout");
    expect("error" in got).toBe(true);
    if ("error" in got) {
      expect(got.error).toContain("Request timeout");
      expect(got.error).toContain("0");
    }
  });
});

describe("formatClientTimeoutMs", () => {
  it("renders 0 as disabled", () => {
    expect(formatClientTimeoutMs(0)).toBe("disabled");
  });
  it("renders a bound in milliseconds", () => {
    expect(formatClientTimeoutMs(60000)).toBe("60000ms");
  });
  it("renders a missing value as a dash", () => {
    expect(formatClientTimeoutMs(undefined)).toBe("-");
  });
});
