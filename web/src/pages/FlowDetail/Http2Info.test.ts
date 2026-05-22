import { describe, expect, it } from "vitest";
import { filterRegularHeaders, isPseudoHeader } from "./Http2Info.js";

// ---------------------------------------------------------------------------
// isPseudoHeader — case-insensitive pseudo-header detection
// ---------------------------------------------------------------------------

describe("isPseudoHeader", () => {
  it("matches HTTP/2 request pseudo-header names", () => {
    expect(isPseudoHeader(":method")).toBe(true);
    expect(isPseudoHeader(":path")).toBe(true);
    expect(isPseudoHeader(":authority")).toBe(true);
    expect(isPseudoHeader(":scheme")).toBe(true);
  });

  it("matches HTTP/2 response pseudo-header names", () => {
    expect(isPseudoHeader(":status")).toBe(true);
  });

  it("is case-insensitive (defensive against mixed-case wire input)", () => {
    expect(isPseudoHeader(":METHOD")).toBe(true);
    expect(isPseudoHeader(":Status")).toBe(true);
  });

  it("returns false for regular headers and non-h2 names", () => {
    expect(isPseudoHeader("content-type")).toBe(false);
    expect(isPseudoHeader("host")).toBe(false);
    expect(isPseudoHeader(":unknown")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// filterRegularHeaders — Headers-tab projection for HTTP/2 (USK-965)
// ---------------------------------------------------------------------------

describe("filterRegularHeaders", () => {
  it("passes null through unchanged", () => {
    expect(filterRegularHeaders(null)).toBeNull();
  });

  it("strips pseudo-headers, keeping regular headers", () => {
    const headers: Record<string, string[]> = {
      ":method": ["GET"],
      ":path": ["/api"],
      "content-type": ["application/json"],
      "x-custom": ["v1", "v2"],
    };
    const result = filterRegularHeaders(headers);
    expect(result).toEqual({
      "content-type": ["application/json"],
      "x-custom": ["v1", "v2"],
    });
  });

  it("returns an empty object when input contains only pseudo-headers (USK-965)", () => {
    // Regression: HEAD-style response with just :status used to fall back to
    // returning the unfiltered input, leaking :status into the Headers tab.
    // The fix guarantees an empty map so HeadersTable shows the "no headers"
    // state and Http2PseudoHeaders is the sole place that renders :status.
    const headers: Record<string, string[]> = {
      ":status": ["204"],
    };
    const result = filterRegularHeaders(headers);
    expect(result).toEqual({});
    expect(result).not.toEqual(headers);
  });

  it("returns an empty object for an empty input map", () => {
    expect(filterRegularHeaders({})).toEqual({});
  });
});
