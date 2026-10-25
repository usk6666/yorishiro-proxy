import { describe, expect, it } from "vitest";
import { isPseudoHeader } from "./pseudoHeaders.js";

// ---------------------------------------------------------------------------
// isPseudoHeader — case-insensitive pseudo-header detection (used by the
// HAR and cURL export sinks)
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
