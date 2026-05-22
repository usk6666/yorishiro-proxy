/**
 * Tests for the RawPatchEditor offset validation helper (USK-967).
 *
 * The editor previously coerced any non-numeric / empty / negative
 * offset to 0 via `parseInt(val, 10)` + `?? 0`, which writes the
 * patch at a wholly different position than the user intended —
 * exactly the byte-level fuzz failure mode this editor exists to
 * support. The pure `validateRawPatchOffset` helper is the gate that
 * surfaces invalid input as a typed error string for inline display
 * and disables the parent's submit button via onValidityChange.
 *
 * The component itself is JSX-heavy; tests for it would pull in
 * jsdom + RTL. Following the pattern of grpcweb-display.test.ts, we
 * verify the pure helper here.
 */

import { describe, expect, it } from "vitest";
import { validateRawPatchOffset } from "./RawPatchEditor.js";

describe("validateRawPatchOffset", () => {
  describe("invalid inputs", () => {
    it("rejects empty string", () => {
      expect(validateRawPatchOffset("")).not.toBeNull();
    });

    it("rejects whitespace-only string", () => {
      expect(validateRawPatchOffset("   ")).not.toBeNull();
    });

    it('rejects non-numeric "abc"', () => {
      const err = validateRawPatchOffset("abc");
      expect(err).not.toBeNull();
      expect(err).toMatch(/number/);
    });

    it("rejects negative integer", () => {
      const err = validateRawPatchOffset("-1");
      expect(err).not.toBeNull();
      expect(err).toMatch(/non-negative/);
    });

    it("rejects fractional value", () => {
      const err = validateRawPatchOffset("1.5");
      expect(err).not.toBeNull();
      expect(err).toMatch(/integer/);
    });

    it("rejects mixed input (1000abc)", () => {
      // Number("1000abc") returns NaN; parseInt would have truncated to
      // 1000 silently — verify the new validator rejects it cleanly.
      expect(validateRawPatchOffset("1000abc")).not.toBeNull();
    });

    it("rejects Infinity", () => {
      expect(validateRawPatchOffset("Infinity")).not.toBeNull();
    });

    it("rejects NaN literal", () => {
      expect(validateRawPatchOffset("NaN")).not.toBeNull();
    });
  });

  describe("valid inputs", () => {
    it("accepts 0", () => {
      expect(validateRawPatchOffset("0")).toBeNull();
    });

    it("accepts positive integer", () => {
      expect(validateRawPatchOffset("42")).toBeNull();
    });

    it("accepts large integer", () => {
      expect(validateRawPatchOffset("65536")).toBeNull();
    });

    it("accepts integer with surrounding whitespace", () => {
      // Number() ignores leading/trailing whitespace; this mirrors what
      // the editor sends after a user copy-paste with stray spaces.
      expect(validateRawPatchOffset("  42  ")).toBeNull();
    });
  });
});
