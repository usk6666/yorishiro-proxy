/**
 * Tests for the BodyPatchEditor pure helpers (USK-973).
 *
 * The editor previously surfaced both `json_path + value` and
 * `regex + replace` rows simultaneously, allowing the user to populate
 * both modes on the same patch. The backend `validateBodyPatch`
 * (`internal/mcp/body_patch.go`) rejects that shape with a hard error,
 * so the UX gap caused a needless server round-trip for input that
 * could never succeed. `detectBodyPatchMode` selects the rendering
 * mode for an existing patch (defensive against legacy data) and
 * `isBodyPatchValid` mirrors the backend's exactly-one-of contract so
 * the parent's submit button can be disabled inline.
 *
 * The component itself is JSX-heavy; tests for it would pull in jsdom
 * + RTL. Following the pattern of RawPatchEditor.test.ts, we verify
 * the pure helpers here.
 */

import { describe, expect, it } from "vitest";
import type { BodyPatch } from "../../lib/mcp/types.js";
import { detectBodyPatchMode, isBodyPatchValid } from "./BodyPatchEditor.js";

describe("detectBodyPatchMode", () => {
  it("returns json_path for an empty patch (default)", () => {
    expect(detectBodyPatchMode({})).toBe("json_path");
  });

  it("returns json_path when only json_path is set", () => {
    expect(detectBodyPatchMode({ json_path: "$.a" })).toBe("json_path");
  });

  it("returns json_path when only value is set", () => {
    // No regex marker present — value alone is ambiguous; default to json_path.
    expect(detectBodyPatchMode({ value: "x" })).toBe("json_path");
  });

  it("returns regex when only regex is set", () => {
    expect(detectBodyPatchMode({ regex: "foo" })).toBe("regex");
  });

  it("returns regex when only replace is set", () => {
    // Defense-only path: replace alone implies regex intent.
    expect(detectBodyPatchMode({ replace: "bar" })).toBe("regex");
  });

  it("returns regex when both modes are set (regex wins)", () => {
    // Defense-only path for legacy data. The editor's write path never
    // produces this shape because handleModeChange clears the other-mode
    // fields.
    expect(
      detectBodyPatchMode({ json_path: "$.a", regex: "foo" } as BodyPatch),
    ).toBe("regex");
  });

  it("treats empty regex string as regex mode (presence over emptiness)", () => {
    // The blank shape produced by switching into regex mode is
    // `{ regex: "", replace: "" }`; detection must keep it in regex mode
    // for the next render to show the regex fields, not flip back to
    // json_path.
    expect(detectBodyPatchMode({ regex: "", replace: "" })).toBe("regex");
  });
});

describe("isBodyPatchValid", () => {
  it("rejects fully empty patch", () => {
    expect(isBodyPatchValid({})).toBe(false);
  });

  it("rejects patch with both modes set", () => {
    expect(
      isBodyPatchValid({ json_path: "$.a", regex: "foo" } as BodyPatch),
    ).toBe(false);
  });

  it("rejects empty json_path string", () => {
    expect(isBodyPatchValid({ json_path: "" })).toBe(false);
  });

  it("rejects whitespace-only json_path", () => {
    expect(isBodyPatchValid({ json_path: "   " })).toBe(false);
  });

  it("rejects empty regex string", () => {
    expect(isBodyPatchValid({ regex: "" })).toBe(false);
  });

  it("rejects whitespace-only regex", () => {
    expect(isBodyPatchValid({ regex: "   " })).toBe(false);
  });

  it("rejects blank-mode-switch shape (regex+replace both empty)", () => {
    // `handleModeChange` writes `{ regex: "", replace: "" }`; that row
    // must be reported invalid so the Send button stays disabled until
    // the user fills the pattern.
    expect(isBodyPatchValid({ regex: "", replace: "" })).toBe(false);
  });

  it("accepts valid json_path patch", () => {
    expect(isBodyPatchValid({ json_path: "$.user.name", value: "alice" })).toBe(
      true,
    );
  });

  it("accepts json_path patch without value (null is valid)", () => {
    // The backend treats omitted/null `value` as a valid JSON null,
    // matching the doc comment in body_patch.go's validateBodyPatch.
    expect(isBodyPatchValid({ json_path: "$.a" })).toBe(true);
  });

  it("accepts valid regex patch", () => {
    expect(isBodyPatchValid({ regex: "foo+", replace: "bar" })).toBe(true);
  });

  it("accepts regex patch with empty replace (matches strip)", () => {
    // Empty replace is a meaningful operation (strip the matched text);
    // only the pattern field is required.
    expect(isBodyPatchValid({ regex: "foo+", replace: "" })).toBe(true);
  });
});
