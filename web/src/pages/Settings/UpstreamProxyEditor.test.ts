/**
 * Unit tests for the upstream-proxy editor's pure helpers and the type
 * guard exported from lib/mcp/types.ts (USK-963).
 *
 * The editor component itself is not rendered here — like the other
 * Settings tests, the project deliberately avoids jsdom / RTL and tests
 * the *behaviour* via the pure helpers that back the component. The
 * helpers are sized so that the React layer is a thin onChange dispatch
 * on top of buildUpstreamProxyPayload + validateUpstreamProxyPayload.
 */

import { describe, expect, it } from "vitest";
import { isRotationUpstream } from "../../lib/mcp/types.js";
import type {
  UpstreamProxyPolicy,
  UpstreamProxyRotationInput,
} from "../../lib/mcp/types.js";
import {
  buildUpstreamProxyPayload,
  validateUpstreamProxyPayload,
  type UpstreamProxyEditorValue,
} from "./UpstreamProxyEditor.js";

// ---------------------------------------------------------------------------
// isRotationUpstream — type guard
// ---------------------------------------------------------------------------

describe("isRotationUpstream", () => {
  it("returns true for a well-formed rotation object", () => {
    const v: UpstreamProxyRotationInput = {
      url_template: "http://session-§__nonce§@proxy:8080",
      rotation: { policy: "per_request" },
    };
    expect(isRotationUpstream(v)).toBe(true);
  });

  it("returns false for a literal-URL string", () => {
    expect(isRotationUpstream("http://proxy:8080")).toBe(false);
  });

  it("returns false for the empty literal disable form", () => {
    expect(isRotationUpstream("")).toBe(false);
  });

  it("returns false for the literal-in-object form `{ url }`", () => {
    expect(isRotationUpstream({ url: "http://proxy:8080" })).toBe(false);
  });

  it("returns false for an object with empty url_template", () => {
    expect(isRotationUpstream({ url_template: "" })).toBe(false);
  });

  it("returns false for null / undefined", () => {
    expect(isRotationUpstream(null)).toBe(false);
    expect(isRotationUpstream(undefined)).toBe(false);
  });

  it("returns false for numbers / arrays (defensive)", () => {
    expect(isRotationUpstream(42)).toBe(false);
    expect(isRotationUpstream([])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildUpstreamProxyPayload — pure payload builder used on save
// ---------------------------------------------------------------------------

describe("buildUpstreamProxyPayload", () => {
  it("emits a trimmed bare string in simple mode", () => {
    const out = buildUpstreamProxyPayload(
      "simple",
      "  http://proxy:3128  ",
      "ignored",
      "per_request",
    );
    expect(out).toBe("http://proxy:3128");
  });

  it("emits an empty string when simple mode has no URL", () => {
    expect(buildUpstreamProxyPayload("simple", "", "", "per_request")).toBe("");
  });

  it("emits a rotation object in rotation mode (per_request)", () => {
    const out = buildUpstreamProxyPayload(
      "rotation",
      "ignored",
      "http://§__nonce§@proxy:8080",
      "per_request",
    );
    expect(out).toEqual({
      url_template: "http://§__nonce§@proxy:8080",
      rotation: { policy: "per_request" },
    });
  });

  it("preserves every policy value in rotation mode", () => {
    const policies: UpstreamProxyPolicy[] = [
      "per_request",
      "per_connection",
      "per_target_host",
      "sticky",
    ];
    for (const p of policies) {
      const out = buildUpstreamProxyPayload(
        "rotation",
        "",
        "http://§__nonce§@proxy:8080",
        p,
      );
      expect(isRotationUpstream(out)).toBe(true);
      if (isRotationUpstream(out)) {
        expect(out.rotation.policy).toBe(p);
      }
    }
  });

  it("trims the rotation template", () => {
    const out = buildUpstreamProxyPayload(
      "rotation",
      "",
      "  http://§x§@proxy  ",
      "sticky",
    );
    if (!isRotationUpstream(out)) {
      throw new Error("expected rotation form");
    }
    expect(out.url_template).toBe("http://§x§@proxy");
  });

  it("does not emit both `url` and `url_template`", () => {
    // Simple mode: bare string only, no url field.
    const simple = buildUpstreamProxyPayload("simple", "http://a", "http://b", "sticky");
    expect(typeof simple).toBe("string");
    // Rotation mode: object form has no `url` field, only `url_template`.
    const rotation = buildUpstreamProxyPayload("rotation", "http://a", "http://b/§x§", "sticky");
    if (isRotationUpstream(rotation)) {
      expect("url" in rotation).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// validateUpstreamProxyPayload — warn-on-save validator
// ---------------------------------------------------------------------------

describe("validateUpstreamProxyPayload", () => {
  it("returns no warnings for the empty-disable string", () => {
    expect(validateUpstreamProxyPayload("")).toEqual([]);
  });

  it("returns no warnings for a well-formed http literal URL", () => {
    expect(validateUpstreamProxyPayload("http://proxy:3128")).toEqual([]);
  });

  it("returns no warnings for socks5", () => {
    expect(validateUpstreamProxyPayload("socks5://proxy:1080")).toEqual([]);
  });

  it("warns when the literal URL has no scheme", () => {
    const w = validateUpstreamProxyPayload("proxy:3128");
    expect(w.length).toBe(1);
    expect(w[0]).toMatch(/scheme|http|socks5/i);
  });

  it("returns no warnings for a rotation template with a macro", () => {
    const v: UpstreamProxyEditorValue = {
      url_template: "http://session-§__nonce§@proxy:8080",
      rotation: { policy: "per_request" },
    };
    expect(validateUpstreamProxyPayload(v)).toEqual([]);
  });

  it("warns when the rotation template has no §...§ macro", () => {
    const v: UpstreamProxyEditorValue = {
      url_template: "http://proxy:8080",
      rotation: { policy: "per_request" },
    };
    const w = validateUpstreamProxyPayload(v);
    expect(w.some((m) => /macro|§/.test(m))).toBe(true);
  });

  it("warns when the rotation template lacks a scheme", () => {
    const v: UpstreamProxyEditorValue = {
      url_template: "proxy-§__nonce§:8080",
      rotation: { policy: "sticky" },
    };
    const w = validateUpstreamProxyPayload(v);
    expect(w.some((m) => /scheme|http|socks5/i.test(m))).toBe(true);
  });

  it("can return multiple warnings at once (no scheme + no macro)", () => {
    const v: UpstreamProxyEditorValue = {
      url_template: "proxy:8080",
      rotation: { policy: "sticky" },
    };
    const w = validateUpstreamProxyPayload(v);
    expect(w.length).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// Integration: payload-shape parity with the wire schema
// ---------------------------------------------------------------------------

describe("payload-shape parity with the wire schema (USK-959)", () => {
  it("simple-mode payload is JSON-serializable as a bare string", () => {
    const out = buildUpstreamProxyPayload("simple", "http://proxy:3128", "", "per_request");
    expect(JSON.parse(JSON.stringify(out))).toBe("http://proxy:3128");
  });

  it("rotation-mode payload is JSON-serializable as an object the backend accepts", () => {
    const out = buildUpstreamProxyPayload(
      "rotation",
      "",
      "http://§__nonce§@proxy:8080",
      "per_target_host",
    );
    const j = JSON.parse(JSON.stringify(out));
    expect(j).toEqual({
      url_template: "http://§__nonce§@proxy:8080",
      rotation: { policy: "per_target_host" },
    });
    // url ⊕ url_template (no url field present)
    expect("url" in j).toBe(false);
  });

  it("payload union for a real save-flow: empty simple → ''", () => {
    // Mirrors the empty-disable case the editor emits when the user
    // hits Save with an empty Simple URL field.
    const out = buildUpstreamProxyPayload("simple", "   ", "", "per_request");
    expect(out).toBe("");
  });
});
