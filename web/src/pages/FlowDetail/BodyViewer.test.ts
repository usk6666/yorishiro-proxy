import { describe, expect, it } from "vitest";
import {
  anomalyLabel,
  isPreviewableImage,
  resolveBodySourceState,
} from "./BodyViewer.js";
import type { DecodeAnomaly } from "../../lib/mcp/types.js";

// ---------------------------------------------------------------------------
// resolveBodySourceState — decoded/original toggle visibility & default
// ---------------------------------------------------------------------------

describe("resolveBodySourceState", () => {
  it("hides the toggle when no Content-Encoding decode happened", () => {
    // Identity / no Content-Encoding flow — server returns no decoded fields.
    const state = resolveBodySourceState(undefined, undefined, undefined);
    expect(state.showToggle).toBe(false);
    expect(state.decodedAvailable).toBe(false);
    expect(state.defaultSource).toBe("original");
  });

  it("hides the toggle when bodyEncodingApplied is the empty string", () => {
    // Server returns empty body_encoding_applied for identity bodies.
    const state = resolveBodySourceState("", "", undefined);
    expect(state.showToggle).toBe(false);
    expect(state.decodedAvailable).toBe(false);
  });

  it("shows the toggle and defaults to decoded for a gzip body", () => {
    const state = resolveBodySourceState(
      '{"hello":"world"}',
      "gzip",
      undefined,
    );
    expect(state.showToggle).toBe(true);
    expect(state.decodedAvailable).toBe(true);
    expect(state.defaultSource).toBe("decoded");
  });

  it("shows the toggle and defaults to decoded for a brotli body", () => {
    const state = resolveBodySourceState("<html/>", "br", undefined);
    expect(state.showToggle).toBe(true);
    expect(state.decodedAvailable).toBe(true);
    expect(state.defaultSource).toBe("decoded");
  });

  it("shows the toggle but disables Decoded when decode produced an anomaly", () => {
    const anomaly: DecodeAnomaly = {
      type: "malformed",
      detail: "gzip: invalid header",
    };
    // Server returns no decoded body when decode fails — only the anomaly.
    const state = resolveBodySourceState(undefined, "", anomaly);
    expect(state.showToggle).toBe(true);
    expect(state.decodedAvailable).toBe(false);
    expect(state.defaultSource).toBe("original");
  });

  it("treats an empty bodyDecoded as unavailable even when codec is set", () => {
    // Edge case: server reports applied codec but the decoded payload was
    // empty (e.g. zero-length body). We don't want a useless empty Decoded
    // tab here.
    const state = resolveBodySourceState("", "gzip", undefined);
    expect(state.decodedAvailable).toBe(false);
    expect(state.defaultSource).toBe("original");
    expect(state.showToggle).toBe(false);
  });

  it("supports all four codecs that the server can return", () => {
    for (const codec of ["gzip", "deflate", "br", "zstd"]) {
      const state = resolveBodySourceState("payload", codec, undefined);
      expect(state.decodedAvailable, codec).toBe(true);
      expect(state.defaultSource, codec).toBe("decoded");
    }
  });
});

// ---------------------------------------------------------------------------
// anomalyLabel — human-readable mapping for known anomaly types
// ---------------------------------------------------------------------------

describe("anomalyLabel", () => {
  it("maps known anomaly types to readable labels", () => {
    expect(anomalyLabel("unknown_encoding")).toBe(
      "Unknown Content-Encoding",
    );
    expect(anomalyLabel("malformed")).toBe("Malformed compressed body");
    expect(anomalyLabel("size_exceeded")).toBe(
      "Decoded body exceeds size cap",
    );
    expect(anomalyLabel("chain_rejected")).toBe(
      "Chained Content-Encoding not supported",
    );
    expect(anomalyLabel("truncated_decode")).toBe(
      "Body was truncated at storage time",
    );
  });

  it("returns the raw type for unknown anomaly types (forward compatibility)", () => {
    // If the server adds a new anomaly type, the WebUI shouldn't drop it on
    // the floor — show the raw key until a label is added.
    expect(anomalyLabel("future_codec_x")).toBe("future_codec_x");
    expect(anomalyLabel("")).toBe("");
  });
});

// ---------------------------------------------------------------------------
// isPreviewableImage — image MIME allowlist (USK-742)
//
// The `<img src="data:...">` preview path renders attacker-controlled body
// bytes. Only an explicit safe-MIME allowlist may pass; in particular,
// image/svg+xml must never be previewable because SVG can carry inline
// `<script>` that executes in the data: origin.
// ---------------------------------------------------------------------------

describe("isPreviewableImage", () => {
  it("allows the canonical safe image MIME types", () => {
    for (const ct of [
      "image/png",
      "image/jpeg",
      "image/jpg",
      "image/gif",
      "image/webp",
      "image/avif",
    ]) {
      expect(isPreviewableImage(ct), ct).toBe(true);
    }
  });

  it("rejects image/svg+xml regardless of casing or parameters", () => {
    // The SVG XSS sink — every reasonable spelling must fail closed.
    for (const ct of [
      "image/svg+xml",
      "Image/SVG+XML",
      "IMAGE/SVG+XML",
      "image/svg+xml; charset=utf-8",
      "  image/svg+xml  ",
    ]) {
      expect(isPreviewableImage(ct), ct).toBe(false);
    }
  });

  it("strips parameters and whitespace before matching", () => {
    expect(isPreviewableImage("image/png; charset=binary")).toBe(true);
    expect(isPreviewableImage("  image/jpeg  ")).toBe(true);
    expect(isPreviewableImage("IMAGE/WEBP")).toBe(true);
  });

  it("rejects unknown or non-image MIME types", () => {
    for (const ct of [
      "application/octet-stream",
      "text/html",
      "image/bmp",
      "image/x-icon",
      "image/tiff",
      "image/heic",
      "image/",
      "imagepng", // missing slash
      "not a mime",
    ]) {
      expect(isPreviewableImage(ct), ct).toBe(false);
    }
  });

  it("rejects empty / null / undefined content types", () => {
    expect(isPreviewableImage("")).toBe(false);
    expect(isPreviewableImage(null)).toBe(false);
    expect(isPreviewableImage(undefined)).toBe(false);
  });
});
