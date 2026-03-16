import { describe, expect, it } from "vitest";
import {
  decodeBase64,
  encodeBase64,
  formatHexDump,
  bytesToText,
} from "./rawBytes";

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

describe("decodeBase64", () => {
  it("decodes a simple ASCII string", () => {
    // "Hello" => "SGVsbG8="
    const result = decodeBase64("SGVsbG8=");
    expect(bytesToText(result)).toBe("Hello");
  });

  it("returns empty Uint8Array for empty string", () => {
    const result = decodeBase64("");
    expect(result.length).toBe(0);
  });

  it("returns empty Uint8Array for invalid base64", () => {
    const result = decodeBase64("!!!not-valid!!!");
    expect(result.length).toBe(0);
  });

  it("decodes binary data correctly", () => {
    // [0x00, 0x01, 0xff] => "AAH/"
    const result = decodeBase64("AAH/");
    expect(Array.from(result)).toEqual([0x00, 0x01, 0xff]);
  });
});

describe("encodeBase64", () => {
  it("encodes a simple ASCII string", () => {
    const bytes = new TextEncoder().encode("Hello");
    expect(encodeBase64(bytes)).toBe("SGVsbG8=");
  });

  it("encodes empty data to empty string", () => {
    expect(encodeBase64(new Uint8Array(0))).toBe("");
  });

  it("encodes binary data correctly", () => {
    const bytes = new Uint8Array([0x00, 0x01, 0xff]);
    expect(encodeBase64(bytes)).toBe("AAH/");
  });
});

describe("base64 round-trip", () => {
  it("round-trips ASCII text", () => {
    const original = new TextEncoder().encode("Hello, World!");
    expect(decodeBase64(encodeBase64(original))).toEqual(original);
  });

  it("round-trips binary data with all byte values", () => {
    const original = new Uint8Array(256);
    for (let i = 0; i < 256; i++) original[i] = i;
    expect(decodeBase64(encodeBase64(original))).toEqual(original);
  });

  it("round-trips empty data", () => {
    const original = new Uint8Array(0);
    expect(decodeBase64(encodeBase64(original))).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Hex dump
// ---------------------------------------------------------------------------

describe("formatHexDump", () => {
  it("formats a single line of 16 bytes", () => {
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bytes[i] = i + 0x41; // A-P
    const result = formatHexDump(bytes);
    expect(result).toBe(
      "00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|"
    );
  });

  it("formats empty data to empty string", () => {
    expect(formatHexDump(new Uint8Array(0))).toBe("");
  });

  it("pads incomplete final line", () => {
    // 3 bytes: "ABC"
    const bytes = new Uint8Array([0x41, 0x42, 0x43]);
    const result = formatHexDump(bytes);
    expect(result).toContain("41 42 43");
    // Should have padding spaces for remaining 13 bytes
    expect(result).toContain("|ABC             |");
  });

  it("shows non-printable bytes as dots in ASCII column", () => {
    const bytes = new Uint8Array([0x00, 0x41, 0x7f, 0x1f]);
    const result = formatHexDump(bytes);
    expect(result).toContain("|.A..");
  });

  it("formats multiple lines", () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = 0x30 + (i % 10); // 0-9 repeating
    const lines = formatHexDump(bytes).split("\n");
    expect(lines.length).toBe(2);
    expect(lines[0]).toMatch(/^00000000/);
    expect(lines[1]).toMatch(/^00000010/);
  });

  it("truncates and appends notice when maxSize is exceeded", () => {
    const bytes = new Uint8Array(48);
    const result = formatHexDump(bytes, 16);
    const lines = result.split("\n");
    // 1 data line + 1 truncation notice
    expect(lines.length).toBe(2);
    expect(lines[1]).toBe("... (32 more bytes truncated)");
  });

  it("does not truncate when data fits within maxSize", () => {
    const bytes = new Uint8Array(16);
    const result = formatHexDump(bytes, 32);
    expect(result).not.toContain("truncated");
  });

  it("handles large data", () => {
    const bytes = new Uint8Array(1024);
    for (let i = 0; i < 1024; i++) bytes[i] = i & 0xff;
    const lines = formatHexDump(bytes).split("\n");
    expect(lines.length).toBe(64); // 1024 / 16
  });
});

// ---------------------------------------------------------------------------
// bytesToText
// ---------------------------------------------------------------------------

describe("bytesToText", () => {
  it("decodes ASCII bytes", () => {
    const bytes = new TextEncoder().encode("Hello");
    expect(bytesToText(bytes)).toBe("Hello");
  });

  it("decodes UTF-8 multibyte characters", () => {
    const bytes = new TextEncoder().encode("こんにちは");
    expect(bytesToText(bytes)).toBe("こんにちは");
  });

  it("handles empty data", () => {
    expect(bytesToText(new Uint8Array(0))).toBe("");
  });

  it("replaces invalid UTF-8 sequences instead of throwing", () => {
    // 0xff is not valid UTF-8 — should produce replacement character
    const bytes = new Uint8Array([0xff, 0xfe]);
    const result = bytesToText(bytes);
    expect(result).toContain("\ufffd");
  });
});
