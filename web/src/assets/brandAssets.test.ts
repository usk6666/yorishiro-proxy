/**
 * Drift guards for the Web UI brand assets (USK-1245).
 *
 * The Web UI ships two copies of the project artwork kept in docs/images/:
 *
 * - yorishiro-proxy-logo-dark.svg: the header wordmark. The Web UI is
 *   dark-only, so the prefers-color-scheme: dark palette is baked in and the
 *   media query removed; otherwise a light-OS user would get the navy ink on
 *   the dark header and the logo would vanish. Only <style> (and the
 *   derivation comment) may differ from the docs original.
 * - yorishiro-proxy-icon.svg: the favicon. The browser tab strip follows the
 *   OS theme, so this is a byte-identical copy that keeps the media query.
 *
 * The web copies are read through import.meta.glob rather than direct
 * imports so that a missing file is an assertion failure, not a module load
 * error.
 */
import { describe, expect, it } from "vitest";
import docsIcon from "../../../docs/images/yorishiro-proxy-icon.svg?raw";
import docsLogo from "../../../docs/images/yorishiro-proxy-logo.svg?raw";

const webAssets = import.meta.glob<string>("./*.svg", {
  query: "?raw",
  import: "default",
  eager: true,
});

const DARK_LOGO = "./yorishiro-proxy-logo-dark.svg";
const ICON = "./yorishiro-proxy-icon.svg";

function stripCommentsAndStyle(svg: string): string {
  return svg
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<style>[\s\S]*?<\/style>/g, "");
}

function styleOf(svg: string): string {
  const m = /<style>([\s\S]*?)<\/style>/.exec(svg);
  return m ? m[1] : "";
}

function countPaths(svg: string): number {
  return (svg.match(/<path\b/g) ?? []).length;
}

describe("docs source artwork", () => {
  it("has the expected path counts so the comparisons below are not vacuous", () => {
    expect(countPaths(docsLogo)).toBe(7);
    expect(countPaths(docsIcon)).toBe(5);
  });
});

describe("dark header logo", () => {
  it("exists in web/src/assets", () => {
    expect(Object.keys(webAssets)).toContain(DARK_LOGO);
  });

  it("is byte-identical to the docs logo outside <style> and comments", () => {
    const dark = webAssets[DARK_LOGO] ?? "";
    expect(countPaths(dark)).toBe(7);
    expect(stripCommentsAndStyle(dark)).toBe(stripCommentsAndStyle(docsLogo));
  });

  it("carries only the dark palette and no prefers-color-scheme media query", () => {
    const dark = webAssets[DARK_LOGO] ?? "";
    const style = styleOf(dark);
    expect(style).not.toBe("");
    expect(dark).not.toMatch(/@media/i);
    expect(dark).not.toMatch(/prefers-color-scheme/i);
    expect(style).not.toMatch(/#1B2140/i);
    expect(style).not.toMatch(/#C9962B/i);
    expect(style).toContain("#E9ECF5");
    expect(style).toContain("#E2B755");
  });
});

describe("favicon", () => {
  it("is a byte-identical copy of the docs icon", () => {
    expect(Object.keys(webAssets)).toContain(ICON);
    const icon = webAssets[ICON] ?? "";
    expect(countPaths(icon)).toBe(5);
    expect(icon).toBe(docsIcon);
  });
});
