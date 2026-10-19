import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import themeCss from "../../styles/theme.css?raw";
import headerCss from "./Header.css?raw";

vi.mock("../../lib/mcp/index.js", () => ({
  useMcpClient: () => ({
    status: "connected",
    error: null,
    connected: true,
    reconnect: async () => {},
  }),
}));

// Import after the mock is registered so Header resolves the stubbed hook.
const { Header } = await import("./Header.js");

function render(): string {
  return renderToStaticMarkup(
    createElement(Header, { onToggleSidebar: () => {}, sidebarCollapsed: false }),
  );
}

describe("Header brand (USK-1245)", () => {
  it("renders the logo as an <img> with alt text instead of text spans", () => {
    const html = render();
    const img = /<img\b[^>]*>/.exec(html)?.[0] ?? "";
    expect(img).not.toBe("");
    expect(img).toContain('alt="yorishiro-proxy"');
    const src = /\bsrc="([^"]*)"/.exec(img)?.[1] ?? "";
    expect(src).toMatch(/yorishiro-proxy-logo-dark\.svg$/);
    expect(html).not.toContain("header-logo-text");
    expect(html).not.toContain("header-logo-accent");
  });

  it("does not inline the SVG markup", () => {
    expect(render()).not.toContain("<style>");
  });

  it("sizes the logo to fit the unchanged 48px header", () => {
    expect(themeCss).toMatch(/--header-height:\s*48px;/);
    const rule = /\.header-logo-img\s*\{([^}]*)\}/.exec(headerCss)?.[1] ?? "";
    expect(rule).toMatch(/(^|[;\s])height:\s*24px/);
    expect(rule).toMatch(/width:\s*auto/);
  });

  it("drops the unused text-brand CSS", () => {
    // Guard against a vacuous pass if the ?raw import ever resolves to "".
    expect(headerCss).toContain(".header-logo");
    expect(headerCss).not.toContain(".header-logo-text");
    expect(headerCss).not.toContain(".header-logo-accent");
  });
});
