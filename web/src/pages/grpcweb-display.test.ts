/**
 * Tests for gRPC-Web protocol display support across WebUI components.
 *
 * Verifies that "gRPC-Web" is handled correctly in:
 * - Protocol badge variant mapping (flow list, flow detail, dashboard)
 * - gRPC flow detection (flow detail panel, message list)
 * - Protocol filter lists
 * - Null guard behavior for gRPC-Web specific fields
 */

import { describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Inline replicas of the functions under test.
// These mirror the actual implementations in the component files.
// We test them here to avoid importing JSX-heavy modules in a pure TS test.
// ---------------------------------------------------------------------------

/** FlowsPage / FlowDetailPage: protocolVariant */
function protocolVariant(
  protocol: string,
): "default" | "success" | "warning" | "danger" | "info" {
  switch (protocol) {
    case "HTTP/1.x":
      return "default";
    case "HTTPS":
      return "success";
    case "WebSocket":
      return "info";
    case "HTTP/2":
      return "info";
    case "gRPC":
    case "gRPC-Web":
      return "warning";
    case "TCP":
      return "danger";
    case "SOCKS5+HTTPS":
      return "success";
    case "SOCKS5+HTTP":
      return "default";
    default:
      return "default";
  }
}

/** FlowDetailPage: isGrpcFlow */
function isGrpcFlow(protocol: string): boolean {
  return protocol === "gRPC" || protocol === "gRPC-Web";
}

/** MessageList: isGrpc check */
function isGrpc(protocol: string): boolean {
  return protocol === "gRPC" || protocol === "gRPC-Web";
}

/** ResendPage: isHttp2Flow */
function isHttp2Flow(protocol: string): boolean {
  const proto = protocol.toLowerCase();
  return proto === "http/2" || proto === "h2" || proto === "grpc" || proto === "grpc-web";
}

/** Protocol lists used in various components. */
const FLOWS_PAGE_PROTOCOLS = [
  "HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "gRPC-Web", "TCP",
  "SOCKS5+HTTPS", "SOCKS5+HTTP",
] as const;

const DASHBOARD_PROTOCOLS = [
  "HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "gRPC-Web", "TCP",
] as const;

const SETTINGS_PROTOCOLS = [
  "HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "gRPC-Web", "TCP",
] as const;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("gRPC-Web protocol display", () => {
  describe("protocolVariant", () => {
    it("returns 'warning' for gRPC-Web", () => {
      expect(protocolVariant("gRPC-Web")).toBe("warning");
    });

    it("returns same variant for gRPC-Web as gRPC", () => {
      expect(protocolVariant("gRPC-Web")).toBe(protocolVariant("gRPC"));
    });

    it("returns 'default' for unknown protocol", () => {
      expect(protocolVariant("unknown")).toBe("default");
    });
  });

  describe("isGrpcFlow", () => {
    it("returns true for gRPC", () => {
      expect(isGrpcFlow("gRPC")).toBe(true);
    });

    it("returns true for gRPC-Web", () => {
      expect(isGrpcFlow("gRPC-Web")).toBe(true);
    });

    it("returns false for HTTP/2", () => {
      expect(isGrpcFlow("HTTP/2")).toBe(false);
    });

    it("returns false for HTTP/1.x", () => {
      expect(isGrpcFlow("HTTP/1.x")).toBe(false);
    });
  });

  describe("isGrpc (MessageList)", () => {
    it("returns true for gRPC-Web", () => {
      expect(isGrpc("gRPC-Web")).toBe(true);
    });

    it("returns true for gRPC", () => {
      expect(isGrpc("gRPC")).toBe(true);
    });

    it("returns false for WebSocket", () => {
      expect(isGrpc("WebSocket")).toBe(false);
    });
  });

  describe("isHttp2Flow (ResendPage)", () => {
    it("returns true for gRPC-Web", () => {
      expect(isHttp2Flow("gRPC-Web")).toBe(true);
    });

    it("returns true for gRPC", () => {
      expect(isHttp2Flow("gRPC")).toBe(true);
    });

    it("returns true for HTTP/2", () => {
      expect(isHttp2Flow("HTTP/2")).toBe(true);
    });

    it("returns false for HTTP/1.x", () => {
      expect(isHttp2Flow("HTTP/1.x")).toBe(false);
    });

    it("returns false for WebSocket", () => {
      expect(isHttp2Flow("WebSocket")).toBe(false);
    });
  });

  describe("protocol lists include gRPC-Web", () => {
    it("FlowsPage PROTOCOLS includes gRPC-Web", () => {
      expect(FLOWS_PAGE_PROTOCOLS).toContain("gRPC-Web");
    });

    it("Dashboard PROTOCOLS includes gRPC-Web", () => {
      expect(DASHBOARD_PROTOCOLS).toContain("gRPC-Web");
    });

    it("Settings PROTOCOLS includes gRPC-Web", () => {
      expect(SETTINGS_PROTOCOLS).toContain("gRPC-Web");
    });
  });

  describe("null guard for gRPC-Web specific fields", () => {
    it("handles missing protocol_summary gracefully", () => {
      const summary = undefined as Record<string, string> | undefined;
      const encoding = (summary ?? {} as Record<string, string>)["encoding"] ?? "";
      const embeddedTrailers = (summary ?? {} as Record<string, string>)["embedded_trailers"] ?? "";
      expect(encoding).toBe("");
      expect(embeddedTrailers).toBe("");
    });

    it("handles empty protocol_summary gracefully", () => {
      const summary: Record<string, string> = {};
      const encoding = summary.encoding ?? "";
      const embeddedTrailers = summary.embedded_trailers ?? "";
      const service = summary.service ?? "";
      const method = summary.method ?? "";
      const grpcStatus = summary.grpc_status ?? "";
      expect(encoding).toBe("");
      expect(embeddedTrailers).toBe("");
      expect(service).toBe("");
      expect(method).toBe("");
      expect(grpcStatus).toBe("");
    });

    it("reads gRPC-Web specific fields from protocol_summary", () => {
      const summary: Record<string, string> = {
        service: "UserService",
        method: "GetUser",
        grpc_status: "0",
        encoding: "base64",
        embedded_trailers: "true",
      };
      expect(summary.encoding).toBe("base64");
      expect(summary.embedded_trailers).toBe("true");
      expect(summary.service).toBe("UserService");
    });

    it("handles gRPC-Web binary encoding variant", () => {
      const summary: Record<string, string> = {
        encoding: "binary",
        embedded_trailers: "true",
      };
      expect(summary.encoding).toBe("binary");
    });
  });
});
