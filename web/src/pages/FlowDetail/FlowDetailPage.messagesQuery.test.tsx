/**
 * Page-level wiring test for FlowDetailPage's `query resource=messages`
 * call.
 *
 * dispatch.test.ts pins `needsMessagesQuery` itself; this file pins that
 * FlowDetailPage actually gates the messages query on it. The data hooks
 * are mocked so every `useQuery` call is recorded, and the page is rendered
 * with renderToStaticMarkup (no jsdom / RTL — see hooks.test.ts header).
 * A single HTTP flow must leave the messages query disabled; a
 * message-timeline flow must enable it.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FlowDetailResult } from "../../lib/mcp/types.js";
import h1Text from "./__fixtures__/h1-flow.response.json?raw";
import h2Text from "./__fixtures__/h2-flow.response.json?raw";
import wsText from "./__fixtures__/ws-flow.response.json?raw";
import grpcText from "./__fixtures__/grpc-flow.response.json?raw";
import sseText from "./__fixtures__/sse-flow.response.json?raw";
import rawText from "./__fixtures__/raw-flow.response.json?raw";

interface RecordedQuery {
  resource: string;
  options: { enabled?: boolean } & Record<string, unknown>;
}

const mockState = vi.hoisted(() => ({
  flow: null as unknown,
  calls: [] as RecordedQuery[],
}));

vi.mock("../../lib/mcp/hooks.js", () => ({
  useQuery: (resource: string, options: RecordedQuery["options"] = {}) => {
    mockState.calls.push({ resource, options });
    return {
      data: resource === "flow" ? mockState.flow : null,
      loading: false,
      error: null,
      refetch: () => {},
    };
  },
  useManage: () => ({ manage: async () => ({}), loading: false }),
}));

vi.mock("../../components/ui/toastContext.js", () => ({
  useToast: () => ({ addToast: () => {} }),
}));

vi.mock("../../components/ui/dialogContext.js", () => ({
  useDialog: () => ({ showDialog: async () => false }),
}));

// Import after the mocks are registered so the page resolves the stubs.
const { FlowDetailPage } = await import("./FlowDetailPage.js");

function renderWithFlow(text: string): RecordedQuery {
  mockState.flow = JSON.parse(text) as FlowDetailResult;
  const flowId = (mockState.flow as FlowDetailResult).id;
  renderToStaticMarkup(
    createElement(
      MemoryRouter,
      { initialEntries: [`/flows/${flowId}`] },
      createElement(
        Routes,
        null,
        createElement(Route, {
          path: "/flows/:id",
          element: createElement(FlowDetailPage),
        }),
      ),
    ),
  );
  const messages = mockState.calls.filter((c) => c.resource === "messages");
  // Guard against a vacuous pass if the page stops calling the hook.
  expect(messages).toHaveLength(1);
  return messages[0];
}

beforeEach(() => {
  mockState.flow = null;
  mockState.calls = [];
});

describe("FlowDetailPage messages query wiring", () => {
  it.each([
    ["h1", h1Text],
    ["h2", h2Text],
  ])("does not enable the messages query for a single HTTP flow (%s)", (_name, text) => {
    expect(renderWithFlow(text).options.enabled).toBe(false);
  });

  it.each([
    ["ws", wsText],
    ["grpc", grpcText],
    ["sse", sseText],
    ["raw", rawText],
  ])("enables the messages query for a %s flow", (_name, text) => {
    expect(renderWithFlow(text).options.enabled).toBe(true);
  });
});
