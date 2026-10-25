/**
 * FlowsPage resets pagination and row selection when the `conn_id` URL
 * parameter changes while the page stays mounted — the active-filter chip's
 * × clears it, and in-app navigation to `/?conn_id=<other>` swaps it. The
 * reset happens during render, so the committed render's `useQuery` call
 * must already carry offset 0 alongside the new filter.
 *
 * Driving that needs state that survives re-renders and event handlers that
 * can be invoked, which renderToStaticMarkup cannot do and the project does
 * not pull in jsdom / RTL for (see hooks.test.ts header). Instead, React's
 * hooks are replaced with a deterministic in-process driver (same idea as
 * hooks.test.ts) and `FlowsPage()` is called as a plain function; its
 * returned element tree is searched for the props the user would interact
 * with (Next button, row checkbox, chip ×). Child components are not
 * rendered, which is fine: only FlowsPage's own state is under test.
 *
 * Render-phase updates (a setter called while FlowsPage is rendering) are
 * handled the way React does: the pass is discarded and FlowsPage re-runs.
 * Only the final, committed pass's `useQuery` call is asserted on. Effects
 * are never run (the only one, useDebounce's timer, is irrelevant here), so
 * a reset moved into a useEffect would also be caught as "one render late".
 */

import type { ReactElement, ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FlowsResult } from "../../lib/mcp/types.js";
import sameConnText from "./__fixtures__/flows-same-conn.response.json?raw";

// ---------------------------------------------------------------------------
// Hook driver
// ---------------------------------------------------------------------------

interface Slot {
  value?: unknown;
  cached?: unknown;
  deps?: readonly unknown[];
}

const driver = vi.hoisted(() => ({
  slots: [] as Slot[],
  cursor: 0,
  rendering: false,
  renderPhaseUpdate: false,
}));

function nextSlot(): Slot {
  if (!driver.rendering) throw new Error("hook called outside render");
  const i = driver.cursor++;
  if (!driver.slots[i]) driver.slots[i] = {};
  return driver.slots[i];
}

function depsEqual(a: readonly unknown[] | undefined, b: readonly unknown[]): boolean {
  if (!a || a.length !== b.length) return false;
  return a.every((v, i) => Object.is(v, b[i]));
}

function fakeUseState<T>(initial: T | (() => T)): [T, (v: T | ((prev: T) => T)) => void] {
  const slot = nextSlot();
  if (!("value" in slot)) {
    slot.value = typeof initial === "function" ? (initial as () => T)() : initial;
  }
  const setter = (v: T | ((prev: T) => T)) => {
    const next = typeof v === "function" ? (v as (prev: T) => T)(slot.value as T) : v;
    if (Object.is(next, slot.value)) return;
    slot.value = next;
    if (driver.rendering) driver.renderPhaseUpdate = true;
  };
  return [slot.value as T, setter];
}

function fakeUseCallback<T>(cb: T, deps: readonly unknown[]): T {
  const slot = nextSlot();
  if (!("cached" in slot) || !depsEqual(slot.deps, deps)) {
    slot.cached = cb;
    slot.deps = deps;
  }
  return slot.cached as T;
}

function fakeUseMemo<T>(factory: () => T, deps: readonly unknown[]): T {
  const slot = nextSlot();
  if (!("cached" in slot) || !depsEqual(slot.deps, deps)) {
    slot.cached = factory();
    slot.deps = deps;
  }
  return slot.cached as T;
}

function fakeUseEffect(): void {
  // Occupy a slot to keep hook order stable; effects are never run.
  nextSlot();
}

vi.mock("react", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react")>()),
  useState: fakeUseState,
  useCallback: fakeUseCallback,
  useMemo: fakeUseMemo,
  useEffect: fakeUseEffect,
}));

// ---------------------------------------------------------------------------
// Router / data mocks
// ---------------------------------------------------------------------------

interface RecordedQuery {
  resource: string;
  options: { filter?: Record<string, unknown>; offset?: number } & Record<string, unknown>;
}

const mockState = vi.hoisted(() => ({
  search: "",
  flows: null as unknown,
  calls: [] as RecordedQuery[],
}));

vi.mock("react-router-dom", () => ({
  useSearchParams: () => [new URLSearchParams(mockState.search), () => {}],
  useNavigate: () => (to: string | { search?: string }) => {
    // clearConnId navigates with `{ search }`; mirror that into the URL.
    if (typeof to === "object" && to.search !== undefined) {
      mockState.search = to.search;
    }
  },
}));

vi.mock("../../lib/mcp/hooks.js", () => ({
  useQuery: (resource: string, options: RecordedQuery["options"] = {}) => {
    mockState.calls.push({ resource, options });
    return {
      data: resource === "flows" ? mockState.flows : null,
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
const { FlowsPage } = await import("./FlowsPage.js");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface Rendered {
  tree: ReactNode;
  query: RecordedQuery;
}

/** Render FlowsPage until no render-phase update is pending (the commit). */
function render(): Rendered {
  for (let pass = 0; pass < 25; pass++) {
    driver.cursor = 0;
    driver.renderPhaseUpdate = false;
    driver.rendering = true;
    mockState.calls = [];
    let tree: ReactNode;
    try {
      tree = FlowsPage();
    } finally {
      driver.rendering = false;
    }
    if (!driver.renderPhaseUpdate) {
      const flows = mockState.calls.filter((c) => c.resource === "flows");
      expect(flows).toHaveLength(1);
      return { tree, query: flows[0] };
    }
  }
  throw new Error("too many render-phase updates");
}

type AnyElement = ReactElement<Record<string, unknown>>;

function isElement(node: unknown): node is AnyElement {
  return typeof node === "object" && node !== null && "props" in node && "type" in node;
}

/** Every element in the tree (FlowsPage level only; children not rendered). */
function elements(node: unknown): AnyElement[] {
  if (Array.isArray(node)) return node.flatMap(elements);
  if (!isElement(node)) return [];
  return [node, ...elements(node.props.children)];
}

function textOf(node: unknown): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textOf).join("");
  if (isElement(node)) return textOf(node.props.children);
  return "";
}

function findOne(tree: ReactNode, pred: (el: AnyElement) => boolean, what: string): AnyElement {
  const found = elements(tree).filter(pred);
  if (found.length !== 1) throw new Error(`expected one ${what}, found ${found.length}`);
  return found[0];
}

function nextButton(tree: ReactNode): AnyElement {
  return findOne(tree, (el) => textOf(el.props.children) === "Next" && "onClick" in el.props, "Next button");
}

function rowCheckboxes(tree: ReactNode): AnyElement[] {
  // Row checkboxes stop click propagation; the header select-all does not.
  return elements(tree).filter(
    (el) => el.type === "input" && el.props.type === "checkbox" && "onClick" in el.props,
  );
}

function clearChip(tree: ReactNode): AnyElement {
  return findOne(
    tree,
    (el) => el.props["aria-label"] === "Clear connection filter",
    "clear connection filter button",
  );
}

function hasBulkBar(tree: ReactNode): boolean {
  return elements(tree).some((el) => el.props.className === "flows-bulk-bar");
}

/**
 * Mount at `/?conn_id=<connA>`, move to page 2, and select the first row.
 * Asserts the precondition so a later offset-0 assertion is not vacuous.
 */
function mountOnPage2WithSelection(): void {
  mockState.search = new URLSearchParams({ conn_id: connA }).toString();
  let { tree, query } = render();
  expect(query.options.offset).toBe(0);

  (nextButton(tree).props.onClick as () => void)();
  ({ tree, query } = render());
  (rowCheckboxes(tree)[0].props.onChange as () => void)();
  ({ tree, query } = render());

  expect(query.options.filter).toEqual({ conn_id: connA });
  expect(query.options.offset).toBe(50);
  expect(rowCheckboxes(tree).map((el) => el.props.checked)).toEqual([true, false]);
  expect(hasBulkBar(tree)).toBe(true);
}

const connA = "conn-h2-multiplexed";
const connB = "conn-other";

// Enough total rows for three 50-row pages so "Next" is enabled.
const sameConn = JSON.parse(sameConnText) as FlowsResult;
const paged: FlowsResult = { ...sameConn, total: 120 };

beforeEach(() => {
  driver.slots = [];
  driver.cursor = 0;
  driver.rendering = false;
  driver.renderPhaseUpdate = false;
  mockState.search = "";
  mockState.flows = paged;
  mockState.calls = [];
});

describe("FlowsPage conn_id change resets offset and selection", () => {
  it("resets when the connection chip's × clears conn_id", () => {
    mountOnPage2WithSelection();

    (clearChip(render().tree).props.onClick as () => void)();
    expect(mockState.search).toBe("");

    const { tree, query } = render();
    expect(query.options.filter).toBeUndefined();
    expect(query.options.offset).toBe(0);
    expect(rowCheckboxes(tree).map((el) => el.props.checked)).toEqual([false, false]);
    expect(hasBulkBar(tree)).toBe(false);
  });

  it("resets when in-app navigation swaps conn_id without remounting", () => {
    mountOnPage2WithSelection();

    mockState.search = new URLSearchParams({ conn_id: connB }).toString();
    const { tree, query } = render();
    expect(query.options.filter).toEqual({ conn_id: connB });
    expect(query.options.offset).toBe(0);
    expect(rowCheckboxes(tree).map((el) => el.props.checked)).toEqual([false, false]);
    expect(hasBulkBar(tree)).toBe(false);
  });

  it("keeps offset and selection when conn_id is unchanged across renders", () => {
    mountOnPage2WithSelection();

    const { tree, query } = render();
    expect(query.options.offset).toBe(50);
    expect(rowCheckboxes(tree).map((el) => el.props.checked)).toEqual([true, false]);
  });
});
