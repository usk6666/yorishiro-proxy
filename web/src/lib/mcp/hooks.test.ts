/**
 * Tests for the pure runner that backs every MCP action hook, plus
 * identity-stability tests for `useMcpAction` and its wrapper hooks
 * (USK-750).
 *
 * `useMcpAction` is a thin React wrapper around `runMcpAction`, which
 * encapsulates the loading/error state machine. The runner-level tests
 * use plain mutators and exercise every behaviour visible at the hook's
 * call site:
 *
 *   - success path: action resolves, loading flips true→false, error stays null
 *   - failure path: action rejects, loading still flips back, error captured,
 *                   the rejection propagates to the caller
 *   - not-connected path: throws "MCP client is not connected" before
 *                         touching the action or any state sinks
 *
 * The identity-stability tests run `useMcpAction` (and its wrappers)
 * through a deterministic in-process hook driver so we can assert that:
 *
 *   - `execute` is `===` across re-renders that don't change `client`
 *     or `status` — even if the inline `call` arrow at the call site is
 *     a fresh function reference every render (regression guard for the
 *     pre-USK-750 behaviour, which listed `call` in `useCallback` deps).
 *   - `execute` *does* change when `client` or `status` changes, so the
 *     ref pattern is not over-stabilising the callback.
 *
 * The driver below mocks the React hooks that `useMcpAction` consumes
 * (`useState`, `useRef`, `useEffect`, `useCallback`) with a tiny
 * deterministic implementation. This avoids pulling in jsdom /
 * happy-dom / @testing-library just to verify a callback-identity
 * invariant — keeping the webui test surface dependency-free.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { McpClient } from "./client.js";

// ---------------------------------------------------------------------------
// React-hook driver
// ---------------------------------------------------------------------------

/**
 * Per-render hook slot store. React tracks hooks by call order; this
 * driver does the same. Each render walks the slots from the start; new
 * slots are appended on the first render and reused on subsequent
 * renders so identity-preserving hooks (`useRef`, `useState`,
 * `useCallback`, `useMemo`) behave correctly.
 */
interface HookRecord {
  // useState / useRef
  value?: unknown;
  // useCallback / useMemo
  cached?: unknown;
  deps?: readonly unknown[];
  // useEffect
  effect?: () => void | (() => void);
  cleanup?: () => void;
}

/**
 * A scheduled effect, tagged with the slot it was registered from so
 * the commit-phase cleanup attachment is a direct lookup rather than
 * an effect-identity scan (USK-750 review F-1).
 */
interface ScheduledEffect {
  effect: () => void | (() => void);
  slotIndex: number;
}

interface Renderer {
  slots: HookRecord[];
  cursor: number;
  effects: ScheduledEffect[];
  /** Run a render of `fn` and return its return value. */
  render: <T>(fn: () => T) => T;
  /** Number of renders performed so far. */
  renderCount: number;
}

function createRenderer(): Renderer {
  const r: Renderer = {
    slots: [],
    cursor: 0,
    effects: [],
    renderCount: 0,
    render<T>(fn: () => T): T {
      r.cursor = 0;
      r.effects = [];
      r.renderCount += 1;
      const out = fn();
      // Flush effects in registration order, mimicking React's commit
      // phase. For each scheduled effect, run any prior cleanup attached
      // to its slot, then run the effect; if it returns a cleanup, store
      // it on the slot it was registered from (direct lookup via the
      // slot index captured at registration time — no identity scan).
      for (const { effect, slotIndex } of r.effects) {
        const slot = r.slots[slotIndex];
        if (slot && typeof slot.cleanup === "function") {
          slot.cleanup();
          slot.cleanup = undefined;
        }
        const result = effect();
        if (typeof result === "function" && slot) {
          slot.cleanup = result;
        }
      }
      return out;
    },
  };
  return r;
}

/** The active renderer for the in-flight `render()` call. */
let active: Renderer | null = null;

function nextSlot(): HookRecord {
  if (!active) throw new Error("hook called outside render");
  const i = active.cursor++;
  if (!active.slots[i]) active.slots[i] = {};
  return active.slots[i]!;
}

function depsEqual(a: readonly unknown[] | undefined, b: readonly unknown[]): boolean {
  if (!a || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (!Object.is(a[i], b[i])) return false;
  }
  return true;
}

function fakeUseState<T>(initial: T | (() => T)): [T, (v: T) => void] {
  const slot = nextSlot();
  if (!("value" in slot)) {
    slot.value = typeof initial === "function" ? (initial as () => T)() : initial;
  }
  const setter = (v: T) => {
    slot.value = v;
  };
  return [slot.value as T, setter];
}

function fakeUseRef<T>(initial: T): { current: T } {
  const slot = nextSlot();
  if (!("value" in slot)) {
    slot.value = { current: initial };
  }
  return slot.value as { current: T };
}

function fakeUseCallback<T extends (...args: unknown[]) => unknown>(
  cb: T,
  deps: readonly unknown[],
): T {
  const slot = nextSlot();
  if (!slot.cached || !depsEqual(slot.deps, deps)) {
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

function fakeUseEffect(effect: () => void | (() => void), deps?: readonly unknown[]): void {
  if (!active) throw new Error("hook called outside render");
  // Capture the slot index *before* `nextSlot()` advances the cursor,
  // so the scheduled effect knows exactly which slot owns it. The
  // commit phase uses this index to attach the cleanup directly.
  const slotIndex = active.cursor;
  const slot = nextSlot();
  // useEffect with no deps runs every render; with deps, only when they
  // change. Cleanup tracking goes through the captured slot index.
  if (!deps || !depsEqual(slot.deps, deps)) {
    slot.effect = effect;
    slot.deps = deps;
    active.effects.push({ effect, slotIndex });
  } else {
    // No-op render; preserve previous effect/cleanup pairing.
  }
}

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

/**
 * Override React's hook exports with our deterministic in-process
 * versions. Only the hooks consumed by `useMcpAction` and the wrappers
 * tested below are stubbed; anything else that touches `react` would
 * surface a TypeError, which keeps the surface honest.
 */
vi.mock("react", () => ({
  useState: fakeUseState,
  useRef: fakeUseRef,
  useCallback: fakeUseCallback,
  useMemo: fakeUseMemo,
  useEffect: fakeUseEffect,
}));

/**
 * Mutable connection state observed by `useMcpContext` between renders.
 * Tests adjust this then call `renderer.render(...)` to simulate a
 * re-render with the new context value.
 */
const ctx: { client: McpClient | null; status: string } = {
  client: {} as McpClient,
  status: "connected",
};

vi.mock("./context.js", () => ({
  useMcpContext: () => ({ ...ctx }),
}));

// Imports must come after mocks are registered so the production code
// resolves to the mocked react / context modules.
const {
  MCP_NOT_CONNECTED_MESSAGE,
  runMcpAction,
  useMcpAction,
  useResend,
  useManage,
  useFuzz,
  useMacro,
  useInterceptAction,
  useSecurity,
  useConfigure,
  useProxyControl,
} = await import("./hooks.js");

// ---------------------------------------------------------------------------
// Test scaffolding for the runner-level tests
// ---------------------------------------------------------------------------

function makeSinks() {
  const loadingCalls: boolean[] = [];
  const errorCalls: (Error | null)[] = [];
  return {
    sinks: {
      setLoading: (v: boolean) => loadingCalls.push(v),
      setError: (e: Error | null) => errorCalls.push(e),
    },
    loadingCalls,
    errorCalls,
  };
}

const fakeClient = {} as unknown as McpClient;

/**
 * Drive a hook through `count` renders, returning each render's output.
 * `next()` is called before every render and may mutate `ctx` or any
 * other state visible to the hook's render closure.
 */
function driveHook<T>(fn: () => T, count: number, between?: (i: number) => void): T[] {
  const renderer = createRenderer();
  const outs: T[] = [];
  for (let i = 0; i < count; i++) {
    if (between && i > 0) between(i);
    active = renderer;
    try {
      outs.push(renderer.render(fn));
    } finally {
      active = null;
    }
  }
  return outs;
}

// ---------------------------------------------------------------------------
// Success path — runner
// ---------------------------------------------------------------------------

describe("runMcpAction — success path", () => {
  let scaffold: ReturnType<typeof makeSinks>;

  beforeEach(() => {
    scaffold = makeSinks();
  });

  it("resolves with the action's return value", async () => {
    const call = vi
      .fn<(c: McpClient, p: { id: string }) => Promise<{ ok: true }>>()
      .mockResolvedValue({ ok: true });

    const result = await runMcpAction(
      call,
      fakeClient,
      "connected",
      { id: "abc" },
      scaffold.sinks,
    );

    expect(result).toEqual({ ok: true });
    expect(call).toHaveBeenCalledTimes(1);
    expect(call).toHaveBeenCalledWith(fakeClient, { id: "abc" });
  });

  it("flips loading true→false and never sets an error", async () => {
    const call = vi.fn().mockResolvedValue("ok");

    await runMcpAction(
      call,
      fakeClient,
      "connected",
      undefined,
      scaffold.sinks,
    );

    expect(scaffold.loadingCalls).toEqual([true, false]);
    // setError is called once at the start to clear any prior error;
    // it must not be called again with a non-null Error on the success path.
    expect(scaffold.errorCalls).toEqual([null]);
  });

  it("clears any prior error before invoking the action", async () => {
    const call = vi.fn().mockResolvedValue("ok");

    await runMcpAction(
      call,
      fakeClient,
      "connected",
      undefined,
      scaffold.sinks,
    );

    // First setError call must clear (null), and there must be no
    // subsequent non-null setError on success.
    expect(scaffold.errorCalls[0]).toBeNull();
    expect(scaffold.errorCalls.every((e) => e === null)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Failure path — runner
// ---------------------------------------------------------------------------

describe("runMcpAction — failure path", () => {
  let scaffold: ReturnType<typeof makeSinks>;

  beforeEach(() => {
    scaffold = makeSinks();
  });

  it("re-throws the rejection so callers can react", async () => {
    const boom = new Error("boom");
    const call = vi.fn().mockRejectedValue(boom);

    await expect(
      runMcpAction(
        call,
        fakeClient,
        "connected",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toBe(boom);
  });

  it("captures the error via setError before re-throwing", async () => {
    const boom = new Error("nope");
    const call = vi.fn().mockRejectedValue(boom);

    await expect(
      runMcpAction(
        call,
        fakeClient,
        "connected",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrow();

    // First call clears prior error; final call records the new one.
    expect(scaffold.errorCalls[0]).toBeNull();
    expect(scaffold.errorCalls[scaffold.errorCalls.length - 1]).toBe(boom);
  });

  it("flips loading back to false even when the action throws", async () => {
    const call = vi.fn().mockRejectedValue(new Error("x"));

    await expect(
      runMcpAction(
        call,
        fakeClient,
        "connected",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrow();

    expect(scaffold.loadingCalls).toEqual([true, false]);
  });

  it("wraps non-Error rejections in an Error instance", async () => {
    // A rejection with a plain string mimics a misbehaving call() that
    // throws a non-Error value. The runner must coerce it so consumers
    // always observe a real Error in `setError` and the re-throw.
    const call = vi.fn().mockRejectedValue("string-error");

    await expect(
      runMcpAction(
        call,
        fakeClient,
        "connected",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrowError("string-error");

    const recorded =
      scaffold.errorCalls[scaffold.errorCalls.length - 1];
    expect(recorded).toBeInstanceOf(Error);
    expect((recorded as Error).message).toBe("string-error");
  });
});

// ---------------------------------------------------------------------------
// Not-connected path — runner
// ---------------------------------------------------------------------------

describe("runMcpAction — not-connected path", () => {
  let scaffold: ReturnType<typeof makeSinks>;

  beforeEach(() => {
    scaffold = makeSinks();
  });

  it("throws the canonical message when client is null", async () => {
    const call = vi.fn();

    await expect(
      runMcpAction(
        call,
        null,
        "connected",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrowError(MCP_NOT_CONNECTED_MESSAGE);
  });

  it("throws when status is not 'connected'", async () => {
    const call = vi.fn();

    await expect(
      runMcpAction(
        call,
        fakeClient,
        "disconnected",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrowError(MCP_NOT_CONNECTED_MESSAGE);

    await expect(
      runMcpAction(
        call,
        fakeClient,
        "connecting",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrowError(MCP_NOT_CONNECTED_MESSAGE);

    await expect(
      runMcpAction(
        call,
        fakeClient,
        "error",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrowError(MCP_NOT_CONNECTED_MESSAGE);
  });

  it("never invokes the action when not connected", async () => {
    const call = vi.fn();

    await expect(
      runMcpAction(
        call,
        null,
        "connected",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrow();

    expect(call).not.toHaveBeenCalled();
  });

  it("never touches loading/error state when not connected", async () => {
    const call = vi.fn();

    await expect(
      runMcpAction(
        call,
        null,
        "connected",
        undefined,
        scaffold.sinks,
      ),
    ).rejects.toThrow();

    // The disconnected pre-check must short-circuit before any state
    // setter fires, otherwise consumers would observe a phantom
    // loading=true → loading=false flicker on a no-op call.
    expect(scaffold.loadingCalls).toEqual([]);
    expect(scaffold.errorCalls).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// useMcpAction — execute identity stability (USK-750 F-1)
// ---------------------------------------------------------------------------

describe("useMcpAction — execute identity stability", () => {
  beforeEach(() => {
    ctx.client = {} as McpClient;
    ctx.status = "connected";
  });

  it("preserves execute identity when call is a fresh inline arrow", () => {
    // Simulates the wrapper-hook pattern where the call passed to
    // `useMcpAction` is reconstructed every render. Pre-USK-750 this
    // would return a fresh `execute` each render; post-fix, it must not.
    const outs = driveHook(
      () => {
        // Fresh arrow on every render — identity changes between renders.
        const call = (c: McpClient, p: unknown) =>
          Promise.resolve({ c, p } as unknown);
        return useMcpAction(call);
      },
      3,
    );

    expect(outs.length).toBe(3);
    expect(outs[1]!.execute).toBe(outs[0]!.execute);
    expect(outs[2]!.execute).toBe(outs[0]!.execute);
  });

  it("changes execute identity when client changes", () => {
    let renderIdx = 0;
    const clientA = { tag: "a" } as unknown as McpClient;
    const clientB = { tag: "b" } as unknown as McpClient;

    ctx.client = clientA;
    const outs = driveHook(
      () => {
        const call = (c: McpClient, p: unknown) =>
          Promise.resolve({ c, p } as unknown);
        return useMcpAction(call);
      },
      2,
      () => {
        renderIdx += 1;
        if (renderIdx === 1) ctx.client = clientB;
      },
    );

    expect(outs[1]!.execute).not.toBe(outs[0]!.execute);
  });

  it("changes execute identity when status changes", () => {
    let renderIdx = 0;
    ctx.status = "connected";
    const outs = driveHook(
      () => {
        const call = (c: McpClient, p: unknown) =>
          Promise.resolve({ c, p } as unknown);
        return useMcpAction(call);
      },
      2,
      () => {
        renderIdx += 1;
        if (renderIdx === 1) ctx.status = "disconnected";
      },
    );

    expect(outs[1]!.execute).not.toBe(outs[0]!.execute);
  });

  it("execute reads through the latest call ref (no stale closure)", async () => {
    // After re-renders, calling `execute` should invoke the most recent
    // `call` even though `execute` itself is the same reference. This
    // verifies the callRef pattern's freshness guarantee.
    let currentSpy = vi.fn().mockResolvedValue("first");
    const outs = driveHook(
      () => useMcpAction((c: McpClient, p: unknown) => currentSpy(c, p)),
      2,
      (i) => {
        if (i === 1) currentSpy = vi.fn().mockResolvedValue("second");
      },
    );

    // execute identity is stable across renders.
    expect(outs[1]!.execute).toBe(outs[0]!.execute);

    // But a call now uses the latest spy.
    const result = await outs[1]!.execute({} as unknown);
    expect(result).toBe("second");
  });
});

// ---------------------------------------------------------------------------
// Wrapper hooks — identity stability (USK-750 F-1 cascade)
// ---------------------------------------------------------------------------

describe("wrapper hook returned-callback identity stability", () => {
  beforeEach(() => {
    ctx.client = {} as McpClient;
    ctx.status = "connected";
  });

  it("useResend().resend is stable across re-renders", () => {
    const outs = driveHook(() => useResend(), 3);
    expect(outs[1]!.resend).toBe(outs[0]!.resend);
    expect(outs[2]!.resend).toBe(outs[0]!.resend);
  });

  it("useManage().manage is stable across re-renders", () => {
    const outs = driveHook(() => useManage(), 2);
    expect(outs[1]!.manage).toBe(outs[0]!.manage);
  });

  it("useFuzz().fuzz is stable across re-renders", () => {
    const outs = driveHook(() => useFuzz(), 2);
    expect(outs[1]!.fuzz).toBe(outs[0]!.fuzz);
  });

  it("useMacro().macro is stable across re-renders", () => {
    const outs = driveHook(() => useMacro(), 2);
    expect(outs[1]!.macro).toBe(outs[0]!.macro);
  });

  it("useInterceptAction().interceptAction is stable across re-renders", () => {
    const outs = driveHook(() => useInterceptAction(), 2);
    expect(outs[1]!.interceptAction).toBe(outs[0]!.interceptAction);
  });

  it("useSecurity().security is stable across re-renders", () => {
    const outs = driveHook(() => useSecurity(), 2);
    expect(outs[1]!.security).toBe(outs[0]!.security);
  });

  it("useConfigure().configure is stable across re-renders", () => {
    const outs = driveHook(() => useConfigure(), 2);
    expect(outs[1]!.configure).toBe(outs[0]!.configure);
  });
});

// ---------------------------------------------------------------------------
// useProxyControl — start/stop identity stability (USK-750 F-2)
// ---------------------------------------------------------------------------

describe("useProxyControl — start/stop identity stability", () => {
  beforeEach(() => {
    ctx.client = {} as McpClient;
    ctx.status = "connected";
  });

  it("start and stop are stable across re-renders that don't touch context", () => {
    const outs = driveHook(() => useProxyControl(), 3);
    expect(outs[1]!.start).toBe(outs[0]!.start);
    expect(outs[1]!.stop).toBe(outs[0]!.stop);
    expect(outs[2]!.start).toBe(outs[0]!.start);
    expect(outs[2]!.stop).toBe(outs[0]!.stop);
  });

  it("start and stop change when client identity changes (negative case)", () => {
    let renderIdx = 0;
    const clientA = { tag: "a" } as unknown as McpClient;
    const clientB = { tag: "b" } as unknown as McpClient;
    ctx.client = clientA;

    const outs = driveHook(
      () => useProxyControl(),
      2,
      () => {
        renderIdx += 1;
        if (renderIdx === 1) ctx.client = clientB;
      },
    );

    expect(outs[1]!.start).not.toBe(outs[0]!.start);
    expect(outs[1]!.stop).not.toBe(outs[0]!.stop);
  });
});
