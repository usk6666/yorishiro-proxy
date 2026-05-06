/**
 * Tests for the pure runner that backs every MCP action hook.
 *
 * `useMcpAction` is a thin React wrapper around `runMcpAction`, which
 * encapsulates the loading/error state machine. Testing the runner
 * directly mirrors the pattern from `dispatch.test.ts` (pure-function
 * tests, no DOM) and exercises every behaviour visible at the hook's
 * call site:
 *
 *   - success path: action resolves, loading flips true→false, error stays null
 *   - failure path: action rejects, loading still flips back, error captured,
 *                   the rejection propagates to the caller
 *   - not-connected path: throws "MCP client is not connected" before
 *                         touching the action or any state sinks
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { McpClient } from "./client.js";
import {
  MCP_NOT_CONNECTED_MESSAGE,
  runMcpAction,
} from "./hooks.js";

// ---------------------------------------------------------------------------
// Test scaffolding
// ---------------------------------------------------------------------------

/**
 * Build a fresh pair of state sinks plus their captured-call lists. We
 * record every transition so the tests can assert the exact ordering
 * of `setLoading(true) → setLoading(false)` and `setError(null) → ...`.
 */
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

/** Minimal McpClient stub. The runner only needs identity, not behaviour. */
const fakeClient = {} as unknown as McpClient;

// ---------------------------------------------------------------------------
// Success path
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
// Failure path
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
// Not-connected path
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
