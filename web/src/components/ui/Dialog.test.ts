import { describe, expect, it } from "vitest";
import {
  applyShowDialog,
  buildDialogState,
  markDialogSettled,
  type DialogOptions,
  type DialogState,
} from "./Dialog.js";

// ---------------------------------------------------------------------------
// buildDialogState — defaults + override behaviour
// ---------------------------------------------------------------------------
//
// We test the pure helpers extracted from DialogProvider rather than rendering
// the component. Vitest in this project runs in node mode (no jsdom), and
// `web/vitest.config.ts` only picks up `*.test.ts`, so a hooks/Testing-Library
// based regression test would require introducing new tooling. The promise-loss
// regression (USK-747) lives entirely in the state-updater logic, so it can be
// pinned with a pure-function test.

describe("buildDialogState", () => {
  it("applies confirm-variant defaults when options omit them", () => {
    const noop = () => {};
    const opts: DialogOptions = { title: "t", message: "m" };
    const state = buildDialogState(opts, noop);
    expect(state.title).toBe("t");
    expect(state.message).toBe("m");
    expect(state.variant).toBe("confirm");
    expect(state.confirmLabel).toBe("Confirm");
    expect(state.cancelLabel).toBe("Cancel");
    expect(state.confirmVariant).toBe("primary");
    expect(state.resolve).toBe(noop);
    expect(state.settled).toBe(false);
  });

  it("uses the alert default for confirmLabel when variant is alert", () => {
    const state = buildDialogState(
      { title: "t", message: "m", variant: "alert" },
      () => {},
    );
    expect(state.variant).toBe("alert");
    expect(state.confirmLabel).toBe("OK");
  });

  it("preserves explicit overrides", () => {
    const state = buildDialogState(
      {
        title: "t",
        message: "m",
        variant: "confirm",
        confirmLabel: "Yes",
        cancelLabel: "No",
        confirmVariant: "danger",
      },
      () => {},
    );
    expect(state.confirmLabel).toBe("Yes");
    expect(state.cancelLabel).toBe("No");
    expect(state.confirmVariant).toBe("danger");
  });
});

// ---------------------------------------------------------------------------
// applyShowDialog — resolver-rescue regression (USK-747)
// ---------------------------------------------------------------------------

describe("applyShowDialog", () => {
  it("returns the new state unchanged when no previous dialog is queued", () => {
    const next: DialogState = buildDialogState(
      { title: "a", message: "m" },
      () => {},
    );
    const result = applyShowDialog(null, next);
    expect(result).toBe(next);
  });

  it("resolves the previous dialog's promise with false before swapping", async () => {
    // Recreate the showDialog flow: a Promise wraps each setDialog call.
    let firstResolve!: (v: boolean) => void;
    const firstPromise = new Promise<boolean>((resolve) => {
      firstResolve = resolve;
    });
    const prev = buildDialogState(
      { title: "first", message: "queued" },
      firstResolve,
    );

    let secondResolve!: (v: boolean) => void;
    const secondPromise = new Promise<boolean>((resolve) => {
      secondResolve = resolve;
    });
    const next = buildDialogState(
      { title: "second", message: "incoming" },
      secondResolve,
    );

    const result = applyShowDialog(prev, next);

    // The displayed dialog is the new one.
    expect(result).toBe(next);
    expect(result.title).toBe("second");

    // The rescue path marks the previous dialog as settled so a StrictMode
    // re-invocation (or a future lookup) cannot resolve it again.
    expect(prev.settled).toBe(true);

    // The first caller's promise resolves with false (cancel-equivalent), so
    // the awaiting code path no longer hangs.
    await expect(firstPromise).resolves.toBe(false);

    // The new dialog's promise stays pending until its own confirm/cancel.
    let secondSettled = false;
    void secondPromise.then(() => {
      secondSettled = true;
    });
    // Yield a microtask so any premature resolution would have flushed.
    await Promise.resolve();
    expect(secondSettled).toBe(false);
  });

  it("skips rescue when the previous dialog is already settled (USK-747 F-1)", async () => {
    // Reproduces the F-1 race: the user clicks Confirm/Cancel, the click
    // handler resolves the promise with the user's actual choice and marks
    // the dialog settled, the dialog enters its 200 ms exit-animation window
    // (still non-null in state), and a NEW `showDialog` lands during that
    // window. The rescue path must NOT call `prev.resolve(false)` — doing so
    // would either be a misleading no-op or, under any future refactor that
    // decouples the flag-flip from the resolve call, would silently override
    // the user's choice.
    let resolveCalls = 0;
    let lastResolveValue: boolean | undefined;
    const userChoiceResolver = (v: boolean) => {
      resolveCalls++;
      lastResolveValue = v;
    };
    const prev = buildDialogState(
      { title: "first", message: "queued" },
      userChoiceResolver,
    );

    // Simulate user clicking Confirm: synchronous resolve(true) + settle.
    prev.resolve(true);
    markDialogSettled(prev);
    expect(resolveCalls).toBe(1);
    expect(lastResolveValue).toBe(true);

    // A new showDialog lands during the exit-animation window.
    const next = buildDialogState(
      { title: "second", message: "incoming" },
      () => {},
    );
    const result = applyShowDialog(prev, next);

    // The new dialog is installed.
    expect(result).toBe(next);
    // CRITICAL: the rescue path did NOT call prev.resolve again. The user's
    // Confirm result (true) is preserved.
    expect(resolveCalls).toBe(1);
    expect(lastResolveValue).toBe(true);
  });

  it("is safe under StrictMode-style double invocation", async () => {
    // React StrictMode invokes setState updaters twice in development. The
    // second call sees the same `prev`, but the first call has already
    // flipped `prev.settled = true`, so the second call's rescue path is
    // skipped. The user-visible Promise sees exactly one resolution.
    let calls = 0;
    let resolve!: (v: boolean) => void;
    const promise = new Promise<boolean>((r) => {
      resolve = (v) => {
        calls++;
        r(v);
      };
    });
    const prev = buildDialogState(
      { title: "first", message: "queued" },
      resolve,
    );
    const next1 = buildDialogState(
      { title: "second", message: "incoming" },
      () => {},
    );

    // Simulate double-invocation: same prev passed twice.
    applyShowDialog(prev, next1);
    applyShowDialog(prev, next1);

    // The awaiter sees the false-rescue exactly once.
    await expect(promise).resolves.toBe(false);
    // After the first rescue marked prev.settled = true, the second call
    // skips the resolve entirely — so the inner closure runs exactly once.
    expect(calls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// markDialogSettled — pinning the post-resolve no-rescue invariant
// ---------------------------------------------------------------------------

describe("markDialogSettled", () => {
  it("flips settled to true so applyShowDialog skips rescue", () => {
    let resolveCalls = 0;
    const prev = buildDialogState(
      { title: "first", message: "queued" },
      () => {
        resolveCalls++;
      },
    );
    expect(prev.settled).toBe(false);
    markDialogSettled(prev);
    expect(prev.settled).toBe(true);

    const next = buildDialogState(
      { title: "second", message: "incoming" },
      () => {},
    );
    applyShowDialog(prev, next);
    expect(resolveCalls).toBe(0);
  });
});
