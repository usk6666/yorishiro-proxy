import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { Button } from "./Button.js";
import "./Dialog.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DialogOptions {
  /** Dialog title text. */
  title: string;
  /** Dialog body message or custom ReactNode content. */
  message: ReactNode;
  /** Dialog variant: "confirm" shows Confirm+Cancel, "alert" shows OK only. */
  variant?: "confirm" | "alert";
  /** Label for the confirm/OK button. Defaults to "OK" (alert) or "Confirm" (confirm). */
  confirmLabel?: string;
  /** Label for the cancel button. Defaults to "Cancel". */
  cancelLabel?: string;
  /** Visual style for the confirm button. Defaults to "primary". */
  confirmVariant?: "primary" | "danger";
}

export interface DialogState extends Required<Pick<DialogOptions, "title" | "variant" | "confirmLabel" | "cancelLabel" | "confirmVariant">> {
  message: ReactNode;
  resolve: (result: boolean) => void;
  /**
   * True once the user's Confirm/Cancel handler has invoked `resolve` with the
   * user's actual choice. The dialog may still be in its 200 ms exit-animation
   * window after this flips, but its promise has already been settled, so
   * `applyShowDialog` must NOT rescue it again — doing so would call `resolve`
   * a second time, and although Promise resolution is spec-locked at the first
   * call, relying on that is racy and misleading. Mutated in-place because
   * `DialogState` is held by reference in the React state cell; readers always
   * see the latest value during the synchronous `setDialog` updater.
   */
  settled: boolean;
}

interface DialogContextValue {
  /** Show a confirm dialog. Returns true if confirmed, false if cancelled. */
  showDialog: (options: DialogOptions) => Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit tests)
// ---------------------------------------------------------------------------

/**
 * Build the next DialogState from a new set of options and the resolver
 * for the freshly-created promise. Pure: no side effects.
 */
export function buildDialogState(
  options: DialogOptions,
  resolve: (result: boolean) => void,
): DialogState {
  const variant = options.variant ?? "confirm";
  return {
    title: options.title,
    message: options.message,
    variant,
    confirmLabel:
      options.confirmLabel ?? (variant === "alert" ? "OK" : "Confirm"),
    cancelLabel: options.cancelLabel ?? "Cancel",
    confirmVariant: options.confirmVariant ?? "primary",
    resolve,
    settled: false,
  };
}

/**
 * Mark a DialogState as having been resolved by the user's Confirm/Cancel
 * handler. After this, `applyShowDialog` must skip rescue for `state` — the
 * awaiter has already received the user's actual result, and a second call
 * to `resolve` would either be a confusing no-op (if the Promise is already
 * settled) or, under any future refactor that decouples flag-flip from
 * resolve-call, would silently override the user's choice with `false`.
 *
 * Mutates in place: `DialogState` is referenced from React state, but
 * because settled-checking and settled-flipping all happen synchronously
 * inside `setDialog` updaters and click handlers (which run before the
 * 200 ms exit timer), there is no rendering observer that would need a
 * fresh object identity. Keeping it a flag flip avoids cloning the message
 * ReactNode unnecessarily.
 */
export function markDialogSettled(state: DialogState): void {
  state.settled = true;
}

/**
 * State updater for `setDialog` when a new dialog is being shown. If a
 * previous dialog is still queued AND has not yet been settled by its own
 * Confirm/Cancel handler (its promise still genuinely pending user input),
 * resolve it with `false` (cancel-equivalent) before returning the new
 * state — without this, the previous caller's `await showDialog(...)` would
 * hang forever.
 *
 * Skip rescue when `prev.settled` is true: the user has already clicked
 * Confirm/Cancel and the Promise has been resolved with their choice; the
 * dialog is only lingering in state for the 200 ms exit-animation window.
 * Resolving again here would be racy (USK-747 F-1).
 *
 * StrictMode safety: in development React invokes this updater twice. The
 * second call sees the same `prev` object — but the rescue path has now
 * mutated `prev.settled` to true, so the second invocation is a no-op for
 * resolve. The Promise's [[PromiseState]] is also spec-locked at the first
 * resolution, so even without the flag the awaiter would only see the first
 * value, but the flag makes the intent explicit.
 */
export function applyShowDialog(
  prev: DialogState | null,
  next: DialogState,
): DialogState {
  if (prev !== null && !prev.settled) {
    prev.resolve(false);
    prev.settled = true;
  }
  return next;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const DialogContext = createContext<DialogContextValue | null>(null);

export function useDialog(): DialogContextValue {
  const context = useContext(DialogContext);
  if (!context) {
    throw new Error("useDialog must be used within a DialogProvider");
  }
  return context;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export function DialogProvider({ children }: { children: ReactNode }) {
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [visible, setVisible] = useState(false);

  const showDialog = useCallback((options: DialogOptions): Promise<boolean> => {
    return new Promise<boolean>((resolve) => {
      const next = buildDialogState(options, resolve);
      setDialog((prev) => applyShowDialog(prev, next));
    });
  }, []);

  // Trigger enter animation after dialog state is set.
  useEffect(() => {
    if (dialog) {
      requestAnimationFrame(() => setVisible(true));
    }
  }, [dialog]);

  const close = useCallback(
    (result: boolean) => {
      // Resolve the user's choice synchronously and mark the dialog settled
      // so that any `showDialog` landing during the 200 ms exit-animation
      // window does NOT trigger the rescue path in `applyShowDialog`. If we
      // deferred the resolve until after the timeout, a racing `showDialog`
      // could call `prev.resolve(false)` first and pre-empt the user's
      // actual click result (USK-747 F-1).
      if (dialog && !dialog.settled) {
        dialog.resolve(result);
        markDialogSettled(dialog);
      }
      setVisible(false);
      // Keep the dialog mounted for the exit animation, then unmount.
      setTimeout(() => {
        setDialog(null);
      }, 200);
    },
    [dialog],
  );

  const handleConfirm = useCallback(() => close(true), [close]);
  const handleCancel = useCallback(() => close(false), [close]);

  return (
    <DialogContext.Provider value={{ showDialog }}>
      {children}
      {dialog && (
        <DialogOverlay
          dialog={dialog}
          visible={visible}
          onConfirm={handleConfirm}
          onCancel={handleCancel}
        />
      )}
    </DialogContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Dialog overlay (internal)
// ---------------------------------------------------------------------------

function DialogOverlay({
  dialog,
  visible,
  onConfirm,
  onCancel,
}: {
  dialog: DialogState;
  visible: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const confirmRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  // Focus the confirm button when the dialog opens.
  useEffect(() => {
    if (visible) {
      confirmRef.current?.focus();
    }
  }, [visible]);

  // Close on Escape key.
  useEffect(() => {
    const handleKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") {
        onCancel();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onCancel]);

  // Focus trap: keep focus within the dialog.
  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      if (e.key !== "Tab") return;

      const el = dialogRef.current;
      if (!el) return;

      const focusable = el.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    },
    [],
  );

  // Clicking the overlay backdrop closes the dialog (cancel).
  const handleOverlayClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (e.target === e.currentTarget) {
        onCancel();
      }
    },
    [onCancel],
  );

  return (
    <div
      className={`dialog-overlay ${visible ? "dialog-overlay--visible" : ""}`}
      onClick={handleOverlayClick}
      onKeyDown={handleKeyDown}
    >
      <div
        ref={dialogRef}
        className={`dialog ${visible ? "dialog--visible" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
        aria-describedby="dialog-message"
      >
        <h2 id="dialog-title" className="dialog-title">
          {dialog.title}
        </h2>
        <div id="dialog-message" className="dialog-message">
          {dialog.message}
        </div>
        <div className="dialog-actions">
          {dialog.variant === "confirm" && (
            <Button variant="secondary" size="sm" onClick={onCancel}>
              {dialog.cancelLabel}
            </Button>
          )}
          <Button
            ref={confirmRef}
            variant={dialog.confirmVariant}
            size="sm"
            onClick={onConfirm}
          >
            {dialog.confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
