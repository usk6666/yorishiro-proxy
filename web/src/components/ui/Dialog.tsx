import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { Button } from "./Button.js";
import "./Dialog.css";
import {
  applyShowDialog,
  buildDialogState,
  DialogContext,
  markDialogSettled,
  type DialogOptions,
  type DialogState,
} from "./dialogContext.js";

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
