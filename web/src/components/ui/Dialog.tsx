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

interface DialogState extends Required<Pick<DialogOptions, "title" | "variant" | "confirmLabel" | "cancelLabel" | "confirmVariant">> {
  message: ReactNode;
  resolve: (result: boolean) => void;
}

interface DialogContextValue {
  /** Show a confirm dialog. Returns true if confirmed, false if cancelled. */
  showDialog: (options: DialogOptions) => Promise<boolean>;
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
      const variant = options.variant ?? "confirm";
      setDialog({
        title: options.title,
        message: options.message,
        variant,
        confirmLabel:
          options.confirmLabel ??
          (variant === "alert" ? "OK" : "Confirm"),
        cancelLabel: options.cancelLabel ?? "Cancel",
        confirmVariant: options.confirmVariant ?? "primary",
        resolve,
      });
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
      setVisible(false);
      // Wait for exit animation before removing from DOM.
      setTimeout(() => {
        dialog?.resolve(result);
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
