/**
 * toastContext -- Toast types, context and `useToast`.
 *
 * Split out of Toast.tsx so that file exports only components (React Fast
 * Refresh). Toast.tsx keeps `ToastProvider` and the rendering.
 */

import { createContext, useContext } from "react";

export interface ToastMessage {
  id: string;
  type: "success" | "error" | "warning" | "info";
  message: string;
  duration?: number;
}

export interface ToastContextValue {
  addToast: (toast: Omit<ToastMessage, "id">) => void;
  removeToast: (id: string) => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used within a ToastProvider");
  }
  return context;
}
