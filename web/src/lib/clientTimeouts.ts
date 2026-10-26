/**
 * Client-side timeouts — request_timeout_ms and client_idle_timeout_ms
 * (USK-1185). Both accept 0 (the bound is disabled) or 100-600000 ms,
 * matching the server-side validation in proxy_start / configure.
 */

export const MIN_CLIENT_TIMEOUT_MS = 100;
export const MAX_CLIENT_TIMEOUT_MS = 600000;

/**
 * Parses a client-side timeout input. Returns the value, or an error
 * message naming `label` for the toast.
 */
export function parseClientTimeoutMs(
  raw: string,
  label: string,
): { value: number } | { error: string } {
  const trimmed = raw.trim();
  const v = /^-?\d+$/.test(trimmed) ? Number(trimmed) : NaN;
  if (v === 0 || (v >= MIN_CLIENT_TIMEOUT_MS && v <= MAX_CLIENT_TIMEOUT_MS)) {
    return { value: v };
  }
  return {
    error: `${label} must be 0 (disabled) or between ${MIN_CLIENT_TIMEOUT_MS} and ${MAX_CLIENT_TIMEOUT_MS}ms`,
  };
}

/** Renders a client-side timeout for display: 0 is "disabled". */
export function formatClientTimeoutMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) {
    return "-";
  }
  return ms === 0 ? "disabled" : `${ms}ms`;
}
