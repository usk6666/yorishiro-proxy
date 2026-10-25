/** USK-1185 scaffold. */
export function parseClientTimeoutMs(
  raw: string,
  label: string,
): { value: number } | { error: string } {
  const v = parseInt(raw, 10);
  if (isNaN(v) || v < 100) {
    return { error: `${label} must be at least 100ms` };
  }
  return { value: v };
}

/** USK-1185 scaffold. */
export function formatClientTimeoutMs(ms: number | null | undefined): string {
  return `${ms}ms`;
}
