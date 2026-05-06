/**
 * Token management for WebUI authentication.
 *
 * Extracts the MCP Bearer token from the URL query string, persists it in
 * sessionStorage, and cleans the URL.
 *
 * Why sessionStorage (USK-742): the MCP bearer token grants full proxy
 * privileges. Persisting it in localStorage means any XSS in the WebUI (e.g.
 * a maliciously crafted MITM-observed response body) can lift the token and
 * survive across browser restarts — a cascade that turns one DOM-level
 * compromise into long-lived MCP access. sessionStorage is scoped per tab
 * and cleared on close, which strictly bounds the blast radius. The
 * `?token=` URL bootstrap is unchanged: each new tab is re-seeded from the
 * server-printed URL.
 */

const STORAGE_KEY = "kp_mcp_token";

/**
 * Return sessionStorage, or null if storage is unavailable (Safari private
 * mode, embedded contexts with disabled storage). Callers must handle null.
 */
function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/**
 * Initialize authentication on app startup.
 *
 * 1. Extract `?token=` from the URL query string
 * 2. If found, save to sessionStorage and strip the parameter from the URL
 * 3. Fall back to a previously stored token in sessionStorage
 * 4. Return the token or undefined if none is available
 */
export function initAuth(): string | undefined {
  const params = new URLSearchParams(window.location.search);
  const urlToken = params.get("token");

  if (urlToken) {
    setStoredToken(urlToken);

    // Remove the token parameter from the URL without a page reload.
    params.delete("token");
    const qs = params.toString();
    const newUrl =
      window.location.pathname +
      (qs ? `?${qs}` : "") +
      window.location.hash;
    history.replaceState(null, "", newUrl);

    return urlToken;
  }

  return getStoredToken();
}

/** Read the stored token from sessionStorage. */
export function getStoredToken(): string | undefined {
  try {
    return storage()?.getItem(STORAGE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

/** Remove the stored token (called on 401 to clear stale tokens). */
export function clearStoredToken(): void {
  try {
    storage()?.removeItem(STORAGE_KEY);
  } catch {
    // Ignore — private browsing or storage quota exceeded.
  }
}

function setStoredToken(token: string): void {
  try {
    storage()?.setItem(STORAGE_KEY, token);
  } catch {
    // Ignore — private browsing or storage quota exceeded.
  }
}
