/**
 * Token management for WebUI authentication.
 *
 * Extracts the MCP Bearer token from the URL query string,
 * persists it in localStorage, and cleans the URL.
 */

const STORAGE_KEY = "kp_mcp_token";

/**
 * Initialize authentication on app startup.
 *
 * 1. Extract `?token=` from the URL query string
 * 2. If found, save to localStorage and strip the parameter from the URL
 * 3. Fall back to a previously stored token in localStorage
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

/** Read the stored token from localStorage. */
export function getStoredToken(): string | undefined {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

/** Remove the stored token (called on 401 to clear stale tokens). */
export function clearStoredToken(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore — private browsing or storage quota exceeded.
  }
}

function setStoredToken(token: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, token);
  } catch {
    // Ignore — private browsing or storage quota exceeded.
  }
}
