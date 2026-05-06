import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

// auth.ts touches `window`, `history`, and `sessionStorage`. The Vitest
// default environment is `node`, so these globals are not provided — each
// test installs minimal stubs via `vi.stubGlobal`. We import the module
// fresh with `await import()` after the stubs are in place to avoid module-
// scope evaluation against stale globals.

const STORAGE_KEY = "kp_mcp_token";

// ---------------------------------------------------------------------------
// In-memory Storage stubs
// ---------------------------------------------------------------------------

class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  key(i: number): string | null {
    return Array.from(this.map.keys())[i] ?? null;
  }
  getItem(k: string): string | null {
    return this.map.has(k) ? (this.map.get(k) as string) : null;
  }
  setItem(k: string, v: string): void {
    this.map.set(k, String(v));
  }
  removeItem(k: string): void {
    this.map.delete(k);
  }
  clear(): void {
    this.map.clear();
  }
}

interface StubHandles {
  sessionStorage: MemoryStorage;
  localStorageSpy: ReturnType<typeof makeLocalStorageSpy>;
  replaceStateSpy: ReturnType<typeof vi.fn>;
  setLocation: (search: string, pathname?: string, hash?: string) => void;
}

function makeLocalStorageSpy() {
  const setItem = vi.fn();
  const getItem = vi.fn(() => null);
  const removeItem = vi.fn();
  return { setItem, getItem, removeItem };
}

function installStubs(opts?: {
  // When true, accessing window.sessionStorage throws — simulates Safari
  // private mode / disabled-storage environments.
  sessionStorageThrows?: boolean;
}): StubHandles {
  const sessionStorage = new MemoryStorage();
  const localStorageSpy = makeLocalStorageSpy();
  const replaceStateSpy = vi.fn();

  // Mutable location stub so tests can change the URL between cases.
  const loc = {
    search: "",
    pathname: "/",
    hash: "",
  };
  const setLocation = (search: string, pathname = "/", hash = "") => {
    loc.search = search;
    loc.pathname = pathname;
    loc.hash = hash;
  };

  const sessionStorageDescriptor = opts?.sessionStorageThrows
    ? {
        get() {
          throw new Error("storage disabled");
        },
      }
    : { get: () => sessionStorage };

  const windowStub = Object.defineProperties({} as Window, {
    location: { get: () => loc },
    sessionStorage: sessionStorageDescriptor,
    // Provide localStorage too so a regression that calls it would be a
    // visible test failure rather than a runtime error.
    localStorage: { get: () => localStorageSpy as unknown as Storage },
  });

  vi.stubGlobal("window", windowStub);
  // The module reads the bare `localStorage` / `history` globals as well.
  vi.stubGlobal("localStorage", localStorageSpy);
  vi.stubGlobal("history", { replaceState: replaceStateSpy });

  return { sessionStorage, localStorageSpy, replaceStateSpy, setLocation };
}

async function freshAuth() {
  vi.resetModules();
  return await import("./auth.js");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("initAuth — URL token bootstrap", () => {
  let stubs: StubHandles;

  beforeEach(() => {
    stubs = installStubs();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("stores the token in sessionStorage and strips it from the URL", async () => {
    stubs.setLocation("?token=secret123&keep=me", "/flows", "#detail");
    const auth = await freshAuth();

    const got = auth.initAuth();

    expect(got).toBe("secret123");
    // sessionStorage holds the token under the canonical key.
    expect(stubs.sessionStorage.getItem(STORAGE_KEY)).toBe("secret123");
    // localStorage is NOT touched on set (the whole point of USK-742).
    expect(stubs.localStorageSpy.setItem).not.toHaveBeenCalled();
    // URL was rewritten without the token but with other params + hash kept.
    expect(stubs.replaceStateSpy).toHaveBeenCalledTimes(1);
    expect(stubs.replaceStateSpy).toHaveBeenCalledWith(
      null,
      "",
      "/flows?keep=me#detail",
    );
  });

  it("falls back to a previously stored sessionStorage token when no URL token is present", async () => {
    stubs.sessionStorage.setItem(STORAGE_KEY, "from-session");
    stubs.setLocation("");
    const auth = await freshAuth();

    expect(auth.initAuth()).toBe("from-session");
    // No URL rewrite should happen when there was no `?token=`.
    expect(stubs.replaceStateSpy).not.toHaveBeenCalled();
  });

  it("returns undefined when no token is present anywhere", async () => {
    stubs.setLocation("");
    const auth = await freshAuth();
    expect(auth.initAuth()).toBeUndefined();
  });

  it("emits a clean URL with just the pathname when no other query params remain", async () => {
    stubs.setLocation("?token=only", "/dashboard");
    const auth = await freshAuth();

    auth.initAuth();

    expect(stubs.replaceStateSpy).toHaveBeenCalledWith(
      null,
      "",
      "/dashboard",
    );
  });
});

describe("getStoredToken / clearStoredToken", () => {
  let stubs: StubHandles;

  beforeEach(() => {
    stubs = installStubs();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("getStoredToken reads from sessionStorage", async () => {
    stubs.sessionStorage.setItem(STORAGE_KEY, "alpha");
    const auth = await freshAuth();
    expect(auth.getStoredToken()).toBe("alpha");
    // localStorage must not be consulted.
    expect(stubs.localStorageSpy.getItem).not.toHaveBeenCalled();
  });

  it("getStoredToken returns undefined when nothing is stored", async () => {
    const auth = await freshAuth();
    expect(auth.getStoredToken()).toBeUndefined();
  });

  it("clearStoredToken removes the token from sessionStorage", async () => {
    stubs.sessionStorage.setItem(STORAGE_KEY, "to-remove");
    const auth = await freshAuth();
    auth.clearStoredToken();
    expect(stubs.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
    // localStorage must not be touched.
    expect(stubs.localStorageSpy.removeItem).not.toHaveBeenCalled();
  });
});

describe("storage failure modes", () => {
  let stubs: StubHandles;

  beforeEach(() => {
    stubs = installStubs({ sessionStorageThrows: true });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("getStoredToken returns undefined when sessionStorage access throws", async () => {
    const auth = await freshAuth();
    expect(auth.getStoredToken()).toBeUndefined();
  });

  it("clearStoredToken does not throw when sessionStorage access throws", async () => {
    const auth = await freshAuth();
    expect(() => auth.clearStoredToken()).not.toThrow();
  });

  it("initAuth still returns the URL token even if sessionStorage is unavailable", async () => {
    // Storage failure must not block the URL bootstrap path; the operator
    // still gets a working session, just one that doesn't survive reload.
    stubs.setLocation("?token=ephemeral");
    const auth = await freshAuth();
    expect(auth.initAuth()).toBe("ephemeral");
    expect(stubs.replaceStateSpy).toHaveBeenCalled();
    expect(stubs.localStorageSpy.setItem).not.toHaveBeenCalled();
  });
});
