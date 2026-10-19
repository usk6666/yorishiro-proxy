import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    // Vitest stubs every CSS module to "" by default, which also empties
    // `?raw` imports. Process only `?raw` CSS so tests can read stylesheet
    // source (USK-1245 Header.test.ts); side-effect `import "./x.css"`
    // stays stubbed.
    css: { include: [/\.css\?raw$/] },
  },
});
