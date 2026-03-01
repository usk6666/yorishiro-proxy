import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/mcp/webui/dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/mcp": {
        target: "http://127.0.0.1:8943",
        changeOrigin: true,
      },
    },
  },
});
