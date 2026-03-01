import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { McpProvider } from "./lib/mcp/index.js";
import { ToastProvider } from "./components/ui/index.js";
import { initAuth } from "./lib/auth.js";
import App from "./App.js";
import "./styles/global.css";
import "./styles/pages.css";

const token = initAuth();
const mcpConfig = { url: "/mcp", token };

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <McpProvider config={mcpConfig}>
      <BrowserRouter>
        <ToastProvider>
          <App />
        </ToastProvider>
      </BrowserRouter>
    </McpProvider>
  </StrictMode>,
);
