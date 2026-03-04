import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout/index.js";
import { DashboardPage } from "./pages/Dashboard/DashboardPage.js";
import { FlowsPage } from "./pages/Flows/FlowsPage.js";
import { FlowDetailPage } from "./pages/FlowDetail/FlowDetailPage.js";
import { InterceptPage } from "./pages/Intercept/InterceptPage.js";
import { ResendPage } from "./pages/Resend/ResendPage.js";
import { FuzzPage } from "./pages/Fuzz/FuzzPage.js";
import { FuzzResultsPage } from "./pages/Fuzz/FuzzResultsPage.js";
import { MacrosPage } from "./pages/Macros/MacrosPage.js";
import { MacroDetailPage } from "./pages/Macros/MacroDetailPage.js";
import { SettingsPage } from "./pages/Settings/SettingsPage.js";
import { SecurityPage } from "./pages/Security/SecurityPage.js";

function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<FlowsPage />} />
        <Route path="flows/:id" element={<FlowDetailPage />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="intercept" element={<InterceptPage />} />
        <Route path="resend" element={<ResendPage />} />
        <Route path="resend/:flowId" element={<ResendPage />} />
        <Route path="fuzz" element={<FuzzPage />} />
        <Route path="fuzz/:fuzzId" element={<FuzzResultsPage />} />
        <Route path="macros" element={<MacrosPage />} />
        <Route path="macros/:name" element={<MacroDetailPage />} />
        <Route path="security" element={<SecurityPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}

export default App;
