import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout/index.js";
import { SessionsPage } from "./pages/Sessions/SessionsPage.js";
import { SessionDetailPage } from "./pages/SessionDetail/SessionDetailPage.js";
import { InterceptPage } from "./pages/Intercept/InterceptPage.js";
import { ResendPage } from "./pages/Resend/ResendPage.js";
import { FuzzPage } from "./pages/Fuzz/FuzzPage.js";
import { FuzzResultsPage } from "./pages/Fuzz/FuzzResultsPage.js";
import { SettingsPage } from "./pages/Settings/SettingsPage.js";

function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<SessionsPage />} />
        <Route path="sessions/:id" element={<SessionDetailPage />} />
        <Route path="intercept" element={<InterceptPage />} />
        <Route path="resend" element={<ResendPage />} />
        <Route path="resend/:sessionId" element={<ResendPage />} />
        <Route path="fuzz" element={<FuzzPage />} />
        <Route path="fuzz/:fuzzId" element={<FuzzResultsPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}

export default App;
