import { useState, useCallback } from "react";
import { Outlet } from "react-router-dom";
import { Header } from "./Header.js";
import { Sidebar } from "./Sidebar.js";
import "./Layout.css";

export function Layout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => !prev);
  }, []);

  return (
    <div className="layout">
      <Header
        onToggleSidebar={toggleSidebar}
        sidebarCollapsed={sidebarCollapsed}
      />
      <div className="layout-body">
        <Sidebar collapsed={sidebarCollapsed} />
        <main className="layout-main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
