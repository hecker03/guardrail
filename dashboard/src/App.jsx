// dashboard/src/App.jsx

import React from "react";
import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Shield, Activity, Zap, FileText, Bell } from "lucide-react";
import Overview from "./components/Overview";
import LiveFeed from "./components/LiveFeed";
// import LimeExplorer from "./components/LimeExplorer";
import AuditLogs from "./components/AuditLogs";
import AlertPanel from "./components/AlertPanel";
import "./styles/app.css";

export default function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <aside className="sidebar">
          <div className="logo">
            <Shield size={28} /> <span>GuardRail</span>
          </div>
          <nav>
            <NavLink to="/" end><Activity size={18} /> Overview</NavLink>
            <NavLink to="/live"><Zap size={18} /> Live Feed</NavLink>
            {/* <NavLink to="/lime"><FileText size={18} /> LIME Explorer</NavLink> */}
            <NavLink to="/audit"><FileText size={18} /> Audit Logs</NavLink>
            <NavLink to="/alerts"><Bell size={18} /> Alerts</NavLink>
          </nav>
        </aside>
        <main className="content">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/live" element={<LiveFeed />} />
            {/* <Route path="/lime" element={<LimeExplorer />} /> */}
            <Route path="/audit" element={<AuditLogs />} />
            <Route path="/alerts" element={<AlertPanel />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}