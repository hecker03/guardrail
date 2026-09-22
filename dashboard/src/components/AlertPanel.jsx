// dashboard/src/components/AlertPanel.jsx

import React, { useEffect, useState } from "react";
import { fetchAlerts } from "../api/client";

export default function AlertPanel() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const load = () => fetchAlerts().then(setAlerts);
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="alerts">
      <h1>Alerts</h1>
      {alerts.length === 0 && <p className="muted">No active alerts.</p>}
      <ul>
        {alerts.map((a) => (
          <li key={a.id} className={`alert alert-${a.severity}`}>
            <div className="alert-title">
              [{a.severity.toUpperCase()}] {a.title}
            </div>
            <div className="alert-body">{a.message}</div>
            <div className="alert-meta">
              {new Date(a.timestamp).toLocaleString()} · {a.layer}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}