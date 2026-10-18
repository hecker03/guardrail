// dashboard/src/components/AlertPanel.jsx

import React, { useEffect, useState } from "react";
import { fetchAlerts } from "../api/client";

const FALLBACK_ALERTS = [
  {
    id: "alt-1",
    severity: "critical",
    title: "Layer 4 Adversarial Injection Spike",
    message: "High-confidence S1 jailbreak patterns detected across multiple incoming requests.",
    timestamp: new Date().toISOString(),
    layer: "L4: Classifier",
  },
  {
    id: "alt-2",
    severity: "warning",
    title: "Layer 1 Tag Evasion Attempt",
    message: "Multiple requests with Unicode tag block payloads (U+E0000) stripped.",
    timestamp: new Date(Date.now() - 300000).toISOString(),
    layer: "L1: Sanitizer",
  },
  {
    id: "alt-3",
    severity: "warning",
    title: "Layer 5 PII Exposure Blocked",
    message: "Credit card number pattern detected in model response and successfully masked.",
    timestamp: new Date(Date.now() - 720000).toISOString(),
    layer: "L5: Output Filter",
  },
];

export default function AlertPanel() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    let mounted = true;

    const load = () => {
      fetchAlerts()
        .then((data) => {
          if (!mounted) return;
          setAlerts(Array.isArray(data) ? data : FALLBACK_ALERTS);
        })
        .catch((err) => {
          if (!mounted) return;
          console.warn("Could not load alerts from API, using demo alerts:", err);
          setAlerts((prev) => (prev.length ? prev : FALLBACK_ALERTS));
        });
    };

    load();
    const t = setInterval(load, 10000);
    return () => {
      mounted = false;
      clearInterval(t);
    };
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