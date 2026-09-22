// dashboard/src/components/KPICards.jsx

import React from "react";

export default function KPICards({ stats }) {
  const kpis = [
    { label: "Total Requests", value: stats.total_requests, color: "#3b82f6" },
    { label: "Attacks Blocked", value: stats.attacks_blocked, color: "#ef4444" },
    { label: "PII Redacted", value: stats.pii_redacted, color: "#f59e0b" },
    { label: "p95 Latency (ms)", value: stats.p95_latency_ms, color: "#10b981" },
  ];

  return (
    <div className="kpi-grid">
      {kpis.map((k) => (
        <div key={k.label} className="kpi-card" style={{ borderColor: k.color }}>
          <div className="kpi-label">{k.label}</div>
          <div className="kpi-value" style={{ color: k.color }}>
            {k.value?.toLocaleString?.() ?? k.value}
          </div>
        </div>
      ))}
    </div>
  );
}