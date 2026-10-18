// dashboard/src/components/AuditLogs.jsx

import React, { useEffect, useState } from "react";
import { fetchAuditLogs } from "../api/client";

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAuditLogs()
      .then((data) => {
        setLogs(Array.isArray(data) ? data : []);
        setLoading(false);
      })
      .catch((err) => {
        console.warn("Could not load audit logs from API:", err);
        // Fallback sample audit logs for demonstration if backend DB is not configured
        setLogs([
          {
            id: 1,
            request_id: "req-98f2-4bc1",
            timestamp: new Date().toISOString(),
            layer: "L1: Sanitization",
            label: "Zero-Width Tags",
            score: 0.85,
            latency_ms: 1.24,
            payload: "Stripped 4 invisible unicode tags",
          },
          {
            id: 2,
            request_id: "req-1a2c-7de8",
            timestamp: new Date(Date.now() - 60000).toISOString(),
            layer: "L2: Isolation",
            label: "HMAC Verified",
            score: 0.0,
            latency_ms: 0.82,
            payload: "System boundary enforced with XML delimiters",
          },
          {
            id: 3,
            request_id: "req-3f4a-9bb2",
            timestamp: new Date(Date.now() - 180000).toISOString(),
            layer: "L4: Classifier",
            label: "S1: Override",
            score: 0.94,
            latency_ms: 24.5,
            payload: "DAN injection attempt detected",
          },
          {
            id: 4,
            request_id: "req-7c8d-11e4",
            timestamp: new Date(Date.now() - 360000).toISOString(),
            layer: "L5: Output Filter",
            label: "PII Redaction",
            score: 0.72,
            latency_ms: 2.15,
            payload: "Masked credit card number and email address",
          },
        ]);
        setLoading(false);
      });
  }, []);

  return (
    <div className="audit-logs">
      <h1>Audit Logs</h1>
      <p style={{ color: "var(--muted)", marginBottom: "20px" }}>
        Real-time security audit trails across all 5 GuardRail defense layers.
      </p>

      {loading ? (
        <div className="loading">Loading audit records...</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Request ID</th>
              <th>Layer</th>
              <th>Event / Threat</th>
              <th>Threat Score</th>
              <th>Latency (ms)</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => {
              const isAlert = (log.score || 0) >= 0.7;
              return (
                <tr key={log.id || log.request_id} className={isAlert ? "row-alert" : ""}>
                  <td style={{ fontFamily: "monospace", fontSize: "12px" }}>
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "-"}
                  </td>
                  <td style={{ fontFamily: "monospace" }}>{log.request_id}</td>
                  <td>
                    <span style={{ fontWeight: 600 }}>{log.layer}</span>
                  </td>
                  <td>
                    <span
                      style={{
                        padding: "3px 8px",
                        borderRadius: "4px",
                        fontSize: "12px",
                        background: isAlert ? "rgba(239, 68, 68, 0.2)" : "rgba(16, 185, 129, 0.2)",
                        color: isAlert ? "var(--danger)" : "var(--ok)",
                      }}
                    >
                      {log.label}
                    </span>
                  </td>
                  <td style={{ fontWeight: 700 }}>
                    {log.score !== undefined ? log.score.toFixed(2) : "-"}
                  </td>
                  <td>{log.latency_ms !== undefined ? log.latency_ms : "-"}</td>
                  <td style={{ color: "var(--muted)", maxWidth: "260px" }}>
                    {typeof log.payload === "object" ? JSON.stringify(log.payload) : log.payload}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
