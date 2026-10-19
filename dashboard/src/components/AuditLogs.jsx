// dashboard/src/components/AuditLogs.jsx

import React, { useEffect, useState } from "react";
import { fetchAuditLogs } from "../api/client";

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
  let mounted = true;
  const load = () => {
    fetchAuditLogs({ limit: 100 })
      .then((data) => {
        if (mounted) {
          setLogs(Array.isArray(data) ? data : []);
          setLoading(false);
        }
      })
      .catch((err) => {
        console.error("Could not load audit logs:", err);
        if (mounted) {
          setLogs([]);
          setLoading(false);
        }
      });
  };

  load();
  const timer = setInterval(load, 3000);

  return () => {
    mounted = false;
    clearInterval(timer);
  };
  }, []);

  return (
    <div className="audit-logs">
      <h1>Audit Logs</h1>
      <p style={{ color: "var(--muted)", marginBottom: "20px" }}>
        Live security events from currently integrated GuardRail layers.
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
