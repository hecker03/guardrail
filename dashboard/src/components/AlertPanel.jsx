import React, { useEffect, useState } from "react";
import { fetchAlerts } from "../api/client";

export default function AlertPanel() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let mounted = true;

    const loadAlerts = () => {
      fetchAlerts()
        .then((data) => {
          if (!mounted) return;

          if (Array.isArray(data)) {
            setAlerts(data);
            setError("");
          } else {
            setAlerts([]);
            setError("The backend returned an invalid alert response.");
          }

          setLoading(false);
        })
        .catch((err) => {
          if (!mounted) return;

          console.error("Could not load live alerts:", err);

          setAlerts([]);
          setError(
            "The live alert service is unavailable. " +
            "No demonstration alerts are being shown."
          );
          setLoading(false);
        });
    };

    loadAlerts();

    const timer = setInterval(loadAlerts, 10000);

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const severityColor = (severity) => {
    switch ((severity || "").toLowerCase()) {
      case "critical":
        return "#ef4444";

      case "warning":
      case "high":
        return "#f59e0b";

      case "medium":
        return "#fbbf24";

      default:
        return "#3b82f6";
    }
  };

  return (
    <div className="alerts">
      <h1>Alerts</h1>

      {error && (
        <div
          className="error"
          style={{
            marginBottom: "16px",
            padding: "12px 16px",
            border: "1px solid #ef4444",
            borderRadius: "6px",
            background: "rgba(239, 68, 68, 0.12)",
            color: "#fca5a5",
          }}
        >
          {error}
        </div>
      )}

      {!error && !loading && (
        <div
          style={{
            marginBottom: "16px",
            color: "#10b981",
            fontSize: "14px",
          }}
        >
          ● Live alerts from the GUARDRAIL backend
        </div>
      )}

      {loading ? (
        <div className="loading">Loading live alerts…</div>
      ) : alerts.length === 0 ? (
        <div
          style={{
            padding: "24px",
            border: "1px solid #334155",
            borderRadius: "8px",
            color: "#94a3b8",
            background: "rgba(30, 41, 59, 0.5)",
          }}
        >
          {error
            ? "Live alerts cannot be retrieved."
            : "No active security alerts for this server session."}
        </div>
      ) : (
        <ul
          style={{
            listStyle: "none",
            padding: 0,
            margin: 0,
          }}
        >
          {alerts.map((alert, index) => {
            const severity = alert.severity || "info";
            const color = severityColor(severity);

            return (
              <li
                key={alert.id || `${alert.timestamp}-${index}`}
                className={`alert alert-${severity}`}
                style={{
                  marginBottom: "14px",
                  padding: "18px 20px",
                  border: `1px solid ${color}`,
                  borderLeft: `5px solid ${color}`,
                  borderRadius: "8px",
                  background: "rgba(30, 41, 59, 0.7)",
                }}
              >
                <div
                  className="alert-title"
                  style={{
                    color,
                    fontWeight: 700,
                    marginBottom: "8px",
                  }}
                >
                  [{severity.toUpperCase()}]{" "}
                  {alert.title || "Security event"}
                </div>

                <div
                  className="alert-body"
                  style={{
                    color: "#e2e8f0",
                    marginBottom: "8px",
                  }}
                >
                  {alert.message || "No additional details available."}
                </div>

                <div
                  className="alert-meta"
                  style={{
                    color: "#94a3b8",
                    fontSize: "12px",
                  }}
                >
                  {alert.timestamp
                    ? new Date(alert.timestamp).toLocaleString()
                    : "Unknown time"}

                  {" · "}

                  {alert.layer || "Unknown layer"}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}