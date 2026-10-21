import React, { useEffect, useState } from "react";
import { fetchStats } from "../api/client";
import KPICards from "./KPICards";
import ThreatTimeline from "./ThreatTimeline";
import LayerHeatmap from "./LayerHeatmap";

const EMPTY_STATS = {
  total_requests: 0,
  attacks_blocked: 0,
  pii_redacted: 0,
  p95_latency_ms: 0,
  timeline: [],
  layer_breakdown: [],
};

export default function Overview() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let mounted = true;

    const load = () => {
      fetchStats("24h")
        .then((data) => {
          if (!mounted) return;

          if (data && typeof data === "object") {
            setStats({
              total_requests: data.total_requests || 0,
              attacks_blocked: data.attacks_blocked || 0,
              pii_redacted: data.pii_redacted || 0,
              p95_latency_ms: data.p95_latency_ms || 0,
              timeline: Array.isArray(data.timeline)
                ? data.timeline
                : [],
              layer_breakdown: Array.isArray(data.layer_breakdown)
                ? data.layer_breakdown
                : [],
            });

            setError("");
          } else {
            setStats(EMPTY_STATS);
            setError("The backend returned an invalid statistics response.");
          }
        })
        .catch((err) => {
          if (!mounted) return;

          console.error("Could not load live statistics:", err);

          setStats(EMPTY_STATS);
          setError(
            "Live monitoring backend is unavailable. " +
            "No demonstration statistics are being shown."
          );
        });
    };

    load();

    const timer = setInterval(load, 15000);

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  if (!stats) {
    return <div className="loading">Loading live statistics…</div>;
  }

  return (
    <div className="overview">
      <h1>Security Overview</h1>

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

      {!error && (
        <div
          style={{
            marginBottom: "16px",
            color: "#10b981",
            fontSize: "14px",
          }}
        >
          ● Live session data from the GUARDRAIL backend
        </div>
      )}

      <KPICards stats={stats} />

      <div className="charts-grid">
        <ThreatTimeline data={stats.timeline} />
        <LayerHeatmap data={stats.layer_breakdown} />
      </div>
    </div>
  );
}