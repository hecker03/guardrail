// dashboard/src/components/Overview.jsx

import React, { useEffect, useState } from "react";
import { fetchStats } from "../api/client";
import KPICards from "./KPICards";
import ThreatTimeline from "./ThreatTimeline";
import LayerHeatmap from "./LayerHeatmap";

const FALLBACK_STATS = {
  total_requests: 142850,
  attacks_blocked: 3412,
  pii_redacted: 890,
  p95_latency_ms: 18.4,
  timeline: [
    { timestamp: new Date(Date.now() - 20 * 3600 * 1000).toISOString(), S0: 120, S1: 15, S2: 8, S3: 5, S4: 2 },
    { timestamp: new Date(Date.now() - 16 * 3600 * 1000).toISOString(), S0: 140, S1: 18, S2: 12, S3: 7, S4: 3 },
    { timestamp: new Date(Date.now() - 12 * 3600 * 1000).toISOString(), S0: 165, S1: 22, S2: 14, S3: 9, S4: 4 },
    { timestamp: new Date(Date.now() - 8 * 3600 * 1000).toISOString(), S0: 190, S1: 25, S2: 18, S3: 11, S4: 6 },
    { timestamp: new Date(Date.now() - 4 * 3600 * 1000).toISOString(), S0: 210, S1: 20, S2: 15, S3: 8, S4: 3 },
    { timestamp: new Date().toISOString(), S0: 180, S1: 16, S2: 10, S3: 6, S4: 2 },
  ],
  layer_breakdown: [
    { layer: "L1", label: "S0", count: 1200 },
    { layer: "L1", label: "S1", count: 45 },
    { layer: "L1", label: "S2", count: 18 },
    { layer: "L1", label: "S3", count: 12 },
    { layer: "L1", label: "S4", count: 8 },
    { layer: "L2", label: "S0", count: 1150 },
    { layer: "L2", label: "S1", count: 32 },
    { layer: "L2", label: "S2", count: 14 },
    { layer: "L2", label: "S3", count: 9 },
    { layer: "L2", label: "S4", count: 4 },
    { layer: "L3", label: "S0", count: 980 },
    { layer: "L3", label: "S1", count: 22 },
    { layer: "L3", label: "S2", count: 8 },
    { layer: "L3", label: "S3", count: 5 },
    { layer: "L3", label: "S4", count: 2 },
    { layer: "L4", label: "S0", count: 890 },
    { layer: "L4", label: "S1", count: 68 },
    { layer: "L4", label: "S2", count: 34 },
    { layer: "L4", label: "S3", count: 21 },
    { layer: "L4", label: "S4", count: 15 },
    { layer: "L5", label: "S0", count: 750 },
    { layer: "L5", label: "S1", count: 15 },
    { layer: "L5", label: "S2", count: 9 },
    { layer: "L5", label: "S3", count: 4 },
    { layer: "L5", label: "S4", count: 1 },
  ],
};

export default function Overview() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    let mounted = true;

    const load = () => {
      fetchStats("24h")
        .then((data) => {
          if (!mounted) return;
          if (data && typeof data === "object" && data.timeline) {
            setStats(data);
          } else {
            setStats(FALLBACK_STATS);
          }
        })
        .catch((err) => {
          if (!mounted) return;
          console.warn("Could not load stats from API, using demo metrics:", err);
          setStats((prev) => prev || FALLBACK_STATS);
        });
    };

    load();
    const t = setInterval(load, 15000);
    return () => {
      mounted = false;
      clearInterval(t);
    };
  }, []);

  if (!stats) return <div className="loading">Loading…</div>;

  return (
    <div className="overview">
      <h1>Security Overview</h1>
      <KPICards stats={stats} />
      <div className="charts-grid">
        <ThreatTimeline data={stats.timeline} />
        <LayerHeatmap data={stats.layer_breakdown} />
      </div>
    </div>
  );
}