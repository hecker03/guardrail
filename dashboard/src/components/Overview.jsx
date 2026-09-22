// dashboard/src/components/Overview.jsx

import React, { useEffect, useState } from "react";
import { fetchStats } from "../api/client";
import KPICards from "./KPICards";
import ThreatTimeline from "./ThreatTimeline";
import LayerHeatmap from "./LayerHeatmap";

export default function Overview() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    fetchStats("24h").then(setStats);
    const t = setInterval(() => fetchStats("24h").then(setStats), 15000);
    return () => clearInterval(t);
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