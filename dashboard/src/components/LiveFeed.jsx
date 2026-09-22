// dashboard/src/components/LiveFeed.jsx

import React, { useEffect, useState } from "react";

const WS_URL = process.env.REACT_APP_WS_URL || "ws://localhost:8000/ws/events";

export default function LiveFeed() {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    const ws = new WebSocket(WS_URL);
    ws.onmessage = (e) => {
      const evt = JSON.parse(e.data);
      setEvents((prev) => [evt, ...prev].slice(0, 200));
    };
    ws.onerror = () => {
      // Fallback: poll
    };
    return () => ws.close();
  }, []);

  return (
    <div className="live-feed">
      <h1>Live Event Feed</h1>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Layer</th>
            <th>Label</th>
            <th>Score</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i} className={e.label !== "S0" ? "row-alert" : ""}>
              <td>{new Date(e.timestamp).toLocaleTimeString()}</td>
              <td>{e.layer}</td>
              <td>{e.label}</td>
              <td>{e.score?.toFixed?.(3)}</td>
              <td>{e.latency_ms} ms</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}