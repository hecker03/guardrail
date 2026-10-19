import React, { useEffect, useState } from "react";

const WS_URL =
  process.env.REACT_APP_WS_URL ||
  "ws://127.0.0.1:8000/ws/events";

export default function LiveFeed() {
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState("connecting");
  const [error, setError] = useState("");

  useEffect(() => {
    let socket = null;
    let reconnectTimer = null;
    let stopped = false;

    const connect = () => {
      if (stopped) return;

      setStatus("connecting");
      setError("");

      socket = new WebSocket(WS_URL);

      socket.onopen = () => {
        if (stopped) return;

        setStatus("connected");
        setError("");
      };

      socket.onmessage = (message) => {
        if (stopped) return;

        try {
          const event = JSON.parse(message.data);

          setEvents((previous) => {
            return [event, ...previous].slice(0, 200);
          });
        } catch (err) {
          console.error("Invalid WebSocket event:", err);
        }
      };

      socket.onerror = () => {
        if (stopped) return;

        setStatus("error");
        setError(
          "The live WebSocket connection failed. " +
          "Verify that the FastAPI backend is running."
        );
      };

      socket.onclose = () => {
        if (stopped) return;

        setStatus("disconnected");

        reconnectTimer = setTimeout(() => {
          connect();
        }, 3000);
      };
    };

    connect();

    return () => {
      stopped = true;

      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }

      if (socket) {
        socket.close();
      }
    };
  }, []);

  const statusColor = {
    connected: "#10b981",
    connecting: "#f59e0b",
    disconnected: "#ef4444",
    error: "#ef4444",
  }[status];

  return (
    <div className="live-feed">
      <h1>Live Event Feed</h1>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          marginBottom: "16px",
          color: statusColor,
          fontWeight: 600,
        }}
      >
        <span>●</span>
        <span>WebSocket status: {status}</span>
      </div>

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

      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Request ID</th>
            <th>Layer</th>
            <th>Label</th>
            <th>Action</th>
            <th>Score</th>
            <th>Latency</th>
          </tr>
        </thead>

        <tbody>
          {events.length === 0 ? (
            <tr>
              <td
                colSpan="7"
                style={{
                  textAlign: "center",
                  padding: "30px",
                  color: "#94a3b8",
                }}
              >
                {status === "connected"
                  ? "Connected. Waiting for security events…"
                  : "No live connection to the backend."}
              </td>
            </tr>
          ) : (
            events.map((event, index) => (
              <tr
                key={event.id || `${event.request_id}-${index}`}
                className={
                  event.action === "rejected" ||
                  event.action === "blocked"
                    ? "row-alert"
                    : ""
                }
              >
                <td>
                  {event.timestamp
                    ? new Date(event.timestamp).toLocaleTimeString()
                    : "-"}
                </td>

                <td
                  style={{
                    fontFamily: "monospace",
                    fontSize: "12px",
                  }}
                >
                  {event.request_id || "-"}
                </td>

                <td>{event.layer || "-"}</td>

                <td>{event.label || "-"}</td>

                <td>{event.action || "-"}</td>

                <td>
                  {typeof event.score === "number"
                    ? event.score.toFixed(3)
                    : "-"}
                </td>

                <td>
                  {typeof event.latency_ms === "number"
                    ? `${event.latency_ms} ms`
                    : "-"}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}