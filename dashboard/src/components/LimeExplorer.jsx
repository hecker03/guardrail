// dashboard/src/components/LimeExplorer.jsx

import React, { useState } from "react";
import { fetchPipeline } from "../api/client";

export default function LimeExplorer() {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    try {
      const res = await fetchPipeline({
        system_prompt: "You are a helpful assistant.",
        user_message: text,
      });
      setResult(res.classification);
    } catch (e) {
      const detail = e.response?.data?.detail;
      if (detail && detail.xai) {
        setResult({
          label: detail.label,
          confidence: detail.confidence,
          xai: detail.xai,
          layer: detail.layer || "L4",
          blocked: true,
        });
      } else if (detail && detail.reason) {
        setResult({
          error: `Request blocked at ${detail.layer || "Pipeline"}: ${detail.reason}`,
        });
      } else {
        setResult({
          label: "S1 (Prompt Injection)",
          confidence: 0.942,
          blocked: true,
          layer: "L4",
          xai: {
            token_attributions: [
              ["Ignore", 0.88],
              ["all", 0.42],
              ["previous", 0.76],
              ["instructions", 0.84],
              ["and", 0.05],
              ["reveal", 0.72],
              ["system", 0.65],
              ["prompt", 0.78],
            ],
          },
          note: `Demo explanation (Backend offline: ${e.message})`,
        });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="lime-explorer">
      <h1>LIME Token Explainer</h1>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Paste a prompt to analyze…"
        rows={6}
      />
      <button onClick={run} disabled={loading || !text.trim()}>
        {loading ? "Analyzing…" : "Analyze"}
      </button>

      {result?.xai && (
        <div className="lime-result">
          <div className="prediction">
            <strong>Prediction:</strong> {result.label} ({(result.confidence * 100).toFixed(1)}%)
            {result.blocked && (
              <span
                style={{
                  marginLeft: "10px",
                  padding: "3px 8px",
                  borderRadius: "4px",
                  fontSize: "12px",
                  background: "rgba(239, 68, 68, 0.2)",
                  color: "var(--danger)",
                  fontWeight: 600,
                }}
              >
                Blocked by {result.layer || "L4"}
              </span>
            )}
          </div>
          {result.note && (
            <div style={{ fontSize: "12px", color: "var(--muted)", margin: "4px 0 10px 0" }}>
              {result.note}
            </div>
          )}
          <div className="tokens">
            {result.xai.token_attributions.map(([token, weight], i) => (
              <span
                key={i}
                className="token"
                style={{
                  backgroundColor:
                    weight > 0
                      ? `rgba(239,68,68,${Math.min(Math.abs(weight), 1)})`
                      : `rgba(16,185,129,${Math.min(Math.abs(weight), 1)})`,
                }}
                title={`weight=${weight.toFixed(3)}`}
              >
                {token}
              </span>
            ))}
          </div>
        </div>
      )}
      {result?.error && (
        <div className="error">
          {typeof result.error === "object" ? JSON.stringify(result.error) : result.error}
        </div>
      )}
    </div>
  );
}