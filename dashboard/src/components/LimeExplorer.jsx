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
      setResult({ error: e.response?.data?.detail || e.message });
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
      <button onClick={run} disabled={loading}>
        {loading ? "Analyzing…" : "Analyze"}
      </button>

      {result?.xai && (
        <div className="lime-result">
          <div className="prediction">
            <strong>Prediction:</strong> {result.label} ({(result.confidence * 100).toFixed(1)}%)
          </div>
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
      {result?.error && <div className="error">{JSON.stringify(result.error)}</div>}
    </div>
  );
}