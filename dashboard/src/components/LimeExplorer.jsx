import React from "react";

export default function LimeExplorer() {
  return (
    <div className="lime-explorer">
      <h1>LIME Token Explainer</h1>

      <div
        style={{
          marginTop: "20px",
          padding: "24px",
          border: "1px solid #f59e0b",
          borderRadius: "8px",
          background: "rgba(245, 158, 11, 0.10)",
        }}
      >
        <h2
          style={{
            marginTop: 0,
            color: "#fbbf24",
          }}
        >
          Layer-4 explainability is under integration
        </h2>

        <p
          style={{
            color: "#cbd5e1",
            lineHeight: 1.6,
          }}
        >
          The user interface for LIME explanations has been created,
          but live Layer-4 explanations are disabled until an approved
          trained classifier checkpoint and held-out evaluation results
          are available.
        </p>

        <p
          style={{
            color: "#94a3b8",
            lineHeight: 1.6,
            marginBottom: 0,
          }}
        >
          No fallback prediction, confidence score, or token attribution
          is displayed because demonstration values could be mistaken
          for executed model results.
        </p>
      </div>
    </div>
  );
}