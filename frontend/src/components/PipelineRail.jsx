import React from "react";

export const STAGES = [
  { key: "clone", label: "Clone" },
  { key: "filter", label: "Filter" },
  { key: "scan", label: "Scan" },
  { key: "split", label: "Split" },
  { key: "embed", label: "Embed" },
  { key: "store", label: "Store" },
];

export default function PipelineRail({ stageIndex, embedProgress, size = "full" }) {
  const mini = size === "mini";
  return (
    <div className={`rail ${mini ? "rail-mini" : ""}`}>
      {STAGES.map((s, i) => {
        const done = i < stageIndex;
        const active = i === stageIndex;
        return (
          <React.Fragment key={s.key}>
            <div className={`rail-node ${done ? "done" : ""} ${active ? "active" : ""}`}>
              {!mini && <span className="rail-node-index">{String(i + 1).padStart(2, "0")}</span>}
              {!mini && <span className="rail-node-label">
                {s.label}
                {s.key === "embed" && active && embedProgress !== undefined && (
                  <span className="embed-progress" style={{ opacity: 0.7, fontSize: '0.9em', marginLeft: '4px' }}>
                    {embedProgress}%
                  </span>
                )}
              </span>}
            </div>
            {i < STAGES.length - 1 && (
              <div className={`rail-link ${i < stageIndex ? "done" : ""}`}>
                <span className="rail-link-fill" />
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
