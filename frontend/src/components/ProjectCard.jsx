import React, { useState } from "react";
import Icon from "./icons";
import PipelineRail from "./PipelineRail";

export default function ProjectCard({ project, active, onSelect, onDelete, onViewReport }) {
  const [confirming, setConfirming] = useState(false);
  const statusMeta = {
    ready: { label: "Ready", color: "var(--status-ready)" },
    indexing: { label: "Indexing", color: "var(--status-indexing)" },
    error: { label: "Failed", color: "var(--status-error)" },
  }[project.status];

  const v = project.vulnerabilities;
  const hasVulns = v && (v.high > 0 || v.medium > 0 || v.low > 0);
  // "Secure" only shows when the project has been scanned (v exists) and everything is 0
  const isSecure = v && !hasVulns;

  // Pick the most-severe colour for the badge label
  const vulnLabel = hasVulns
    ? v.high > 0
      ? `${v.high} High`
      : v.medium > 0
      ? `${v.medium} Med`
      : `${v.low} Low`
    : null;
  const vulnColor = hasVulns
    ? v.high > 0
      ? "var(--status-error)"
      : v.medium > 0
      ? "var(--status-warning)"
      : "var(--text-tertiary)"
    : null;

  return (
    <div
      className={`project-card ${active ? "active" : ""}`}
      role="button"
      tabIndex={0}
      onClick={() => onSelect(project.id)}
      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelect(project.id)}
    >
      <div className="project-card-top">
        <Icon.Repo className="project-card-icon" />
        <span className="project-card-name">{project.name}</span>
        <span className="status-chip" style={{ "--dot": statusMeta.color }}>
          <Icon.Dot />
          {statusMeta.label}
        </span>
      </div>
      <div className="project-card-url">{project.url.replace("https://", "")}</div>
      {project.status === "ready" ? (
        <>
          <div className="project-card-meta">
            <span>{project.files} files</span>
            <span className="meta-sep">·</span>
            <span>{project.indexedAt}</span>
            {/* Vulnerability / Secure badge */}
            {hasVulns && (
              <>
                <span className="meta-sep">·</span>
                <button
                  onClick={(e) => { e.stopPropagation(); onViewReport && onViewReport(project); }}
                  style={{
                    background: "none",
                    border: `1px solid ${vulnColor}`,
                    color: vulnColor,
                    borderRadius: "4px",
                    padding: "1px 7px",
                    fontSize: "11px",
                    fontWeight: 700,
                    cursor: "pointer",
                    lineHeight: "18px",
                    letterSpacing: "0.03em",
                  }}
                  title="View vulnerability report"
                >
                  ⚠ {vulnLabel}
                </button>
              </>
            )}
            {isSecure && (
              <>
                <span className="meta-sep">·</span>
                <span style={{
                  color: "var(--status-ready)",
                  fontSize: "11px",
                  fontWeight: 700,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "3px",
                  letterSpacing: "0.03em",
                }}>
                  ✓ Secure
                </span>
              </>
            )}
          </div>
        </>
      ) : project.status === "error" ? (
        <div className="project-card-error">
          <span>⚠ {project.error || "Indexing failed. Please try again."}</span>
        </div>
      ) : (
        <PipelineRail stageIndex={project.stageIndex} size="mini" />
      )}
    </div>
  );
}
