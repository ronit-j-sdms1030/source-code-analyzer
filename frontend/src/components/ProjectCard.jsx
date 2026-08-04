import React, { useState } from "react";
import Icon from "./icons";
import PipelineRail from "./PipelineRail";

export default function ProjectCard({ project, active, onSelect, onDelete }) {
  const [confirming, setConfirming] = useState(false);
  const statusMeta = {
    ready: { label: "Ready", color: "var(--status-ready)" },
    indexing: { label: "Indexing", color: "var(--status-indexing)" },
    error: { label: "Failed", color: "var(--status-error)" },
  }[project.status];

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
        <button
          className="delete-trigger"
          aria-label={`Delete ${project.name}`}
          onClick={(e) => {
            e.stopPropagation();
            setConfirming(true);
          }}
        >
          <Icon.Trash />
        </button>
      </div>
      <div className="project-card-url">{project.url.replace("https://", "")}</div>
      {project.status === "ready" ? (
        <div className="project-card-meta">
          <span>{project.files} files</span>
          <span className="meta-sep">·</span>
          <span>{project.indexedAt}</span>
        </div>
      ) : project.status === "error" ? (
        <div className="project-card-error">
          <span>⚠ {project.error || "Indexing failed. Please try again."}</span>
        </div>
      ) : (
        <PipelineRail stageIndex={project.stageIndex} size="mini" />
      )}
      {confirming && (
        <div className="delete-confirm" onClick={(e) => e.stopPropagation()}>
          <span>Delete this repo?</span>
          <div className="delete-confirm-actions">
            <button
              className="delete-confirm-cancel"
              onClick={() => setConfirming(false)}
            >
              Cancel
            </button>
            <button
              className="delete-confirm-delete"
              onClick={() => onDelete(project.id)}
            >
              Delete
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
