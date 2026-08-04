import React, { useState, useRef, useEffect } from "react";
import { MODEL_NAME } from "../lib/api";

export default function NewProjectPanel({ open, onClose, onCreate }) {
  const [url, setUrl] = useState("");
  const inputRef = useRef(null);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 180);
  }, [open]);

  const submit = (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    onCreate(url.trim());
    setUrl("");
  };

  return (
    <div className={`new-project ${open ? "open" : ""}`}>
      <form onSubmit={submit} className="new-project-form">
        <label className="field-label">GitHub repository URL</label>
        <input
          ref={inputRef}
          className="field-input"
          placeholder="https://github.com/owner/repo"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <div className="new-project-actions">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-accent" disabled={!url.trim()}>
            Index repository
          </button>
        </div>
        <p className="field-hint">
          Shallow clone · Python files only · runs fully on local Ollama + {MODEL_NAME}
        </p>
      </form>
    </div>
  );
}
