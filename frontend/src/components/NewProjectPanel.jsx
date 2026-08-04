import React, { useState, useRef, useEffect } from "react";
import { MODEL_NAME } from "../lib/api";

export default function NewProjectPanel({ open, onClose, onCreate }) {
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const inputRef = useRef(null);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 180);
    if (!open) { setToken(""); setShowToken(false); }
  }, [open]);

  const submit = (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    onCreate(url.trim(), token.trim());
    setUrl("");
    setToken("");
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

        {showToken ? (
          <>
            <label className="field-label" style={{ marginTop: "0.75rem" }}>
              Access Token
              <span
                onClick={() => { setShowToken(false); setToken(""); }}
                style={{ marginLeft: "0.5rem", opacity: 0.5, cursor: "pointer", fontWeight: 400 }}
              >
                ✕ remove
              </span>
            </label>
            <input
              className="field-input"
              type="password"
              placeholder="github_pat_xxxxxxxxxxxx"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          </>
        ) : (
          <button
            type="button"
            onClick={() => setShowToken(true)}
            style={{
              background: "none", border: "none", padding: "0.4rem 0",
              color: "var(--accent)", cursor: "pointer", fontSize: "0.78rem",
              textAlign: "left", opacity: 0.75,
            }}
          >
            🔒 Private repo? Add access token
          </button>
        )}

        <div className="new-project-actions">
          <button type="button" className="btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-accent" disabled={!url.trim() || (showToken && !token.trim())}>
            Index repository
          </button>
        </div>
        <p className="field-hint">
          Shallow clone · Python, JS, TS, Java, Go & more · powered by {MODEL_NAME}
        </p>
      </form>
    </div>
  );
}

