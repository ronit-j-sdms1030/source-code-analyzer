import React, { useState, useRef, useEffect } from "react";
import ReactMarkdown from "react-markdown";
import Icon from "./icons";
import { MODEL_NAME } from "../lib/api";

export function ChatMessage({ msg }) {
  const isUser = msg.role === "user";
  return (
    <div className={`msg ${isUser ? "msg-user" : "msg-assistant"}`}>
      <div className="msg-role">{isUser ? "You" : MODEL_NAME}</div>
      <div className="msg-bubble">
        {msg.pending ? (
          <span className="thinking">
            <span className="dot" /><span className="dot" /><span className="dot" />
          </span>
        ) : (
          <>
            <div className="msg-text">
              <ReactMarkdown>{msg.text}</ReactMarkdown>
            </div>
            {msg.sources && msg.sources.length > 0 && (
              <div className="source-chips">
                {msg.sources.map((s) => (
                  <span key={s} className="source-chip">
                    <Icon.File />
                    {s}
                  </span>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default function ChatPanel({ project, onAsk, onViewReport, onDelete }) {
  const [draft, setDraft] = useState("");
  const scrollRef = useRef(null);

  const v = project.vulnerabilities;
  const hasVulns = v && (v.high > 0 || v.medium > 0 || v.low > 0);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [project.messages]);

  const submit = (e) => {
    e.preventDefault();
    if (!draft.trim()) return;
    onAsk(project.id, draft.trim());
    setDraft("");
  };

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <div>
          <div className="chat-header-name">{project.name}</div>
          <div className="chat-header-sub">{project.url.replace("https://", "")}</div>
          {v && (
            <div className="security-badges" style={{ marginTop: "12px" }}>
              {v.high > 0 && <span className="sec-badge high">🔴 {v.high} High</span>}
              {v.medium > 0 && <span className="sec-badge medium">🟡 {v.medium} Med</span>}
              {v.low > 0 && <span className="sec-badge low">🔵 {v.low} Low</span>}
              {!hasVulns && <span className="sec-badge clean">✅ Secure</span>}
              <span 
                className="sec-badge" 
                style={{ marginLeft: "6px", borderStyle: "dashed", cursor: "pointer" }}
                onClick={() => onViewReport && onViewReport(project)}
              >
                View Report
              </span>
            </div>
          )}
        </div>
        <div className="chat-header-stats">
          <div className="stat">
            <span className="stat-num">{project.files}</span>
            <span className="stat-label">Files</span>
          </div>
          <div className="stat" style={{ display: 'flex', gap: '4px', alignItems: 'center', marginLeft: '12px' }}>
            <button
              className="action-btn"
              title="Download Code Repository (.zip)"
              onClick={() => window.open(`http://127.0.0.1:5000/projects/${project.id}/download/repo`)}
            >
              <Icon.Download />
            </button>
            {hasVulns && (
              <button
                className="action-btn"
                title="Download Vulnerability Report (.json)"
                onClick={() => window.open(`http://127.0.0.1:5000/projects/${project.id}/download/report`)}
              >
                <Icon.File />
              </button>
            )}
            <button
              className="action-btn delete-trigger"
              title={`Delete ${project.name}`}
              onClick={() => {
                if (window.confirm(`Are you sure you want to delete ${project.name}?`)) {
                  onDelete && onDelete(project.id);
                }
              }}
            >
              <Icon.Trash />
            </button>
          </div>
        </div>
      </div>

      <div className="chat-scroll" ref={scrollRef}>
        {project.messages.map((m, i) => (
          <ChatMessage msg={m} key={i} />
        ))}
      </div>

      <form className="chat-input-wrapper" onSubmit={submit}>
        <textarea
          className="chat-input-box"
          placeholder="Ask anything, @ to mention, / for actions"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit(e);
            }
          }}
          rows={1}
        />
        <div className="chat-input-toolbar">
          <div className="toolbar-left">
            <button type="button" className="toolbar-btn plus-btn">
              <Icon.Plus />
            </button>
          </div>
          <div className="toolbar-right">
            <button type="submit" className="toolbar-btn send-btn-round" disabled={!draft.trim()}>
              <Icon.ArrowRight />
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
