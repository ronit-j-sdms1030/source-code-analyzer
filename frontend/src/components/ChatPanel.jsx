import React, { useState, useRef, useEffect } from "react";
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
            <p className="msg-text">{msg.text}</p>
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

export default function ChatPanel({ project, onAsk }) {
  const [draft, setDraft] = useState("");
  const scrollRef = useRef(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [project.messages.length]);

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
        </div>
        <div className="chat-header-stats">
          <div className="stat">
            <span className="stat-num">{project.files}</span>
            <span className="stat-label">Files</span>
          </div>
          <div className="stat">
            <span className="stat-num online">●</span>
            <span className="stat-label">{MODEL_NAME}</span>
          </div>
        </div>
      </div>

      <div className="chat-scroll" ref={scrollRef}>
        {project.messages.map((m, i) => (
          <ChatMessage msg={m} key={i} />
        ))}
      </div>

      <form className="chat-input-row" onSubmit={submit}>
        <input
          className="chat-input"
          placeholder={`Ask ${project.name} a question — e.g. "where is the database session created?"`}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
        />
        <button type="submit" className="btn-accent send-btn" disabled={!draft.trim()}>
          <Icon.Send />
        </button>
      </form>
    </div>
  );
}
