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
