import React, { useState, useRef, useEffect } from "react";
import ReactMarkdown from "react-markdown";
import Icon from "./icons";
import { getVulnerabilities, autoFixVulnerability, rescanVulnerabilities } from "../lib/api";
import { MODEL_NAME } from "../lib/api";

const CodeBlock = ({ node, inline, className, children, ...props }) => {
  const match = /language-(\w+)/.exec(className || "");
  const lang = match ? match[1] : "";
  const codeText = String(children).replace(/\n$/, "");

  if (!inline && lang === "diff") {
    return (
      <pre className={className} style={{ backgroundColor: "#1e1e1e", padding: "12px", borderRadius: "6px", overflowX: "auto", fontSize: "13px", lineHeight: "1.5" }}>
        <code className={className} {...props}>
          {codeText.split("\n").map((line, i) => {
            let color = "#d4d4d4";
            if (line.startsWith("+") && !line.startsWith("+++")) color = "#4ade80"; // green
            else if (line.startsWith("-") && !line.startsWith("---")) color = "#f87171"; // red
            else if (line.startsWith("@@")) color = "#a78bfa"; // purple
            
            return (
              <div key={i} style={{ color, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                {line || " "}
              </div>
            );
          })}
        </code>
      </pre>
    );
  }
  
  return !inline ? (
    <pre className={className} style={{ backgroundColor: "#1e1e1e", padding: "12px", borderRadius: "6px", overflowX: "auto", fontSize: "13px", color: "#d4d4d4", lineHeight: "1.5" }}>
      <code className={className} {...props}>
        {children}
      </code>
    </pre>
  ) : (
    <code className={className} style={{ backgroundColor: "rgba(0,0,0,0.1)", padding: "2px 4px", borderRadius: "3px" }} {...props}>
      {children}
    </code>
  );
};

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
              {(() => {
                if (isUser || !msg.text) return <ReactMarkdown components={{ code: CodeBlock }}>{msg.text}</ReactMarkdown>;
                const parts = msg.text.split(/\[ACTION:FIX:(\d+)\]/);
                if (parts.length === 1) return <ReactMarkdown components={{ code: CodeBlock }}>{msg.text}</ReactMarkdown>;
                let fixButtonIndex = 1;
                return parts.map((part, i) => {
                  if (i % 2 === 1) {
                    const vulnNum = parseInt(part, 10);
                    const displayNum = fixButtonIndex++;
                    return (
                      <button 
                        key={i} 
                        onClick={() => window.onChatAutoFix && window.onChatAutoFix(vulnNum)}
                        disabled={window.chatFixingFor === vulnNum || window.chatFixStatus?.[vulnNum] === 'success'}
                        className={window.chatFixingFor === vulnNum ? "btn-fixing" : ""}
                        style={{
                          background: window.chatFixStatus?.[vulnNum] === 'success' ? "var(--status-ready)" : "var(--accent)",
                          color: "#fff",
                          border: "none",
                          padding: "4px 10px",
                          borderRadius: "4px",
                          cursor: window.chatFixingFor === vulnNum || window.chatFixStatus?.[vulnNum] === 'success' ? "not-allowed" : "pointer",
                          fontSize: "12px",
                          margin: "0 4px",
                          display: "inline-block"
                        }}
                      >
                        {window.chatFixingFor === vulnNum ? "Fixing..." : window.chatFixStatus?.[vulnNum] === 'success' ? "Fixed" : `Fix`}
                      </button>
                    );
                  }
                  return <ReactMarkdown components={{ code: CodeBlock }} key={i}>{part}</ReactMarkdown>;
                });
              })()}
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

export default function ChatPanel({ project, onAsk, onViewReport, onDelete, onRefresh, onAddMessage }) {
  const [draft, setDraft] = useState("");
  const scrollRef = useRef(null);
  
  useEffect(() => {
    window.onRefreshProjects = onRefresh;
  }, [onRefresh]);
  
  const [fixingAll, setFixingAll] = useState(false);
  const [fixAllStatus, setFixAllStatus] = useState("");

  const handleFixAll = async () => {
    setFixingAll(true);
    setFixAllStatus("Fetching vulnerabilities...");
    try {
      const data = await getVulnerabilities(project.id);
      if (data && data.results) {
        for (let i = 0; i < data.results.length; i++) {
          setFixAllStatus(`Fixing ${i + 1} of ${data.results.length}...`);
          const res = await autoFixVulnerability(project.id, data.results[i]);
          if (res?.message && onAddMessage) {
            onAddMessage(project.id, "assistant", `**✨ Fix Applied (${i + 1}/${data.results.length}):** ${res.message}`);
          }
        }
        setFixAllStatus("✓ All fixed!");
        if (onRefresh) onRefresh();
      } else {
        setFixAllStatus("No vulnerabilities to fix.");
      }
    } catch (err) {
      setFixAllStatus("Error: " + err.message);
    }
    setFixingAll(false);
  };

  const [rescanning, setRescanning] = useState(false);
  const handleRescan = async () => {
    setRescanning(true);
    try {
      await rescanVulnerabilities(project.id);
      if (onRefresh) onRefresh();
    } catch (err) {
      alert("Error rescanning: " + err.message);
    }
    setRescanning(false);
  };

  const v = project.vulnerabilities;
  const hasVulns = v && (v.high > 0 || v.medium > 0 || v.low > 0);

  const [chatFixingFor, setChatFixingFor] = useState(null);
  const [chatFixStatus, setChatFixStatus] = useState({});

  useEffect(() => {
    window.chatFixingFor = chatFixingFor;
    window.chatFixStatus = chatFixStatus;
    window.onChatAutoFix = async (vulnNum) => {
      setChatFixingFor(vulnNum);
      setChatFixStatus((prev) => ({ ...prev, [vulnNum]: 'applying' }));
      try {
        const data = await getVulnerabilities(project.id);
        const finding = data?.results?.[vulnNum - 1];
        if (finding) {
          const res = await autoFixVulnerability(project.id, finding);
          setChatFixStatus((prev) => ({ ...prev, [vulnNum]: 'success' }));
          if (res?.message && onAddMessage) {
            onAddMessage(project.id, "assistant", `**✨ Fix Applied:** ${res.message}`);
          }
          if (window.onRefreshProjects) window.onRefreshProjects();
        } else {
          setChatFixStatus((prev) => ({ ...prev, [vulnNum]: 'Error: finding not found' }));
        }
      } catch (err) {
        setChatFixStatus((prev) => ({ ...prev, [vulnNum]: 'Error: ' + err.message }));
      }
      setChatFixingFor(null);
    };
  }, [project.id, chatFixingFor, chatFixStatus]);

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
              {hasVulns && (
                <span 
                  className="sec-badge" 
                  style={{ marginLeft: "6px", borderStyle: "dashed", cursor: (fixingAll || fixAllStatus === "✓ All fixed!") ? "not-allowed" : "pointer", background: fixAllStatus === "✓ All fixed!" ? "var(--status-ready)" : "var(--accent)", color: "#fff" }}
                  onClick={() => { if (!fixingAll && fixAllStatus !== "✓ All fixed!") handleFixAll(); }}
                >
                  {fixingAll ? fixAllStatus : fixAllStatus || "✨ Auto-Fix All"}
                </span>
              )}
              <span 
                className="sec-badge" 
                style={{ marginLeft: "6px", borderStyle: "dashed", cursor: rescanning ? "not-allowed" : "pointer" }}
                onClick={() => { if (!rescanning) handleRescan(); }}
              >
                {rescanning ? "Rescanning..." : "🔄 Recheck Report"}
              </span>
            </div>
          )}
        </div>
        <div className="chat-header-stats">
          <div className="stat">
            <span className="stat-num">{project.files}</span>
            <span className="stat-label">Files</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'row', gap: '8px', alignItems: 'center', marginLeft: '12px' }}>
            <button
              className="action-btn"
              title="Push Fixes to a new GitHub Branch"
              onClick={async () => {
                const branch = window.prompt("Enter a name for the new branch:", "security-fixes") || "security-fixes";
                const commitMessage = window.prompt("Enter a commit message:", "Apply automated security fixes") || "Apply automated security fixes";
                
                let token = "";
                if (window.confirm("Do you want to provide a GitHub Personal Access Token (PAT) to authenticate this push? (Required for private repos or public repos without write access)")) {
                  token = window.prompt("Enter your GitHub PAT (it will not be stored permanently):") || "";
                }
                
                try {
                  const res = await fetch(`http://127.0.0.1:5000/projects/${project.id}/push`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, branch, commit_message: commitMessage })
                  });
                  const data = await res.json();
                  if (!res.ok) {
                    window.alert("Failed to push: " + (data.error || "Unknown error"));
                  } else {
                    window.alert(data.message);
                  }
                } catch (e) {
                  window.alert("Network error: " + e.message);
                }
              }}
            >
              <Icon.Github />
            </button>
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
                title="Download Vulnerability Report (.pdf)"
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
