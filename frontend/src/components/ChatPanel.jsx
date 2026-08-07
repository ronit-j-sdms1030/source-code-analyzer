import React, { useState, useRef, useEffect } from "react";
import ReactMarkdown from "react-markdown";
import Icon from "./icons";
import { getVulnerabilities, autoFixVulnerability, rescanVulnerabilities, applyEvaluatedFix, getQualityScanStatus, startQualityScan, pollQualityScanStatus, cancelQualityScan } from "../lib/api";
import { MODEL_NAME } from "../lib/api";

const CodeBlock = ({ node, inline, className, children, ...props }) => {
  const match = /language-(\w+)/.exec(className || "");
  const lang = match ? match[1] : "";
  const codeText = String(children).replace(/\n$/, "");
  const isMultiLine = codeText.includes("\n");

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
  
  // Only render as a full block if it has multiple lines or an explicit language tag.
  // Otherwise, treat it as an inline snippet even if the markdown parser flagged it as !inline
  // (which happens when the LLM places backticks on their own lines).
  if (!inline && (lang || isMultiLine)) {
    return (
      <pre className={className} style={{ backgroundColor: "#1e1e1e", padding: "12px", borderRadius: "6px", overflowX: "auto", fontSize: "13px", color: "#d4d4d4", lineHeight: "1.5" }}>
        <code className={className} {...props}>
          {children}
        </code>
      </pre>
    );
  }

  // Inline snippet rendering with a black/dark outline
  return (
    <code className={className} style={{ backgroundColor: "var(--bg-panel-raised)", border: "1px solid var(--text-primary)", color: "var(--text-primary)", padding: "2px 6px", borderRadius: "4px", fontSize: "0.9em" }} {...props}>
      {children}
    </code>
  );
};

export function ChatMessage({ msg, onApplyFix }) {
  const isUser = msg.role === "user";
  const [applyingFixFor, setApplyingFixFor] = useState(null);

  const renderPayloads = () => {
    if (!msg.evaluate_fix_payloads) return null;
    return msg.evaluate_fix_payloads.map((payload, idx) => (
      <div key={idx} style={{ marginTop: "16px", padding: "12px", backgroundColor: "var(--bg-panel-raised)", borderRadius: "6px", border: "1px solid var(--border-color)" }}>
        <ReactMarkdown components={{ code: CodeBlock }}>{payload.risk_assessment}</ReactMarkdown>
        <button
          className="action-btn"
          style={{ marginTop: "12px", padding: "8px 16px", backgroundColor: "#3b82f6", color: "white", borderRadius: "4px", width: "100%", textAlign: "center", cursor: applyingFixFor === idx ? "not-allowed" : "pointer" }}
          disabled={applyingFixFor === idx}
          onClick={async () => {
            setApplyingFixFor(idx);
            await onApplyFix(payload.finding, payload.fixed_content);
            setApplyingFixFor(null);
          }}
        >
          {applyingFixFor === idx ? "Applying Fix..." : "Apply Fix"}
        </button>
      </div>
    ));
  };

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
                return <ReactMarkdown components={{ code: CodeBlock }}>{msg.text}</ReactMarkdown>;
              })()}
              {renderPayloads()}
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
  
  const [qualityMetrics, setQualityMetrics] = useState(null);
  const cancelPoll = useRef(null);

  const fetchQuality = async () => {
    try {
      const res = await getQualityScanStatus(project.id);
      setQualityMetrics(res);
      if (res.status === "running") {
        pollQuality(project.id);
      }
    } catch (err) {
      if (String(err).includes("404")) {
        setQualityMetrics({ status: "not_started" });
      }
    }
  };

  const pollQuality = (id) => {
    if (cancelPoll.current) cancelPoll.current();
    cancelPoll.current = pollQualityScanStatus(id, (metrics) => {
      setQualityMetrics(metrics);
    });
  };

  useEffect(() => {
    fetchQuality();
    return () => {
      if (cancelPoll.current) cancelPoll.current();
    };
  }, [project.id]);

  const handleRunQualityScan = async () => {
    try {
      setQualityMetrics({ status: "running", stage: "Queued" });
      await startQualityScan(project.id);
      pollQuality(project.id);
    } catch (err) {
      alert("Error starting quality scan: " + err.message);
      setQualityMetrics({ status: "error", error: err.message });
    }
  };

  const handleCancelQualityScan = async () => {
    try {
      await cancelQualityScan(project.id);
      setQualityMetrics({ status: "cancelled", error: "Scan was stopped by the user." });
    } catch (err) {
      alert("Error stopping quality scan: " + err.message);
    }
  };

  useEffect(() => {
    window.onRefreshProjects = onRefresh;
  }, [onRefresh]);
  

  const handleApplyFix = async (finding, fixed_content) => {
    try {
      const res = await applyEvaluatedFix(project.id, finding, fixed_content);
      if (res?.message && onAddMessage) {
        onAddMessage(project.id, "assistant", `**✨ Fix Applied:** ${res.message}`);
      }
      await rescanVulnerabilities(project.id);
      if (onRefresh) onRefresh();
    } catch (err) {
      alert("Error applying fix: " + err.message);
    }
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

              <span 
                className="sec-badge" 
                style={{ marginLeft: "6px", borderStyle: "dashed", cursor: rescanning ? "not-allowed" : "pointer" }}
                onClick={() => { if (!rescanning) handleRescan(); }}
              >
                {rescanning ? "Rescanning..." : "🔄 Recheck Report"}
              </span>
            </div>
          )}
          
          <div className="quality-panel" style={{ marginTop: "16px", padding: "12px", background: "var(--bg-panel-raised)", borderRadius: "8px", border: "1px solid var(--border-hair)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                Code Quality (SonarQube)
              </div>
              <div style={{ display: "flex", gap: "8px" }}>
                {qualityMetrics?.status === "running" && (
                  <button
                    className="action-btn"
                    style={{ fontSize: "11px", padding: "4px 8px", backgroundColor: "var(--bg-panel)", color: "var(--text-error)" }}
                    onClick={handleCancelQualityScan}
                  >
                    Stop Scan
                  </button>
                )}
                <button
                  className="action-btn"
                  style={{ fontSize: "11px", padding: "4px 8px" }}
                  disabled={qualityMetrics?.status === "running"}
                  onClick={handleRunQualityScan}
                >
                  {qualityMetrics?.status === "running" ? "Scanning..." : "Run Quality Scan"}
                </button>
              </div>
            </div>
            
            <div style={{ marginTop: "12px", display: "flex", gap: "12px", flexWrap: "wrap" }}>
              {qualityMetrics?.status === "complete" ? (
                <>
                  <span className="sec-badge" style={{ background: "var(--bg-void)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}>
                    ✨ Maintainability: {qualityMetrics.sqale_rating ? ["A", "B", "C", "D", "E"][Math.floor(parseFloat(qualityMetrics.sqale_rating)) - 1] || qualityMetrics.sqale_rating : "N/A"}
                  </span>
                  <span className="sec-badge" style={{ background: "var(--bg-void)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}>
                    🐛 Code Smells: {qualityMetrics.code_smells || 0}
                  </span>
                  <span className="sec-badge" style={{ background: "var(--bg-void)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}>
                    👯 Duplication: {qualityMetrics.duplicated_lines_density || 0}%
                  </span>
                  <span className="sec-badge" style={{ background: "var(--bg-void)", border: "1px solid var(--border-color)", color: "var(--text-primary)" }}>
                    🧠 Complexity: {qualityMetrics.complexity || 0}
                  </span>
                </>
              ) : qualityMetrics?.status === "running" ? (
                <div style={{ color: "var(--text-secondary)", fontSize: "13px" }}>
                  <span className="thinking"><span className="dot" /><span className="dot" /><span className="dot" /></span>
                  {qualityMetrics.stage || "Analyzing..."}
                </div>
              ) : qualityMetrics?.status === "error" ? (
                <div style={{ color: "var(--status-error)", fontSize: "13px" }}>
                  ⚠ {qualityMetrics.error}
                </div>
              ) : (
                <div style={{ color: "var(--text-secondary)", fontSize: "13px" }}>
                  Not scanned yet.
                </div>
              )}
            </div>
          </div>
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
                const rawBranch = window.prompt("Enter a name for the new branch:", "security-fixes") ?? "security-fixes";
                // Sanitize: strip whitespace and replace characters git rejects in ref names
                // (spaces, ~, ^, :, ?, *, [, \, .., @{, trailing .lock, etc.)
                const branch = rawBranch
                  .trim()
                  .replace(/[\s~^:?*\[\\]+/g, "-")   // replace invalid chars with -
                  .replace(/\.{2,}/g, "-")            // replace .. with -
                  .replace(/-{2,}/g, "-")             // collapse multiple hyphens
                  .replace(/^[-.]|[-.]$/g, "")        // strip leading/trailing - or .
                  || "security-fixes";
                const commitMessage = window.prompt("Enter a commit message:", "Apply automated security fixes") || "Apply automated security fixes";
                
                let token = "";
                if (window.confirm("Do you want to provide a GitHub Personal Access Token (PAT) to authenticate this push? (Required for private repos or public repos without write access)")) {
                  token = window.prompt("Enter your GitHub PAT (it will not be stored permanently):") || "";
                }
                
                try {
                  const res = await fetch(`/projects/${project.id}/push`, {
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
          <ChatMessage msg={m} key={i} onApplyFix={handleApplyFix} />
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
