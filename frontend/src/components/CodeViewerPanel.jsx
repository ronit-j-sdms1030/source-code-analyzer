import React, { useEffect, useRef, useState } from "react";
import { Light as SyntaxHighlighter } from "react-syntax-highlighter";

// ── Register only the languages we care about (keeps bundle small) ────────────
import js     from "react-syntax-highlighter/dist/esm/languages/hljs/javascript";
import ts     from "react-syntax-highlighter/dist/esm/languages/hljs/typescript";
import python from "react-syntax-highlighter/dist/esm/languages/hljs/python";
import java   from "react-syntax-highlighter/dist/esm/languages/hljs/java";
import go     from "react-syntax-highlighter/dist/esm/languages/hljs/go";
import ruby   from "react-syntax-highlighter/dist/esm/languages/hljs/ruby";
import rust   from "react-syntax-highlighter/dist/esm/languages/hljs/rust";
import css    from "react-syntax-highlighter/dist/esm/languages/hljs/css";
import xml    from "react-syntax-highlighter/dist/esm/languages/hljs/xml";
import bash   from "react-syntax-highlighter/dist/esm/languages/hljs/bash";
import yaml   from "react-syntax-highlighter/dist/esm/languages/hljs/yaml";
import json_  from "react-syntax-highlighter/dist/esm/languages/hljs/json";
import php    from "react-syntax-highlighter/dist/esm/languages/hljs/php";
import c      from "react-syntax-highlighter/dist/esm/languages/hljs/c";
import cpp    from "react-syntax-highlighter/dist/esm/languages/hljs/cpp";
import csharp from "react-syntax-highlighter/dist/esm/languages/hljs/csharp";

SyntaxHighlighter.registerLanguage("javascript", js);
SyntaxHighlighter.registerLanguage("typescript", ts);
SyntaxHighlighter.registerLanguage("python",     python);
SyntaxHighlighter.registerLanguage("java",       java);
SyntaxHighlighter.registerLanguage("go",         go);
SyntaxHighlighter.registerLanguage("ruby",       ruby);
SyntaxHighlighter.registerLanguage("rust",       rust);
SyntaxHighlighter.registerLanguage("css",        css);
SyntaxHighlighter.registerLanguage("xml",        xml);
SyntaxHighlighter.registerLanguage("bash",       bash);
SyntaxHighlighter.registerLanguage("yaml",       yaml);
SyntaxHighlighter.registerLanguage("json",       json_);
SyntaxHighlighter.registerLanguage("php",        php);
SyntaxHighlighter.registerLanguage("c",          c);
SyntaxHighlighter.registerLanguage("cpp",        cpp);
SyntaxHighlighter.registerLanguage("csharp",     csharp);

// ── Dark theme matching the app palette ────────────────────────────────────────
const THEME = {
  "hljs": {
    background: "transparent",
    color: "#c9d1d9",
  },
  "hljs-comment": { color: "#8b949e", fontStyle: "italic" },
  "hljs-keyword": { color: "#ff7b72" },
  "hljs-string":  { color: "#a5d6ff" },
  "hljs-number":  { color: "#79c0ff" },
  "hljs-literal": { color: "#79c0ff" },
  "hljs-built_in":{ color: "#ffa657" },
  "hljs-type":    { color: "#ffa657" },
  "hljs-title":   { color: "#d2a8ff" },
  "hljs-attr":    { color: "#7ee787" },
  "hljs-variable":{ color: "#ffa657" },
  "hljs-name":    { color: "#7ee787" },
  "hljs-tag":     { color: "#7ee787" },
  "hljs-meta":    { color: "#8b949e" },
  "hljs-params":  { color: "#c9d1d9" },
  "hljs-selector-tag": { color: "#7ee787" },
};

// Lines to render on each side of the vulnerable range for lazy windowing
const WINDOW_PADDING = 100;

/**
 * CodeViewerPanel — slide-in panel showing a full file with syntax highlighting
 * and a highlighted vulnerable line range.
 *
 * Props:
 *   fileData  { content, start_line, end_line, language, file_path, stale, error }
 *   onClose   () => void
 */
export default function CodeViewerPanel({ fileData, onClose, onApplyFix, isApplying }) {
  const { content, start_line, end_line, language, file_path, stale, finding = {} } = fileData;

  const [isEditing, setIsEditing] = useState(false);
  const [editedContent, setEditedContent] = useState(content || "");

  // Reset if file changes
  useEffect(() => {
    setEditedContent(content || "");
    setIsEditing(false);
  }, [content]);

  const lines     = content ? content.split("\n") : [];
  const totalLines = lines.length;

  // ── Virtualized window: render WINDOW_PADDING lines on each side of highlight
  const winStart = Math.max(0, (start_line - 1) - WINDOW_PADDING);
  const winEnd   = Math.min(totalLines, (end_line ?? start_line) + WINDOW_PADDING);

  const windowedContent = lines.slice(winStart, winEnd).join("\n");
  const lineNumberStart = winStart + 1;

  const highlightRef = useRef(null);
  const textareaRef = useRef(null);

  // Scroll to the highlighted range after mount
  useEffect(() => {
    if (!isEditing) {
      const el = highlightRef.current;
      if (el) {
        setTimeout(() => el.scrollIntoView({ behavior: "smooth", block: "center" }), 180);
      }
    } else {
      // Focus textarea and attempt to scroll roughly to the start_line
      const ta = textareaRef.current;
      if (ta) {
        ta.focus();
        // Rough estimate of scroll position
        const lineHeight = 21; // approx 21px per line
        ta.scrollTop = Math.max(0, (start_line - 5) * lineHeight);
      }
    }
  }, [fileData, isEditing, start_line]);

  const startIdx = start_line - 1; // 0-based
  const endIdx   = (end_line ?? start_line) - 1;

  const lineProps = (lineNumber) => {
    const absoluteLine = lineNumber + winStart;
    const isVuln = absoluteLine >= startIdx && absoluteLine <= endIdx;
    return {
      style: isVuln
        ? {
            display: "block",
            background: "rgba(240, 85, 63, 0.18)",
            borderLeft: "3px solid var(--status-error)",
            paddingLeft: "6px",
            marginLeft: "-9px",
          }
        : { display: "block" },
      ref: isVuln && absoluteLine === startIdx ? highlightRef : undefined,
    };
  };

  const handleApply = () => {
    if (onApplyFix) {
      onApplyFix(editedContent);
    }
  };

  return (
    <div className="code-viewer-overlay" onClick={onClose}>
      <div className="code-viewer-panel" onClick={(e) => e.stopPropagation()}>
        {/* ── Header ── */}
        <div className="code-viewer-header">
          <div className="code-viewer-title">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, color: "var(--text-tertiary)" }}>
              <polyline points="16 18 22 12 16 6" />
              <polyline points="8 6 2 12 8 18" />
            </svg>
            <code style={{ fontSize: "13px", color: "var(--text-primary)", fontFamily: "'IBM Plex Mono', monospace" }}>
              {file_path}
            </code>
            {!isEditing && (
              <span style={{ fontSize: "11px", color: "var(--text-tertiary)", background: "var(--bg-void)", border: "1px solid var(--border-hair)", padding: "1px 6px", borderRadius: "4px", fontFamily: "monospace" }}>
                L{start_line}{end_line && end_line !== start_line ? `–${end_line}` : ""}
              </span>
            )}
            {language && (
              <span style={{ fontSize: "11px", color: "var(--text-tertiary)", background: "var(--bg-void)", border: "1px solid var(--border-hair)", padding: "1px 6px", borderRadius: "4px" }}>
                {language}
              </span>
            )}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            {isEditing ? (
              <>
                <button
                  onClick={() => setIsEditing(false)}
                  disabled={isApplying}
                  style={{
                    background: "transparent",
                    color: "var(--text-secondary)",
                    border: "1px solid var(--border-hair)",
                    padding: "5px 12px",
                    borderRadius: "5px",
                    cursor: "pointer",
                    fontSize: "12px",
                  }}
                >
                  Cancel
                </button>
                <button
                  onClick={handleApply}
                  disabled={isApplying || editedContent === content}
                  style={{
                    background: "var(--status-ready)",
                    color: "#000",
                    border: "none",
                    padding: "6px 16px",
                    borderRadius: "5px",
                    cursor: isApplying || editedContent === content ? "not-allowed" : "pointer",
                    fontSize: "12px",
                    fontWeight: "bold",
                    opacity: isApplying || editedContent === content ? 0.6 : 1,
                    display: "flex",
                    alignItems: "center",
                    gap: "6px"
                  }}
                >
                  {isApplying ? "Applying..." : "✅ Save & Apply"}
                </button>
              </>
            ) : (
              <button
                onClick={() => setIsEditing(true)}
                style={{
                  background: "var(--bg-panel-raised)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border-hair)",
                  padding: "5px 12px",
                  borderRadius: "5px",
                  cursor: "pointer",
                  fontSize: "12px",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px"
                }}
              >
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                Edit File
              </button>
            )}
            <button className="modal-close" onClick={onClose} aria-label="Close file viewer" style={{ marginLeft: "8px" }}>✕</button>
          </div>
        </div>

        {/* ── Stale content warning ── */}
        {stale && !isEditing && (
          <div className="code-viewer-stale-banner">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <span>
              <strong>File has changed since this finding was recorded.</strong> The highlighted range may no longer reflect the current file. Re-scan to refresh findings.
            </span>
          </div>
        )}

        {/* ── Main Content Split (Sidebar + Editor) ── */}
        <div style={{ display: "flex", flexGrow: 1, overflow: "hidden" }}>
          
          {/* ── Left Sidebar: Issue & Fix ── */}
          <div style={{ 
            width: "280px", 
            borderRight: "1px solid var(--border-hair)", 
            padding: "20px", 
            overflowY: "auto", 
            background: "rgba(0,0,0,0.15)",
            display: "flex",
            flexDirection: "column",
            gap: "20px",
            flexShrink: 0
          }}>
            <div>
              <h4 style={{ margin: "0 0 10px 0", color: "var(--text-primary)", fontSize: "12px", textTransform: "uppercase", letterSpacing: "0.06em", opacity: 0.8 }}>
                Issue Description
              </h4>
              <p style={{ margin: 0, fontSize: "13px", color: "var(--text-secondary)", lineHeight: "1.5" }}>
                {finding.extra?.message || "No description provided."}
              </p>
            </div>
            
            {finding.extra?.fix && finding.extra.fix.toLowerCase() !== "false" && (
              <div>
                <h4 style={{ margin: "0 0 10px 0", color: "var(--text-primary)", fontSize: "12px", textTransform: "uppercase", letterSpacing: "0.06em", opacity: 0.8 }}>
                  Suggested Fix
                </h4>
                <pre style={{ 
                  margin: 0, 
                  background: "rgba(0,0,0,0.3)", 
                  padding: "12px", 
                  borderRadius: "6px", 
                  overflowX: "auto", 
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  border: "1px solid var(--border-hair)",
                  color: "#4ade80", /* green for fix */
                  fontFamily: "'IBM Plex Mono', monospace",
                  fontSize: "12.5px",
                  lineHeight: "1.4"
                }}>
                  {finding.extra.fix}
                </pre>
              </div>
            )}
          </div>

          {/* ── Right Content: Editor ── */}
          <div style={{ flexGrow: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
            {/* ── Vuln range legend ── */}
            {!isEditing && (
              <div className="code-viewer-legend">
                <span className="code-viewer-legend-dot" />
                <span>Vulnerable range</span>
                {totalLines > WINDOW_PADDING * 2 && (
                  <span style={{ marginLeft: "auto", fontSize: "11px", color: "var(--text-tertiary)" }}>
                    Showing lines {winStart + 1}–{winEnd} of {totalLines.toLocaleString()}
                  </span>
                )}
              </div>
            )}

            {/* ── Code body ── */}
            <div className="code-viewer-body" style={{ display: "flex", flexDirection: "column", height: "100%" }}>
          {isEditing ? (
            <textarea
              ref={textareaRef}
              value={editedContent}
              onChange={(e) => setEditedContent(e.target.value)}
              spellCheck="false"
              style={{
                flexGrow: 1,
                width: "100%",
                height: "100%",
                background: "transparent",
                color: "#c9d1d9",
                border: "none",
                padding: "16px",
                fontFamily: "'IBM Plex Mono', 'Cascadia Code', monospace",
                fontSize: "13px",
                lineHeight: "1.6",
                resize: "none",
                outline: "none",
                whiteSpace: "pre",
                overflowWrap: "normal",
                overflowX: "auto"
              }}
            />
          ) : (
            <SyntaxHighlighter
              language={language || "plaintext"}
              style={THEME}
              showLineNumbers
              startingLineNumber={lineNumberStart}
              lineProps={lineProps}
              wrapLines
              lineNumberStyle={{
                minWidth: "3em",
                paddingRight: "1em",
                color: "var(--text-tertiary)",
                userSelect: "none",
                fontSize: "12px",
              }}
              customStyle={{
                margin: 0,
                padding: "16px",
                fontSize: "13px",
                lineHeight: "1.6",
                fontFamily: "'IBM Plex Mono', 'Cascadia Code', monospace",
                background: "transparent",
                overflowX: "auto",
              }}
              codeTagProps={{ style: { fontFamily: "inherit" } }}
            >
              {windowedContent}
            </SyntaxHighlighter>
          )}
        </div>
        </div>
        </div>
      </div>
    </div>
  );
}
