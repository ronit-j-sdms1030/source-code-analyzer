import React, { useState, useEffect, useCallback, useRef } from "react";
import Icon from "./components/icons";
import PipelineRail, { STAGES } from "./components/PipelineRail";
import NewProjectPanel from "./components/NewProjectPanel";
import ProjectCard from "./components/ProjectCard";
import ChatPanel from "./components/ChatPanel";
import VulnerabilityModal from "./components/VulnerabilityModal";
import { listProjects, startIngest, deleteProject as apiDeleteProject, askQuestion as apiAskQuestion, getChatHistory, pollIngestStatus, login, logout, checkAuth } from "./lib/api";
import starkLogo from "/stark.svg";

/* ---------------------------------- login ---------------------------------- */

function Login({ onLogin }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      await login(password);
      onLogin();
    } catch (err) {
      setError("Invalid password");
    }
    setLoading(false);
  };

  return (
    <div style={{ display: "flex", height: "100vh", alignItems: "center", justifyContent: "center", background: "var(--bg-void)" }}>
      <form onSubmit={handleSubmit} style={{ width: "100%", maxWidth: "360px", padding: "40px", background: "var(--bg-panel)", borderRadius: "12px", border: "1px solid var(--border-hair)", boxShadow: "0 10px 30px rgba(0,0,0,0.5)" }}>
        <div style={{ textAlign: "center", marginBottom: "32px" }}>
          <img src={starkLogo} alt="Stark Digital" style={{ width: "48px", height: "48px", marginBottom: "16px" }} />
          <h2 style={{ margin: 0, fontSize: "20px", color: "var(--text-primary)" }}>Sign In</h2>
        </div>
        {error && <div style={{ color: "var(--status-error)", marginBottom: "16px", fontSize: "14px", textAlign: "center" }}>{error}</div>}
        <div style={{ marginBottom: "24px" }}>
          <input
            type="password"
            placeholder="Admin Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ width: "100%", padding: "12px 16px", background: "var(--bg-void)", border: "1px solid var(--border-hair)", borderRadius: "6px", color: "var(--text-primary)", fontSize: "15px" }}
            autoFocus
          />
        </div>
        <button type="submit" className="btn-accent" style={{ width: "100%", padding: "12px", justifyContent: "center" }} disabled={loading || !password}>
          {loading ? "Authenticating..." : "Continue"}
        </button>
      </form>
    </div>
  );
}

/* ------------------------------- empty state ------------------------------- */

function EmptyState({ onOpenNew }) {
  return (
    <div className="empty-state">
      <div className="empty-eyebrow">SOURCE CODE ANALYZER</div>
      <h1 className="empty-title">
        Ask a codebase questions
        <br /> the way you'd ask a colleague.
      </h1>
      <p className="empty-sub">
        Clone a repository, and only the relevant chunks — not the whole tree — get
        pulled into context. Every answer cites the file it came from. Runs entirely
        on local models: nothing leaves this machine.
      </p>
      <button className="btn-accent empty-cta" onClick={onOpenNew}>
        <Icon.Plus /> Add your first project
      </button>
      <div className="empty-rail-wrap">
        <div className="empty-rail-label">HOW A REPO GETS INDEXED</div>
        <PipelineRail stageIndex={-1} />
      </div>
    </div>
  );
}

/* ---------------------------------- app ---------------------------------- */

export default function SourceCodeAnalyzer() {
  const [projects, setProjects] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [reportProject, setReportProject] = useState(null);
  const [newOpen, setNewOpen] = useState(false);
  const [theme, setTheme] = useState("dark");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(null);
  const cancelPollers = useRef({});

  // Listen for 401 unauthorized events from api.js
  useEffect(() => {
    const handleAuthError = () => setIsAuthenticated(false);
    window.addEventListener("unauthorized", handleAuthError);
    return () => window.removeEventListener("unauthorized", handleAuthError);
  }, []);

  // Bypass auth and load projects on mount
  useEffect(() => {
    setIsAuthenticated(true);
    loadProjects();
  }, []);

  const _chatSessionKey = (projectId) => `chat_session_${projectId}`;

  // Chat history lives server-side keyed by sessionId (see backend/src/memory.py),
  // but the browser only remembers that sessionId for as long as this tab's React
  // state is alive — a refresh wipes it. Persist it to localStorage so a reload can
  // restore both the session (for LLM context continuity) and the visible messages.
  const restoreChatSession = async (projectId) => {
    const sessionId = localStorage.getItem(_chatSessionKey(projectId));
    if (!sessionId) return;
    try {
      const { messages } = await getChatHistory(projectId, sessionId);
      if (messages && messages.length) {
        updateProject(projectId, { sessionId, messages });
      } else {
        updateProject(projectId, { sessionId });
      }
    } catch (err) {
      console.error(`Failed to restore chat session for ${projectId}`, err);
    }
  };

  const loadProjects = () => {
    listProjects()
      .then((list) => {
        setProjects(list);
        if (list[0]) setSelectedId(list[0].id);
        list.filter((p) => p.status === "indexing").forEach((p) => watchIngest(p.id));
        list.forEach((p) => restoreChatSession(p.id));
      })
      .catch((err) => console.error("Failed to load projects", err));
  };

  useEffect(() => {
    return () => Object.values(cancelPollers.current).forEach((cancel) => cancel && cancel());
  }, []);

  const selected = projects.find((p) => p.id === selectedId) || null;

  const updateProject = useCallback((id, patch) => {
    setProjects((prev) => prev.map((p) => (p.id === id ? { ...p, ...(typeof patch === "function" ? patch(p) : patch) } : p)));
  }, []);

  const watchIngest = (id) => {
    const cancel = pollIngestStatus(id, (status) => {
      updateProject(id, status);
    });
    cancelPollers.current[id] = cancel;
  };

  const createProject = async (url, token = "") => {
    setNewOpen(false);
    try {
      const project = await startIngest(url, token);
      setProjects((prev) => [project, ...prev]);
      setSelectedId(project.id);
      watchIngest(project.id);
    } catch (err) {
      console.error("Failed to start ingest", err);
    }
  };

  const deleteProjectHandler = async (id) => {
    try {
      await apiDeleteProject(id);
    } catch (err) {
      console.error("Failed to delete project", err);
    }
    if (cancelPollers.current[id]) {
      cancelPollers.current[id]();
      delete cancelPollers.current[id];
    }
    localStorage.removeItem(_chatSessionKey(id));
    setProjects((prev) => {
      const next = prev.filter((p) => p.id !== id);
      setSelectedId((curr) => (curr === id ? (next[0] ? next[0].id : null) : curr));
      return next;
    });
  };

  const refreshProjectData = async () => {
    try {
      const list = await listProjects();
      setProjects((prev) => 
        prev.map(p => {
          const fresh = list.find(l => l.id === p.id);
          return fresh ? { ...fresh, messages: p.messages } : p;
        })
      );
      // Also keep reportProject in sync so the modal's project.vulnerabilities
      // prop is always current (enables stale-report reconciliation on re-open).
      setReportProject((prev) => {
        if (!prev) return prev;
        const fresh = list.find(l => l.id === prev.id);
        return fresh ? { ...fresh, messages: prev.messages } : prev;
      });
    } catch(err) {
      console.error("Failed to refresh project data", err);
    }
  };

  const askQuestion = async (projectId, question) => {
    // 1. Get current session ID from project state
    const project = projects.find(p => p.id === projectId);
    const sessionId = project?.sessionId;

    updateProject(projectId, (p) => ({
      messages: [...p.messages, { role: "user", text: question }, { role: "assistant", pending: true }],
    }));
    try {
      const { answer, sources, sessionId: returnedSessionId, evaluate_fix_payloads } = await apiAskQuestion(projectId, question, sessionId);
      if (returnedSessionId) {
        localStorage.setItem(_chatSessionKey(projectId), returnedSessionId);
      }
      updateProject(projectId, (p) => {
        const msgs = [...p.messages];
        msgs[msgs.length - 1] = { role: "assistant", text: answer, sources: sources || [], evaluate_fix_payloads };
        return { messages: msgs, sessionId: returnedSessionId || p.sessionId };
      });
    } catch (err) {
      updateProject(projectId, (p) => {
        const msgs = [...p.messages];
        msgs[msgs.length - 1] = { role: "assistant", text: `Error: ${err.message}`, sources: [] };
        return { messages: msgs };
      });
    }
  };

  const addMessage = (projectId, role, text) => {
    updateProject(projectId, (p) => ({
      messages: [...p.messages, { role, text, sources: [] }],
    }));
  };



  return (
    <div className="app" data-theme={theme}>
      <header className="topbar">
        <div className="brand">
          <img src={starkLogo} alt="Stark Digital" className="brand-logo" />
          <div className="brand-text">
            <span className="brand-name">Stark Digital</span>
            <span className="brand-product">Source Code Analyzer</span>
          </div>
        </div>
        <div className="topbar-stats">
          <span>{projects.length} repos</span>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginLeft: 'auto' }}>
          <button
            className="theme-toggle"
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
            aria-label="Toggle theme"
          >
            <span className="theme-toggle-label">{theme === "dark" ? "Dark" : "Light"}</span>
            <span className="theme-toggle-track">
              <span className="theme-toggle-thumb" />
            </span>
          </button>
        </div>
      </header>

      <div className="body">
        <aside className={`sidebar ${sidebarOpen ? "open" : "collapsed"}`}>
          <div className="sidebar-header">
            <button 
              className="sidebar-toggle-btn" 
              onClick={() => setSidebarOpen(!sidebarOpen)}
              title={sidebarOpen ? "Collapse Sidebar" : "Expand Sidebar"}
            >
              <Icon.Chevron className={sidebarOpen ? "left" : "right"} />
            </button>
          </div>

          <div className="sidebar-content">
            <button className="new-project-toggle" onClick={() => setNewOpen((v) => !v)}>
              <Icon.Plus />
              New project
              <Icon.Chevron className={`chev ${newOpen ? "up" : ""}`} />
            </button>

            <NewProjectPanel open={newOpen} onClose={() => setNewOpen(false)} onCreate={createProject} />

            <div className="project-list">
              <div className="project-list-label">Repositories</div>
              {projects.map((p) => (
                <ProjectCard 
                  key={p.id} 
                  project={p} 
                  active={p.id === selectedId} 
                  onSelect={setSelectedId} 
                  onDelete={deleteProjectHandler} 
                  onViewReport={setReportProject}
                />
              ))}
            </div>
          </div>
        </aside>

        <main className="main">
          {!selected && <EmptyState onOpenNew={() => setNewOpen(true)} />}
          {selected && selected.status === "indexing" && (
            <div className="indexing-view">
              <div className="empty-eyebrow">INDEXING · {selected.name}</div>
              <h2 className="indexing-title">Turning a repository into searchable vectors</h2>
              <PipelineRail stageIndex={selected.stageIndex} embedProgress={selected.embedProgress} />
              <p className="indexing-note">
                Shallow clone → collect .py files → chunk by function/class → embed → persist to ChromaDB.
                This repo will stay indexed on disk once complete.
              </p>
            </div>
          )}
          {selected && selected.status === "ready" && <ChatPanel project={selected} onAsk={askQuestion} onViewReport={() => setReportProject(selected)} onDelete={deleteProjectHandler} onRefresh={refreshProjectData} onAddMessage={addMessage} />}
          {selected && selected.status === "error" && (
            <div className="indexing-view" style={{ textAlign: "center" }}>
              <div className="empty-eyebrow" style={{ color: "var(--status-error)" }}>FAILED · {selected.name}</div>
              <h2 className="indexing-title">Indexing failed</h2>
              <p className="indexing-note" style={{ color: "var(--status-error)" }}>
                {selected.error || "An unknown error occurred during indexing."}
              </p>
              <button
                className="btn-accent"
                style={{ marginTop: "24px", background: "var(--status-error)" }}
                onClick={() => {
                  if (window.confirm(`Are you sure you want to delete ${selected.name}?`)) {
                    deleteProjectHandler(selected.id);
                  }
                }}
              >
                Delete Repository
              </button>
            </div>
          )}

        </main>
      </div>

      {reportProject && (
        <VulnerabilityModal 
          project={reportProject} 
          onClose={() => setReportProject(null)} 
          onRefresh={refreshProjectData}
          onAddMessage={addMessage}
        />
      )}
    </div>
  );
}
