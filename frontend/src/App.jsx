import React, { useState, useEffect, useCallback, useRef } from "react";
import Icon from "./components/icons";
import PipelineRail, { STAGES } from "./components/PipelineRail";
import NewProjectPanel from "./components/NewProjectPanel";
import ProjectCard from "./components/ProjectCard";
import ChatPanel from "./components/ChatPanel";
import VulnerabilityModal from "./components/VulnerabilityModal";
import { listProjects, startIngest, deleteProject as apiDeleteProject, askQuestion as apiAskQuestion, pollIngestStatus } from "./lib/api";
import starkLogo from "/stark.svg";

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
  const cancelPollers = useRef({});

  // Load existing projects from the backend on mount.
  useEffect(() => {
    listProjects()
      .then((list) => {
        setProjects(list);
        if (list[0]) setSelectedId(list[0].id);
        // resume polling for anything still indexing
        list.filter((p) => p.status === "indexing").forEach((p) => watchIngest(p.id));
      })
      .catch((err) => console.error("Failed to load projects", err));
    return () => Object.values(cancelPollers.current).forEach((cancel) => cancel && cancel());
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    setProjects((prev) => {
      const next = prev.filter((p) => p.id !== id);
      setSelectedId((curr) => (curr === id ? (next[0] ? next[0].id : null) : curr));
      return next;
    });
  };

  const askQuestion = async (projectId, question) => {
    updateProject(projectId, (p) => ({
      messages: [...p.messages, { role: "user", text: question }, { role: "assistant", pending: true }],
    }));
    try {
      const { answer, sources } = await apiAskQuestion(projectId, question);
      updateProject(projectId, (p) => {
        const msgs = [...p.messages];
        msgs[msgs.length - 1] = { role: "assistant", text: answer, sources: sources || [] };
        return { messages: msgs };
      });
    } catch (err) {
      updateProject(projectId, (p) => {
        const msgs = [...p.messages];
        msgs[msgs.length - 1] = { role: "assistant", text: `Error: ${err.message}`, sources: [] };
        return { messages: msgs };
      });
    }
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
              <PipelineRail stageIndex={selected.stageIndex} />
              <p className="indexing-note">
                Shallow clone → collect .py files → chunk by function/class → embed → persist to ChromaDB.
                This repo will stay indexed on disk once complete.
              </p>
            </div>
          )}
          {selected && selected.status === "ready" && <ChatPanel project={selected} onAsk={askQuestion} onViewReport={setReportProject} onDelete={deleteProjectHandler} />}
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
          projectId={reportProject.id} 
          projectName={reportProject.name} 
          onClose={() => setReportProject(null)} 
        />
      )}
    </div>
  );
}
