// lib/api.js — real fetch() calls against the Flask backend.
// Backend routes (see backend/app.py):
//   POST /ingest              { url }                    -> { id, name, status, stageIndex }
//   GET  /ingest/:id/status                               -> { id, status, stageIndex, files, chunks }
//   POST /chat                { projectId, question }     -> { answer, sources: [...] }
//   GET  /projects                                        -> [ project, ... ]
//   DELETE /projects/:id                                  -> { ok: true }

export const MODEL_NAME = "Llama 3.1 8B (Chat) / Qwen 3 Coder 30B (Fix)";

const BASE_URL = ""; // same-origin; Flask serves the built frontend + API

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...options,
  });
  if (!res.ok) {
    if (res.status === 401) {
      window.dispatchEvent(new Event("unauthorized"));
    }
    const body = await res.text().catch(() => "");
    throw new Error(`${options.method || "GET"} ${path} failed: ${res.status} ${body}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

export function listProjects() {
  return request("/projects");
}

export function startIngest(url, token = "") {
  return request("/ingest", {
    method: "POST",
    body: JSON.stringify({ url, token }),
  });
}

export function getIngestStatus(id) {
  return request(`/ingest/${id}/status`);
}

export function deleteProject(id) {
  return request(`/projects/${id}`, { method: "DELETE" });
}

export function getVulnerabilities(id) {
  return request(`/projects/${id}/vulnerabilities`);
}

export function generateVulnReport(id, finding) {
  return request(`/projects/${id}/vulnerabilities/report`, {
    method: "POST",
    body: JSON.stringify({ finding }),
  });
}

export function autoFixVulnerability(id, finding) {
  return request(`/projects/${id}/vulnerabilities/autofix`, {
    method: "POST",
    body: JSON.stringify({ finding }),
  });
}

export function evaluateFix(id, finding) {
  return request(`/projects/${id}/vulnerabilities/evaluate_fix`, {
    method: "POST",
    body: JSON.stringify({ finding }),
  });
}

export function applyEvaluatedFix(id, finding, fixed_content) {
  return request(`/projects/${id}/vulnerabilities/apply_evaluated_fix`, {
    method: "POST",
    body: JSON.stringify({ finding, fixed_content }),
  });
}

export function rescanVulnerabilities(id) {
  return request(`/projects/${id}/vulnerabilities/rescan`, {
    method: "POST",
  });
}

export function askQuestion(projectId, question) {
  return request("/chat", {
    method: "POST",
    body: JSON.stringify({ projectId, question }),
  });
}

/**
 * Polls /ingest/:id/status until status is "ready" or "error".
 * Calls onUpdate(status) after every poll so the UI (pipeline rail) can
 * update live. Returns a cancel() function to stop polling early.
 */
export function pollIngestStatus(id, onUpdate, { intervalMs = 1000 } = {}) {
  let cancelled = false;

  const tick = async () => {
    if (cancelled) return;
    try {
      const status = await getIngestStatus(id);
      onUpdate(status);
      if (status.status === "ready" || status.status === "error") return;
    } catch (err) {
      onUpdate({ status: "error", error: String(err) });
      return;
    }
    if (!cancelled) setTimeout(tick, intervalMs);
  };

  tick();
  return () => {
    cancelled = true;
  };
}

export function login(password) {
  return request("/api/login", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export function logout() {
  return request("/api/logout", {
    method: "POST",
  });
}

export function checkAuth() {
  return request("/api/check_auth");
}

/**
 * Fetch full file content for a finding's in-app code viewer.
 * Returns { content, start_line, end_line, language, file_path, stale }
 */
export function getFileContent(projectId, finding) {
  const filePath  = finding.path ?? finding.file_path ?? "";
  const startLine = finding.start?.line ?? finding.start_line ?? 1;
  const endLine   = finding.end?.line   ?? finding.end_line   ?? startLine;
  const params    = new URLSearchParams({ file_path: filePath, start_line: startLine, end_line: endLine });
  return request(`/projects/${projectId}/file_content?${params}`);
}

