// lib/api.js — real fetch() calls against the Flask backend.
// Backend routes (see backend/app.py):
//   POST /ingest              { url }                    -> { id, name, status, stageIndex }
//   GET  /ingest/:id/status                               -> { id, status, stageIndex, files, chunks }
//   POST /chat                { projectId, question }     -> { answer, sources: [...] }
//   GET  /projects                                        -> [ project, ... ]
//   DELETE /projects/:id                                  -> { ok: true }

export const MODEL_NAME = "qwen-2.5-coder-7b-instruct (OpenRouter)";

const BASE_URL = ""; // same-origin; Flask serves the built frontend + API

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
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
