"""Flask app entry point.

Routes:
  GET    /projects              -> list all indexed/indexing projects
  POST   /ingest                -> { url } kick off cloning + indexing for a repo
  GET    /ingest/<id>/status    -> poll pipeline stage for a project
  POST   /chat                  -> { projectId, question } -> { answer, sources }
  DELETE /projects/<id>         -> remove a project and its ChromaDB collection

In production this also serves the built React frontend from ./static
(see frontend/vite.config.js, which builds directly into backend/static).
"""

from flask import Flask, jsonify, request, send_from_directory, send_file, session
from functools import wraps

from src import config
from src.ingestion import start_ingest, get_status, delete_project
from src.chain import answer_question
from src.vectorstore import list_projects

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = config.SECRET_KEY

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

@app.post("/api/login")
def login():
    body = request.get_json(force=True)
    password = (body or {}).get("password", "")
    if password == config.ADMIN_PASSWORD:
        session['authenticated'] = True
        return jsonify({"ok": True})
    return jsonify({"error": "Invalid password"}), 401

@app.post("/api/logout")
def logout():
    session.pop('authenticated', None)
    return jsonify({"ok": True})

@app.get("/api/check_auth")
def check_auth():
    return jsonify({"authenticated": session.get('authenticated', False)})



@app.get("/projects")
@auth_required
def projects():
    from src.ingestion import _projects, _lock
    db_list = list_projects()
    # Merge in-memory _projects (always up-to-date) over ChromaDB data
    # so that vulnerability counts updated by apply_fix are reflected
    # immediately without waiting for ChromaDB to be written.
    with _lock:
        mem = dict(_projects)  # snapshot
    if mem:
        merged = []
        for p in db_list:
            pid = p.get("id")
            if pid and pid in mem:
                # In-memory copy wins for mutable fields like vulnerabilities
                merged.append({**p, **{k: v for k, v in mem[pid].items() if k != "messages"}})
            else:
                merged.append(p)
        return jsonify(merged)
    return jsonify(db_list)


@app.post("/ingest")
@auth_required
def ingest():
    body = request.get_json(force=True)
    url = (body or {}).get("url", "").strip()
    token = (body or {}).get("token", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    project = start_ingest(url, token=token)
    return jsonify(project), 201


@app.get("/ingest/<project_id>/status")
@auth_required
def ingest_status(project_id):
    status = get_status(project_id)
    if status is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(status)


@app.post("/projects/<project_id>/quality-scan")
@auth_required
def trigger_quality_scan(project_id):
    from src.sonarqube import start_quality_scan
    start_quality_scan(project_id)
    return jsonify({"status": "queued"})


@app.post("/projects/<project_id>/quality-scan/cancel")
@auth_required
def cancel_quality_scan_endpoint(project_id):
    from src.sonarqube import cancel_quality_scan
    cancel_quality_scan(project_id)
    return jsonify({"status": "cancelled"})


@app.get("/projects/<project_id>/quality-scan/status")
@auth_required
def get_quality_scan_status(project_id):
    from src.memory import get_quality_metrics
    metrics = get_quality_metrics(project_id)
    if not metrics:
        return jsonify({"status": "not_started"}), 404
    return jsonify(metrics)


@app.post("/chat")
@auth_required
def chat():
    import uuid
    body = request.get_json(force=True)
    project_id = (body or {}).get("projectId")
    question = (body or {}).get("question", "").strip()
    session_id = (body or {}).get("sessionId", "")
    
    if not session_id:
        session_id = uuid.uuid4().hex
        
    if not project_id or not question:
        return jsonify({"error": "projectId and question are required"}), 400
        
    result = answer_question(project_id, question, session_id)

    # Return the session_id to the client so they can include it in future requests
    result["sessionId"] = session_id

    return jsonify(result)


@app.get("/projects/<project_id>/chat_history")
@auth_required
def get_chat_history(project_id):
    """Restores a chat session's message history (e.g. after a page reload)."""
    from src.memory import get_session_history
    session_id = request.args.get("sessionId", "").strip()
    if not session_id:
        return jsonify({"error": "sessionId is required"}), 400
    return jsonify({"messages": get_session_history(session_id)})


@app.get("/projects/<project_id>/vulnerabilities")
@auth_required
def get_vulnerabilities(project_id):
    import os
    import json
    report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
    if not os.path.exists(report_path):
        return jsonify({"results": []})
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Language detection from file extension ──────────────────────────────────────
_EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rb": "ruby", ".rs": "rust", ".php": "php",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cxx": "cpp", ".cc": "cpp",
    ".cs": "csharp", ".css": "css", ".html": "xml", ".htm": "xml",
    ".xml": "xml", ".sh": "bash", ".bash": "bash", ".zsh": "bash",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json",
    ".env": "bash", ".toml": "bash", ".tf": "python", ".kt": "java",
    ".swift": "swift",
}

def _infer_language(path: str) -> str:
    import os as _os
    _, ext = _os.path.splitext(path.lower())
    return _EXT_TO_LANG.get(ext, "plaintext")


@app.get("/projects/<project_id>/file_content")
@auth_required
def get_file_content(project_id):
    """
    Returns the full (or windowed) content of a source file for the in-app
    code viewer, along with the vulnerable line range, language, and a
    staleness indicator.

    Query params:
      file_path   — relative path within the repo  (required)
      start_line  — 1-based start of the vulnerable range (required)
      end_line    — 1-based end   of the vulnerable range (optional)
    """
    import os
    import json
    import hashlib

    file_path  = request.args.get("file_path", "").strip()
    start_line = int(request.args.get("start_line", 1))
    end_line   = int(request.args.get("end_line", start_line))

    if not file_path:
        return jsonify({"error": "file_path is required"}), 400

    # ── Resolve absolute path ────────────────────────────────────────────────
    repo_dir  = os.path.join(config.REPOS_DIR, project_id)
    abs_path  = os.path.normpath(os.path.join(repo_dir, file_path))

    # Path traversal guard
    if not abs_path.startswith(os.path.realpath(repo_dir)):
        return jsonify({"error": "Invalid file path"}), 400

    if not os.path.exists(abs_path):
        return jsonify({
            "error":  "file_not_found",
            "detail": f"File '{file_path}' not found. It may have been deleted since the scan.",
        }), 404

    # ── Try to read the file ─────────────────────────────────────────────────
    try:
        with open(abs_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return jsonify({"error": "cannot_read", "detail": str(e)}), 500

    # Reject binary files
    if b"\x00" in raw[:8192]:
        return jsonify({
            "error":  "binary_file",
            "detail": "This file appears to be binary and cannot be displayed.",
        }), 415

    # Decode — try UTF-8, fall back to latin-1 with replacement
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = raw.decode("latin-1")
        except Exception:
            return jsonify({
                "error":  "encoding_error",
                "detail": "File encoding could not be determined.",
            }), 415

    # ── Staleness detection ──────────────────────────────────────────────────
    # Compare current file hash against the hash stored in project meta at
    # ingest time (written by ingestion.py into the project meta).
    stale = False
    try:
        from src.vectorstore import get_project_meta
        meta = get_project_meta(project_id) or {}
        file_hashes = meta.get("file_hashes", {})
        if file_path in file_hashes:
            current_hash = hashlib.md5(raw).hexdigest()
            stale = (current_hash != file_hashes[file_path])
    except Exception:
        pass  # non-fatal — just don't show staleness indicator

    language   = _infer_language(file_path)
    total_lines = content.count("\n") + 1

    return jsonify({
        "content":    content,
        "file_path":  file_path,
        "language":   language,
        "start_line": start_line,
        "end_line":   end_line,
        "total_lines": total_lines,
        "stale":      stale,
    })




@app.post("/projects/<project_id>/vulnerabilities/report")
@auth_required
def generate_vuln_report(project_id):
    from src.chain import generate_vulnerability_report
    body = request.get_json(force=True)
    finding = (body or {}).get("finding")
    if not finding:
        return jsonify({"error": "finding is required"}), 400
    try:
        report = generate_vulnerability_report(project_id, finding)
        return jsonify({"report": report})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/projects/<project_id>/vulnerabilities/autofix")
@auth_required
def auto_fix_vulnerability(project_id):
    from src.chain import apply_auto_fix
    import os
    import json
    
    body = request.get_json(force=True)
    finding = (body or {}).get("finding")
    if not finding:
        return jsonify({"error": "finding is required"}), 400
    try:
        result = apply_auto_fix(project_id, finding)
        
        # Remove the finding from the report.json to keep it in sync
        report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
            
            if "results" in report_data:
                original_len = len(report_data["results"])
                # Coerce line numbers to int on both sides so that a frontend-
                # sent float (e.g. 42.0) cannot silently miss an int (42).
                finding_line = int(finding.get("start", {}).get("line") or 0)
                finding_msg  = finding.get("extra", {}).get("message", "")
                finding_path = finding.get("path", "")

                # Partition: collect matched (to archive) vs remaining
                from datetime import datetime as _dt
                matched, remaining = [], []
                for r in report_data["results"]:
                    if (
                        r.get("path") == finding_path
                        and int(r.get("start", {}).get("line") or 0) == finding_line
                        and r.get("extra", {}).get("message", "") == finding_msg
                    ):
                        matched.append({**r, "fixed_at": _dt.utcnow().isoformat() + "Z"})
                    else:
                        remaining.append(r)

                report_data["results"] = remaining
                report_data.setdefault("fixed", []).extend(matched)

                # If we actually removed something, save it back
                if len(remaining) < original_len:
                    with open(report_path, "w", encoding="utf-8") as f:
                        json.dump(report_data, f, indent=2)

                    # Update in-memory counts and db so badges update immediately
                    counts = {"high": 0, "medium": 0, "low": 0}
                    for res in report_data["results"]:
                        sev = res.get("extra", {}).get("severity", "").lower()
                        if sev in ("error", "high"): counts["high"] += 1
                        elif sev in ("warning", "medium"): counts["medium"] += 1
                        else: counts["low"] += 1

                    from src.ingestion import _projects, _lock
                    from src.vectorstore import upsert_project_meta, get_project_meta
                    with _lock:
                        if project_id in _projects:
                            _projects[project_id]["vulnerabilities"] = counts
                            upsert_project_meta(project_id, {**_projects[project_id]})
                        else:
                            # Project not in memory (e.g. after server restart) —
                            # load from ChromaDB, patch counts, write back.
                            stored = get_project_meta(project_id) or {}
                            stored["vulnerabilities"] = counts
                            upsert_project_meta(project_id, stored)
                            
                    # Inject the fix into the chat history so the LLM remembers!
                    from src.chain import _append_history
                    fix_desc = finding.get("extra", {}).get("message", "")
                    _append_history(project_id, {
                        "role": "assistant",
                        "text": f"**✨ Fix Applied:** Fixed `{finding.get('path', 'unknown file')}` ({fix_desc}).\nDetails: {result.get('message', '')}"
                    })

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/projects/<project_id>/vulnerabilities/evaluate_fix")
@auth_required
def evaluate_fix(project_id):
    from src.chain import evaluate_auto_fix
    body = request.get_json(force=True)
    finding = (body or {}).get("finding")
    if not finding:
        return jsonify({"error": "finding is required"}), 400
    try:
        result = evaluate_auto_fix(project_id, finding)
        if "error" in result:
            return jsonify(result), 200  # Return 200 so the frontend can display the error gracefully
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/projects/<project_id>/vulnerabilities/apply_evaluated_fix")
@auth_required
def apply_evaluated_fix(project_id):
    import os
    import json
    import sys
    
    body = request.get_json(force=True)
    finding = (body or {}).get("finding")
    fixed_content = (body or {}).get("fixed_content")
    
    if not finding or not fixed_content:
        return jsonify({"error": "finding and fixed_content are required"}), 400
        
    file_path = finding.get("path", "")
    if not file_path:
        return jsonify({"error": "Finding does not contain a file path."}), 400

    full_path = os.path.join(config.REPOS_DIR, project_id, file_path)
    # Path traversal guard
    if not os.path.normpath(full_path).startswith(os.path.realpath(os.path.join(config.REPOS_DIR, project_id))):
        return jsonify({"error": "Invalid file path"}), 400

    if not os.path.exists(full_path):
        return jsonify({"error": f"File not found on disk: {file_path}"}), 400

    # ── Write the fixed content to disk ─────────────────────────────────────
    try:
        with open(full_path, "w", encoding="utf-8") as fh:
            fh.write(fixed_content)
    except OSError as write_err:
        print(
            f"[apply_fix ERROR] Failed to write fix to '{full_path}': {write_err}",
            file=sys.stderr, flush=True
        )
        return jsonify({"error": f"Could not write fix to file '{file_path}': {write_err}"}), 500

    removed_from_report = False
    try:
        # ── Remove the finding from report.json to keep it in sync ──────────
        report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as fh:
                report_data = json.load(fh)

            if "results" in report_data:
                original_len = len(report_data["results"])
                # Coerce line numbers to int on both sides so that a frontend-
                # sent float (e.g. 42.0) cannot silently miss an int (42).
                finding_line = int(finding.get("start", {}).get("line") or 0)
                finding_msg  = finding.get("extra", {}).get("message", "")
                finding_path = finding.get("path", "")

                from datetime import datetime as _dt
                matched, remaining = [], []
                for r in report_data["results"]:
                    if (
                        r.get("path") == finding_path
                        and int(r.get("start", {}).get("line") or 0) == finding_line
                        and r.get("extra", {}).get("message", "") == finding_msg
                    ):
                        matched.append({**r, "fixed_at": _dt.utcnow().isoformat() + "Z"})
                    else:
                        remaining.append(r)

                report_data["results"] = remaining
                report_data.setdefault("fixed", []).extend(matched)

                if len(remaining) < original_len:
                    removed_from_report = True
                    with open(report_path, "w", encoding="utf-8") as fh:
                        json.dump(report_data, fh, indent=2)

                    counts = {"high": 0, "medium": 0, "low": 0}
                    for res in report_data["results"]:
                        sev = res.get("extra", {}).get("severity", "").lower()
                        if sev in ("error", "high"): counts["high"] += 1
                        elif sev in ("warning", "medium"): counts["medium"] += 1
                        else: counts["low"] += 1

                    from src.ingestion import _projects, _lock
                    from src.vectorstore import upsert_project_meta, get_project_meta
                    with _lock:
                        if project_id in _projects:
                            _projects[project_id]["vulnerabilities"] = counts
                            upsert_project_meta(project_id, {**_projects[project_id]})
                        else:
                            # Project not in memory (e.g. after server restart) —
                            # load from ChromaDB, patch counts, write back.
                            stored = get_project_meta(project_id) or {}
                            stored["vulnerabilities"] = counts
                            upsert_project_meta(project_id, stored)

                    from src.chain import _append_history
                    fix_desc = finding.get("extra", {}).get("message", "")
                    _append_history(project_id, {
                        "role": "assistant",
                        "text": f"**✨ Fix Applied:** Fixed `{file_path}` ({fix_desc})."
                    })
                else:
                    print(
                        f"[apply_fix WARN] Finding not matched in report.json "
                        f"(path={finding_path!r}, line={finding_line}, msg={finding_msg!r}). "
                        "File was written but report was not updated.",
                        file=sys.stderr, flush=True
                    )
    except Exception as e:
        # Report update is best-effort; the file fix already succeeded.
        print(f"[apply_fix WARN] Could not update report.json: {e}", file=sys.stderr, flush=True)

    return jsonify({
        "status": "success",
        "file": file_path,
        "message": "Applied evaluated fix successfully.",
        "removed_from_report": removed_from_report,
    })

@app.post("/projects/<project_id>/vulnerabilities/rescan")
@auth_required
def rescan_vulnerabilities_route(project_id):
    from src.ingestion import rescan_vulnerabilities
    try:
        counts = rescan_vulnerabilities(project_id)
        return jsonify({"vulnerabilities": counts})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.delete("/projects/<project_id>")
@auth_required
def remove_project(project_id):
    delete_project(project_id)
    return jsonify({"ok": True})


@app.get("/projects/<project_id>/download/repo")
@auth_required
def download_repo(project_id):
    import shutil
    import os
    repo_path = os.path.join(config.REPORTS_DIR, "..", "repos", project_id)
    if not os.path.exists(repo_path):
        return jsonify({"error": "repo not found"}), 404
    
    zips_dir = os.path.join(config.DATA_DIR, "zips")
    os.makedirs(zips_dir, exist_ok=True)
    zip_path = os.path.join(zips_dir, project_id)
    shutil.make_archive(zip_path, 'zip', repo_path)
    return send_file(zip_path + ".zip", as_attachment=True, download_name=f"{project_id}_repo.zip")


@app.post("/projects/<project_id>/push")
@auth_required
def push_fixes(project_id):
    import os
    import git
    import uuid
    from urllib.parse import urlparse, urlunparse, quote
    
    repo_path = os.path.join(config.REPORTS_DIR, "..", "repos", project_id)
    if not os.path.exists(repo_path):
        return jsonify({"error": "repo not found"}), 404
        
    data = request.json or {}
    token = data.get("token", "").strip()
    raw_branch = data.get("branch", "").strip()
    # Sanitize: remove/replace characters that git rejects in ref names
    # (spaces, \n, ~, ^, :, ?, *, [, \) and sequences like ".." or "@{"
    import re as _re
    safe_branch = _re.sub(r'[\s~^:?*\[\\]+', '-', raw_branch)
    safe_branch = _re.sub(r'\.{2,}', '-', safe_branch)
    safe_branch = _re.sub(r'-{2,}', '-', safe_branch)
    safe_branch = safe_branch.strip('-.')
    branch_name = safe_branch or f"security-fixes-{uuid.uuid4().hex[:6]}"
    commit_message = data.get("commit_message", "").strip() or "Apply automated security fixes"
    
    try:
        repo = git.Repo(repo_path)
        
        # Create or checkout branch
        if branch_name in repo.heads:
            current = repo.heads[branch_name]
        else:
            current = repo.create_head(branch_name)
        current.checkout()
        
        # Add and commit all changes if the working tree is dirty
        if repo.is_dirty() or repo.untracked_files:
            repo.git.add(all=True)
            repo.index.commit(commit_message)
        
        # Handle authentication if token is provided
        origin = repo.remotes.origin
        original_url = list(origin.urls)[0]
        
        if token:
            parsed = urlparse(original_url)
            encoded_token = quote(token, safe="")
            # Replace auth in URL
            authed = parsed._replace(netloc=f"x-access-token:{encoded_token}@{parsed.hostname}")
            authed_url = urlunparse(authed)
            origin.set_url(authed_url)
            
        try:
            # Disable terminal prompt so git doesn't hang waiting for credentials
            os.environ["GIT_TERMINAL_PROMPT"] = "0"
            # Push the branch (force push to overwrite old history on that branch)
            origin.push(branch_name, force=True)
        finally:
            # Always restore original URL so the token isn't saved permanently
            if token:
                origin.set_url(original_url)
                
        return jsonify({"ok": True, "branch": branch_name, "message": f"Successfully pushed to branch '{branch_name}' on GitHub!"})
        
    except git.exc.GitCommandError as e:
        err_msg = str(e).lower()
        if "authentication failed" in err_msg or "403" in err_msg or "401" in err_msg or "terminal prompts disabled" in err_msg or "could not read username" in err_msg:
            return jsonify({"error": "Authentication failed. The repository requires a GitHub Personal Access Token (PAT) to push. Please provide a valid PAT when prompted."}), 401
        return jsonify({"error": f"Git error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/projects/<project_id>/download/report")
@auth_required
def download_report(project_id):
    import os
    report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "report not found"}), 404
    from src.pdf_generator import generate_vulnerability_pdf
    pdf_path = os.path.join(config.REPORTS_DIR, f"{project_id}.pdf")
    
    try:
        generate_vulnerability_pdf(project_id, report_path, pdf_path)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        
    return send_file(pdf_path, as_attachment=True, download_name=f"{project_id}_vulnerabilities.pdf")


# Serve the built frontend (frontend/vite.config.js builds into ./static).
@app.get("/")
@app.get("/<path:path>")
def serve_frontend(path=""):
    if path and (app.static_folder and (app.static_folder + "/" + path)):
        try:
            return send_from_directory(app.static_folder, path)
        except Exception:
            pass
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT, debug=config.DEBUG)
