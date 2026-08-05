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

from flask import Flask, jsonify, request, send_from_directory, send_file

from src import config
from src.ingestion import start_ingest, get_status, delete_project
from src.chain import answer_question
from src.vectorstore import list_projects

app = Flask(__name__, static_folder="static", static_url_path="")


@app.get("/projects")
def projects():
    return jsonify(list_projects())


@app.post("/ingest")
def ingest():
    body = request.get_json(force=True)
    url = (body or {}).get("url", "").strip()
    token = (body or {}).get("token", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    project = start_ingest(url, token=token)
    return jsonify(project), 201


@app.get("/ingest/<project_id>/status")
def ingest_status(project_id):
    status = get_status(project_id)
    if status is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(status)


@app.post("/chat")
def chat():
    body = request.get_json(force=True)
    project_id = (body or {}).get("projectId")
    question = (body or {}).get("question", "").strip()
    if not project_id or not question:
        return jsonify({"error": "projectId and question are required"}), 400
    result = answer_question(project_id, question)
    return jsonify(result)


@app.get("/projects/<project_id>/vulnerabilities")
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


@app.post("/projects/<project_id>/vulnerabilities/report")
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
                # Filter out the matching finding
                report_data["results"] = [
                    r for r in report_data["results"] 
                    if not (r.get("path") == finding.get("path") and 
                            r.get("start", {}).get("line") == finding.get("start", {}).get("line") and 
                            r.get("extra", {}).get("message") == finding.get("extra", {}).get("message"))
                ]
                
                # If we actually removed something, save it back
                if len(report_data["results"]) < original_len:
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
                    with _lock:
                        if project_id in _projects:
                            from src.vectorstore import upsert_project_meta
                            _projects[project_id]["vulnerabilities"] = counts
                            upsert_project_meta(project_id, {**_projects[project_id]})
                            
                    # Inject the fix into the chat history so the LLM remembers!
                    from src.chain import _append_history
                    msg = f"**✨ Fix Applied:** Fixed {finding.get('path', 'unknown file')} ({finding.get('extra', {}).get('message', '')}).\nDetails: {result.get('message', '')}"
                    _append_history(project_id, {"role": "assistant", "text": msg})

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/projects/<project_id>/vulnerabilities/rescan")
def rescan_vulnerabilities_route(project_id):
    from src.ingestion import rescan_vulnerabilities
    try:
        counts = rescan_vulnerabilities(project_id)
        return jsonify({"vulnerabilities": counts})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.delete("/projects/<project_id>")
def remove_project(project_id):
    delete_project(project_id)
    return jsonify({"ok": True})


@app.get("/projects/<project_id>/download/repo")
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
def push_repo(project_id):
    import os
    import git
    import uuid
    from urllib.parse import urlparse, urlunparse, quote
    
    repo_path = os.path.join(config.REPORTS_DIR, "..", "repos", project_id)
    if not os.path.exists(repo_path):
        return jsonify({"error": "repo not found"}), 404
        
    data = request.json or {}
    token = data.get("token", "").strip()
    branch_name = data.get("branch", "").strip() or f"security-fixes-{uuid.uuid4().hex[:6]}"
    commit_message = data.get("commit_message", "").strip() or "Apply automated security fixes"
    
    try:
        repo = git.Repo(repo_path)
        
        # Check if there are any changes to commit
        if not repo.is_dirty() and not repo.untracked_files:
            return jsonify({"error": "No security fixes have been applied yet. Nothing to push!"}), 400
            
        # Create and checkout new branch
        current = repo.create_head(branch_name)
        current.checkout()
        
        # Add and commit all changes
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
            # Push the branch
            origin.push(branch_name)
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
