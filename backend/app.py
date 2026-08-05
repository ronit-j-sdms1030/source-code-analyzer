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

from flask import Flask, jsonify, request, send_from_directory

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


@app.delete("/projects/<project_id>")
def remove_project(project_id):
    delete_project(project_id)
    return jsonify({"ok": True})


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
