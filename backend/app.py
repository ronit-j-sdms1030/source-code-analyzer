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
    if not url:
        return jsonify({"error": "url is required"}), 400
    project = start_ingest(url)
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
