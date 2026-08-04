"""Ingestion pipeline: clone -> filter -> split -> embed -> store.

Kicks off indexing for a repo URL in a background thread so /ingest returns
immediately, and exposes get_status()/delete_project() for the /ingest/:id/status
and DELETE /projects/:id routes to poll and clean up.
"""

import re
import shutil
import threading
import time
import uuid

from . import config
from .embeddings import embed_chunks
from .vectorstore import write_chunks, delete_collection, upsert_project_meta, get_project_meta

STAGES = ["clone", "filter", "split", "embed", "store"]

_projects = {}  # in-memory status cache; vectorstore.list_projects() is the source of truth for "ready" projects
_lock = threading.Lock()


def _repo_name_from_url(url: str) -> str:
    clean = url.rstrip("/").removesuffix(".git")
    return clean.split("/")[-1] or "repository"


def start_ingest(url: str) -> dict:
    project_id = f"p{uuid.uuid4().hex[:10]}"
    project = {
        "id": project_id,
        "name": _repo_name_from_url(url),
        "url": url,
        "status": "indexing",
        "stageIndex": 0,
        "files": 0,
        "chunks": 0,
        "indexedAt": None,
        "messages": [],
    }
    with _lock:
        _projects[project_id] = project

    thread = threading.Thread(target=_run_pipeline, args=(project_id, url), daemon=True)
    thread.start()
    return project


def get_status(project_id: str):
    with _lock:
        cached = _projects.get(project_id)
    if cached:
        return cached
    return get_project_meta(project_id)


def delete_project(project_id: str):
    with _lock:
        _projects.pop(project_id, None)
    delete_collection(project_id)
    shutil.rmtree(f"{config.REPOS_DIR}/{project_id}", ignore_errors=True)


def _set_stage(project_id: str, stage_index: int):
    with _lock:
        if project_id in _projects:
            _projects[project_id]["stageIndex"] = stage_index


def _run_pipeline(project_id: str, url: str):
    try:
        # [1] Repo cloner — shallow clone (git clone --depth=1)
        repo_path = _clone_repo(project_id, url)
        _set_stage(project_id, 1)

        # [2] File filter — collect .py files, skip noise dirs
        py_files = _filter_python_files(repo_path)
        _set_stage(project_id, 2)

        # [3] Code-aware splitter — chunk by function/class
        chunks = _split_files(py_files)
        _set_stage(project_id, 3)

        # [4] Embedder — chunk -> vector
        vectors = embed_chunks([c["text"] for c in chunks])
        _set_stage(project_id, 4)

        # [5] Vector writer — persist to ChromaDB (per-repo collection)
        write_chunks(project_id, chunks, vectors)
        _set_stage(project_id, 5)

        # Post-indexing cleanup: raw repo files aren't needed once vectors persist.
        shutil.rmtree(repo_path, ignore_errors=True)

        result = {
            "status": "ready",
            "stageIndex": len(STAGES),
            "files": len(py_files),
            "chunks": len(chunks),
            "indexedAt": "just now",
            "messages": [
                {
                    "role": "assistant",
                    "text": f"Repo indexed. {len(py_files)} Python files split into "
                    f"{len(chunks):,} chunks. Ask me anything about this codebase.",
                    "sources": [],
                }
            ],
        }
        with _lock:
            _projects[project_id].update(result)
        upsert_project_meta(project_id, {**_projects[project_id]})
    except Exception as exc:  # noqa: BLE001
        with _lock:
            if project_id in _projects:
                _projects[project_id]["status"] = "error"
                _projects[project_id]["error"] = str(exc)


def _clone_repo(project_id: str, url: str) -> str:
    """Shallow-clones the repo via GitPython (--depth=1) into data/repos/<id>."""
    from git import Repo  # GitPython

    dest = f"{config.REPOS_DIR}/{project_id}"
    Repo.clone_from(url, dest, depth=1)
    return dest


def _filter_python_files(repo_path: str) -> list:
    """Walks the cloned tree, collects .py files, skips noise directories."""
    import os

    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in config.SKIP_DIRS]
        for name in filenames:
            if name.endswith(".py"):
                files.append(os.path.join(root, name))
                if len(files) >= config.MAX_FILES_PER_REPO:
                    return files
    return files


def _split_files(py_files: list) -> list:
    """Breaks each file into chunks aligned to functions/classes.

    Uses LangChain's RecursiveCharacterTextSplitter.from_language(Language.PYTHON)
    so chunks preserve logical context instead of splitting on arbitrary line counts.
    """
    from langchain.text_splitter import RecursiveCharacterTextSplitter, Language

    splitter = RecursiveCharacterTextSplitter.from_language(
        language=Language.PYTHON, chunk_size=800, chunk_overlap=100
    )
    chunks = []
    for i, path in enumerate(py_files):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        for j, piece in enumerate(splitter.split_text(text)):
            chunks.append({"text": piece, "file_path": path, "chunk_index": j})
    return chunks
