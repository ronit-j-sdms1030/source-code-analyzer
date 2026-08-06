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

STAGES = ["clone", "filter", "scan", "split", "embed", "store"]

_projects = {}  # in-memory status cache; vectorstore.list_projects() is the source of truth for "ready" projects
_lock = threading.Lock()


def _repo_name_from_url(url: str) -> str:
    clean = url.rstrip("/").removesuffix(".git")
    return clean.split("/")[-1] or "repository"


def start_ingest(url: str, token: str = "") -> dict:
    project_id = f"p{uuid.uuid4().hex[:10]}"
    project = {
        "id": project_id,
        "name": _repo_name_from_url(url),
        "url": url,  # store the clean URL, never the token
        "status": "indexing",
        "stageIndex": 0,
        "files": 0,
        "chunks": 0,
        "indexedAt": None,
        "messages": [],
    }
    with _lock:
        _projects[project_id] = project

    thread = threading.Thread(target=_run_pipeline, args=(project_id, url, token), daemon=True)
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


def _run_semgrep(project_id: str, repo_path: str) -> dict:
    """Runs Semgrep on the cloned repo, saves JSON report, returns severity counts."""
    import subprocess
    import json
    import os
    
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
    
    try:
        subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--config", "custom_rules.yml", "--no-git-ignore", "--exclude", ".git", "--json", "--output", report_path, repo_path],
            check=False,  # Returns non-zero if issues are found, which is normal
            capture_output=True,
        )
        
        counts = {"high": 0, "medium": 0, "low": 0}
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            # Ignore vulnerabilities from .env.example files
            data["results"] = [f for f in data.get("results", []) if not f.get("path", "").endswith(".env.example")]
            
            file_cache = {}
            for finding in data.get("results", []):
                # Convert absolute path to relative path
                path = finding.get("path", "")
                if path and path.startswith(repo_path):
                    finding["path"] = os.path.relpath(path, repo_path)
                    
                # Guardrail: log when we are falling back to manual extraction
                raw_lines = finding.get("extra", {}).get("lines", "").lower()
                if raw_lines and len(raw_lines) < 40 and ("login" in raw_lines or "requires" in raw_lines):
                    print(f"[INFO] Semgrep snippet redacted ('{raw_lines}'). Overriding with manual file extraction for '{finding.get('check_id')}'.", flush=True)
                    
                # Manually extract snippet to bypass Semgrep redaction
                try:
                    rel_path = finding.get("path", "")
                    abs_path = os.path.join(repo_path, rel_path)
                    
                    if abs_path not in file_cache:
                        with open(abs_path, 'r', encoding='utf-8') as src_file:
                            file_cache[abs_path] = src_file.read().splitlines()
                            
                    lines = file_cache[abs_path]
                    start_line = finding.get("start", {}).get("line", 1) - 1
                    end_line = finding.get("end", {}).get("line", start_line + 1)
                    
                    if "extra" not in finding:
                        finding["extra"] = {}
                        
                    if start_line >= 0 and end_line <= len(lines) and start_line < end_line:
                        finding["extra"]["lines"] = "\n".join(lines[start_line:end_line])
                    else:
                        finding["extra"]["lines"] = "[UNABLE TO EXTRACT VALUE]"
                except Exception:
                    if "extra" not in finding:
                        finding["extra"] = {}
                    finding["extra"]["lines"] = "[UNABLE TO EXTRACT VALUE]"
                    
                sev = finding.get("extra", {}).get("severity", "").lower()
                if sev == "error" or sev == "high":
                    counts["high"] += 1
                elif sev == "warning" or sev == "medium":
                    counts["medium"] += 1
                else:
                    counts["low"] += 1
                    
            # Save the fixed relative paths back to disk
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            # ── Persist per-file MD5 hashes for staleness detection ──────────
            # Stored in project meta as { "file_hashes": { "rel/path": "hex" } }
            import hashlib as _hashlib
            file_hashes = {}
            for abs_p, file_lines in file_cache.items():
                try:
                    rel_p = os.path.relpath(abs_p, repo_path)
                    raw_bytes = "\n".join(file_lines).encode("utf-8", errors="replace")
                    file_hashes[rel_p] = _hashlib.md5(raw_bytes).hexdigest()
                except Exception:
                    pass
            # Will be merged into project meta by _run_pipeline
            return counts, file_hashes

        return counts, {}
    except Exception as e:
        print(f"[semgrep error] {e}", flush=True)
        return {"high": 0, "medium": 0, "low": 0}, {}


def rescan_vulnerabilities(project_id: str) -> dict:
    import os
    repo_path = os.path.join(config.REPOS_DIR, project_id)
    if not os.path.exists(repo_path):
        raise ValueError("Repository files not found on disk. Rescan impossible.")
    
    vuln_counts, file_hashes = _run_semgrep(project_id, repo_path)
    
    from .vectorstore import get_project_meta, upsert_project_meta
    
    with _lock:
        project = None
        if project_id in _projects:
            _projects[project_id]["vulnerabilities"] = vuln_counts
            _projects[project_id]["file_hashes"] = file_hashes
            project = _projects[project_id]
        else:
            project = get_project_meta(project_id)
            if project:
                project["vulnerabilities"] = vuln_counts
                project["file_hashes"] = file_hashes
                
        if project:
            upsert_project_meta(project_id, project)
    
    return vuln_counts


def _generate_repo_tree(repo_path: str) -> str:
    """Generates a text representation of the file tree for LLM context."""
    import os

    tree_lines = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in config.SKIP_DIRS]
        dirs.sort()
        files.sort()
        
        rel_path = os.path.relpath(root, repo_path)
        if rel_path == ".":
            rel_path = ""
        else:
            # Unix-style paths for the tree
            rel_path = rel_path.replace(os.sep, "/")
            tree_lines.append(f"{rel_path}/")
            
        for f in files:
            if rel_path:
                tree_lines.append(f"{rel_path}/{f}")
            else:
                tree_lines.append(f)
                
        if len(tree_lines) > 5000:
            tree_lines.append("... (tree truncated, too many files)")
            break
            
    return "\n".join(tree_lines)


def _run_pipeline(project_id: str, url: str, token: str = ""):
    try:
        # [1] Repo cloner — shallow clone (git clone --depth=1)
        repo_path = _clone_repo(project_id, url, token)
        _set_stage(project_id, 1)

        # [2] File filter — collect all supported source files, skip noise dirs
        py_files = _filter_source_files(repo_path)
        _set_stage(project_id, 2)

        # Generate file tree before the repo is deleted, so LLM can understand repo structure
        file_tree = _generate_repo_tree(repo_path)

        # [3] Semgrep — Scan for vulnerabilities
        vuln_counts, file_hashes = _run_semgrep(project_id, repo_path)
        _set_stage(project_id, 3)

        # [4] Code-aware splitter — chunk by function/class
        chunks = _split_files(py_files, repo_path)
        _set_stage(project_id, 4)

        # [4.5] Deterministic Dependency Graph
        try:
            from .graph import build_graph
            from .memory import save_graph
            graph = build_graph(project_id, repo_path, py_files)
            save_graph(project_id, graph)
        except Exception as e:
            print(f"Graph build error: {e}")

        # [5] Embedder — chunk -> vector
        vectors = embed_chunks([c["text"] for c in chunks])
        _set_stage(project_id, 5)

        # [6] Vector writer — persist to ChromaDB (per-repo collection)
        write_chunks(project_id, chunks, vectors)
        _set_stage(project_id, 6)

        # Post-indexing cleanup: (Removed to allow autofix feature to work on repo files)

        result = {
            "status": "ready",
            "stageIndex": len(STAGES),
            "files": len(py_files),
            "chunks": len(chunks),
            "file_tree": file_tree,
            "vulnerabilities": vuln_counts,
            "file_hashes": file_hashes,
            "indexedAt": "just now",
            "messages": [
                {
                    "role": "assistant",
                    "text": f"Repo indexed. {len(py_files)} source files split into "
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


def _clone_repo(project_id: str, url: str, token: str = "") -> str:
    """Shallow-clones the repo via GitPython (--depth=1) into data/repos/<id>.

    If a token is supplied it is injected into the HTTPS URL so private
    repos can be cloned. GitHub PATs use 'x-access-token:<token>@host'.
    The token is never stored — it exists only for the duration of this call.
    """
    from git import Repo  # GitPython
    from urllib.parse import urlparse, urlunparse, quote
    import os

    clone_url = url
    if token:
        parsed = urlparse(url)
        encoded_token = quote(token, safe="")
        # GitHub documents x-access-token as the username for PAT auth
        authed = parsed._replace(netloc=f"x-access-token:{encoded_token}@{parsed.hostname}")
        clone_url = urlunparse(authed)

    dest = f"{config.REPOS_DIR}/{project_id}"
    os.makedirs(dest, exist_ok=True)
    try:
        Repo.clone_from(clone_url, dest, depth=1, env={"GIT_TERMINAL_PROMPT": "0"})
    except Exception as exc:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        stderr = str(exc).lower()
        print(f"[clone error] {exc}", flush=True)
        # Produce a friendly message based on the git error and whether a token was provided
        if "repository not found" in stderr or "not found" in stderr or "terminal prompts disabled" in stderr:
            if not token:
                raise RuntimeError(
                    "This appears to be a private repository. "
                    "Please click '🔒 Private repo? Add access token' and enter "
                    "your GitHub Personal Access Token (PAT) to continue."
                )
            else:
                raise RuntimeError(
                    "Repository not found or access denied. "
                    "Make sure your PAT belongs to an account that has access to this repo "
                    "and has the 'repo' scope (classic) or 'Contents: Read' permission (fine-grained)."
                )
        elif "authentication failed" in stderr or "403" in stderr or "401" in stderr:
            raise RuntimeError(
                "Authentication failed. Your access token is invalid or has expired. "
                "Please generate a new PAT on GitHub and try again."
            )
        elif "could not resolve host" in stderr or "unable to connect" in stderr:
            raise RuntimeError(
                "Network error: could not reach GitHub. Please check your internet connection."
            )
        else:
            raise RuntimeError(f"Clone failed: {exc}")
    return dest


# Supported file extensions mapped to their LangChain Language enum value.
# Extensions not listed here are skipped during ingestion.
SUPPORTED_EXTENSIONS = {
    ".py": "PYTHON",
    ".js": "JS",
    ".jsx": "JS",
    ".ts": "TS",
    ".tsx": "TS",
    ".java": "JAVA",
    ".go": "GO",
    ".c": "C",
    ".h": "C",
    ".cpp": "CPP",
    ".cc": "CPP",
    ".cs": "CSHARP",
    ".rs": "RUST",
    ".rb": "RUBY",
    ".php": "PHP",
    ".swift": "SWIFT",
    ".kt": "KOTLIN",
    ".scala": "SCALA",
    ".md": "MARKDOWN",
}


def _filter_source_files(repo_path: str) -> list:
    """Walks the cloned tree, collects all supported source files, skips noise dirs."""
    import os

    files = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in config.SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                files.append(os.path.join(root, name))
                if len(files) >= config.MAX_FILES_PER_REPO:
                    return files
    return files


def _split_files(source_files: list, repo_path: str) -> list:
    """Breaks each file into chunks using a language-aware splitter.

    Uses LangChain's RecursiveCharacterTextSplitter.from_language() with the
    correct Language enum for each file extension, so chunks preserve logical
    context (functions, classes, blocks) instead of splitting on arbitrary line
    counts. Falls back to generic splitting for unrecognized extensions.
    """
    import os
    from langchain_text_splitters import RecursiveCharacterTextSplitter, Language

    _splitter_cache = {}

    def _get_splitter(ext: str):
        lang_name = SUPPORTED_EXTENSIONS.get(ext)
        if lang_name not in _splitter_cache:
            try:
                lang = Language[lang_name]
                splitter = RecursiveCharacterTextSplitter.from_language(
                    language=lang, chunk_size=800, chunk_overlap=100
                )
            except (KeyError, Exception):
                splitter = RecursiveCharacterTextSplitter(
                    chunk_size=800, chunk_overlap=100
                )
            _splitter_cache[lang_name] = splitter
        return _splitter_cache[lang_name]

    chunks = []
    for path in source_files:
        ext = os.path.splitext(path)[1].lower()
        splitter = _get_splitter(ext)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
            
        # Use clean relative paths (e.g. 'app/bot.py') instead of ugly absolute ones
        # so the UI and the LLM see a clean, standard file structure
        rel_path = os.path.relpath(path, repo_path).replace(os.sep, "/")
        
        for j, piece in enumerate(splitter.split_text(text)):
            chunks.append({"text": piece, "file_path": rel_path, "chunk_index": j})
    return chunks
