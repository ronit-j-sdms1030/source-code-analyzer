"""ChromaDB setup, persistence, and per-repo collection management.

One collection per repo, persisted to disk under data/chroma so re-opening a
repo skips re-indexing. A small "projects" collection stores project metadata
(name, url, file/chunk counts) so /projects can list everything without
re-scanning the filesystem.
"""

from . import config

_META_COLLECTION = "projects_meta"

# Module-level singleton. Using a plain variable instead of @lru_cache gives
# us explicit control to reset it if the connection goes stale (e.g. after
# Flask's hot-reload kills and recreates the Python process mid-request).
_chroma_client = None


def _client():
    global _chroma_client
    if _chroma_client is not None:
        return _chroma_client
    import chromadb
    _chroma_client = chromadb.PersistentClient(path=config.CHROMA_DIR)
    return _chroma_client


def _reset_client():
    """Clear the cached client so the next call to _client() reconnects."""
    global _chroma_client
    _chroma_client = None


def _client_with_retry():
    """Return a healthy ChromaDB client, reconnecting once if the cached
    instance is stale (e.g. after a Flask hot-reload)."""
    try:
        return _client()
    except Exception:  # noqa: BLE001
        _reset_client()
        return _client()


def _collection_name(project_id: str) -> str:
    return f"repo_{project_id}"

def _findings_collection_name(project_id: str) -> str:
    return f"findings_{project_id}"

def _memory_collection_name(project_id: str) -> str:
    return f"memory_{project_id}"


def write_chunks(project_id: str, chunks: list, vectors: list):
    """Writes embedded chunks + metadata (file path, chunk index) to a
    persisted ChromaDB collection named per repo."""
    client = _client_with_retry()
    collection = client.get_or_create_collection(_collection_name(project_id))
    collection.add(
        ids=[f"{project_id}-{i}" for i in range(len(chunks))],
        embeddings=vectors,
        documents=[c["text"] for c in chunks],
        metadatas=[
            {"file_path": c["file_path"], "chunk_index": c["chunk_index"], "project_id": project_id}
            for c in chunks
        ],
    )


def query_chunks(project_id: str, query_vector: list, top_k: int = 5) -> dict:
    client = _client_with_retry()
    collection = client.get_or_create_collection(_collection_name(project_id))
    return collection.query(query_embeddings=[query_vector], n_results=top_k)

def write_findings(project_id: str, findings: list, vectors: list):
    """Writes embedded findings to a persisted ChromaDB collection named per repo."""
    if not findings:
        return
    client = _client_with_retry()
    collection = client.get_or_create_collection(_findings_collection_name(project_id))
    collection.add(
        ids=[f["finding_id"] for f in findings],
        embeddings=vectors,
        documents=[f["text"] for f in findings],
        metadatas=[f["metadata"] for f in findings],
    )

def query_findings(project_id: str, query_vector: list = None, where: dict = None, top_k: int = 5) -> dict:
    client = _client_with_retry()
    collection = client.get_or_create_collection(_findings_collection_name(project_id))
    kwargs = {}
    if query_vector:
        kwargs["query_embeddings"] = [query_vector]
        kwargs["n_results"] = top_k
    else:
        kwargs["n_results"] = top_k
        # Chroma requires query_embeddings or query_texts for query(), but we can use get() for pure metadata lookups
        if where:
            res = collection.get(where=where)
        else:
            res = collection.get()
        # Wrap get() results in outer lists to match query() format
        return {
            "ids": [res.get("ids", [])],
            "documents": [res.get("documents", [])],
            "metadatas": [res.get("metadatas", [])]
        }

    if where:
        kwargs["where"] = where
    return collection.query(**kwargs)

def write_memory(project_id: str, memory_id: str, text: str, vector: list, metadata: dict):
    client = _client_with_retry()
    collection = client.get_or_create_collection(_memory_collection_name(project_id))
    collection.add(
        ids=[memory_id],
        embeddings=[vector],
        documents=[text],
        metadatas=[metadata]
    )

def query_memory(project_id: str, query_vector: list, top_k: int = 2) -> dict:
    client = _client_with_retry()
    collection = client.get_or_create_collection(_memory_collection_name(project_id))
    # Check count first to avoid querying empty collection which can error in some chroma versions
    if collection.count() == 0:
        return {"documents": [[]], "metadatas": [[]]}
    return collection.query(query_embeddings=[query_vector], n_results=top_k)


def delete_collection(project_id: str):
    client = _client_with_retry()
    try:
        client.delete_collection(_collection_name(project_id))
    except Exception:  # noqa: BLE001
        pass
    try:
        client.delete_collection(_findings_collection_name(project_id))
    except Exception:
        pass
    try:
        client.delete_collection(_memory_collection_name(project_id))
    except Exception:
        pass
        
    meta = client.get_or_create_collection(_META_COLLECTION)
    try:
        meta.delete(ids=[project_id])
    except Exception:  # noqa: BLE001
        pass
        
    import os
    report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
    if os.path.exists(report_path):
        try:
            os.remove(report_path)
        except Exception:
            pass


def upsert_project_meta(project_id: str, project: dict):
    import json

    client = _client_with_retry()
    meta = client.get_or_create_collection(_META_COLLECTION)
    meta.upsert(ids=[project_id], documents=[json.dumps(project)], metadatas=[{"project_id": project_id}])


def get_project_meta(project_id: str):
    import json

    client = _client_with_retry()
    meta = client.get_or_create_collection(_META_COLLECTION)
    result = meta.get(ids=[project_id])
    docs = result.get("documents") or []
    return json.loads(docs[0]) if docs else None


def list_projects() -> list:
    import json

    client = _client_with_retry()
    meta = client.get_or_create_collection(_META_COLLECTION)
    result = meta.get()
    return [json.loads(d) for d in (result.get("documents") or [])]
