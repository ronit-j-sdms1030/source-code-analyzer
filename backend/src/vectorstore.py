"""ChromaDB setup, persistence, and per-repo collection management.

One collection per repo, persisted to disk under data/chroma so re-opening a
repo skips re-indexing. A small "projects" collection stores project metadata
(name, url, file/chunk counts) so /projects can list everything without
re-scanning the filesystem.
"""

from functools import lru_cache

from . import config

_META_COLLECTION = "projects_meta"


@lru_cache(maxsize=1)
def _client():
    import chromadb

    return chromadb.PersistentClient(path=config.CHROMA_DIR)


def _collection_name(project_id: str) -> str:
    return f"repo_{project_id}"


def write_chunks(project_id: str, chunks: list, vectors: list):
    """Writes embedded chunks + metadata (file path, chunk index) to a
    persisted ChromaDB collection named per repo."""
    client = _client()
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
    client = _client()
    collection = client.get_or_create_collection(_collection_name(project_id))
    return collection.query(query_embeddings=[query_vector], n_results=top_k)


def delete_collection(project_id: str):
    client = _client()
    try:
        client.delete_collection(_collection_name(project_id))
    except Exception:  # noqa: BLE001
        pass
    meta = client.get_or_create_collection(_META_COLLECTION)
    try:
        meta.delete(ids=[project_id])
    except Exception:  # noqa: BLE001
        pass


def upsert_project_meta(project_id: str, project: dict):
    import json

    client = _client()
    meta = client.get_or_create_collection(_META_COLLECTION)
    meta.upsert(ids=[project_id], documents=[json.dumps(project)], metadatas=[{"project_id": project_id}])


def get_project_meta(project_id: str):
    import json

    client = _client()
    meta = client.get_or_create_collection(_META_COLLECTION)
    result = meta.get(ids=[project_id])
    docs = result.get("documents") or []
    return json.loads(docs[0]) if docs else None


def list_projects() -> list:
    import json

    client = _client()
    meta = client.get_or_create_collection(_META_COLLECTION)
    result = meta.get()
    return [json.loads(d) for d in (result.get("documents") or [])]
