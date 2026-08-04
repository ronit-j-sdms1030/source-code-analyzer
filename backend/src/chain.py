"""RAG chain: embeds the question, retrieves relevant chunks from ChromaDB,
builds a prompt with prior chat history, and calls Ollama (qwen2.5-coder:3b).

The LLM never sees the whole repository — only the specific chunks retrieval
decided were relevant to the current question. This is what lets a small
local model handle codebases far larger than its context window.
"""

from . import config
from .embeddings import embed_query
from .vectorstore import query_chunks

# Very small in-memory chat history per project, keyed by project_id.
# A production build would persist this alongside project metadata.
_history = {}


def _build_prompt(question: str, chunks: list, history: list) -> str:
    context = "\n\n".join(f"# {c['file_path']}\n{c['text']}" for c in chunks)
    history_text = "\n".join(f"{h['role']}: {h['text']}" for h in history[-6:])
    return (
        "You are a source code analysis assistant. Answer using only the "
        "retrieved code chunks below. Cite the file path where the answer "
        "comes from.\n\n"
        f"Conversation so far:\n{history_text}\n\n"
        f"Retrieved code chunks:\n{context}\n\n"
        f"Question: {question}\nAnswer:"
    )


def answer_question(project_id: str, question: str) -> dict:
    query_vector = embed_query(question)
    results = query_chunks(project_id, query_vector, top_k=5)

    documents = (results.get("documents") or [[]])[0]
    metadatas = (results.get("metadatas") or [[]])[0]
    chunks = [{"text": d, "file_path": m.get("file_path", "unknown")} for d, m in zip(documents, metadatas)]

    history = _history.setdefault(project_id, [])
    prompt = _build_prompt(question, chunks, history)

    answer = _call_ollama(prompt)

    history.append({"role": "user", "text": question})
    history.append({"role": "assistant", "text": answer})

    sources = sorted({c["file_path"] for c in chunks})
    return {"answer": answer, "sources": sources}


def _call_ollama(prompt: str) -> str:
    import requests

    resp = requests.post(
        f"{config.OLLAMA_BASE_URL}/api/generate",
        json={"model": config.OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get("response", "").strip()
