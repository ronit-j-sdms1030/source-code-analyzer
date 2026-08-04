import os

from . import config
from .embeddings import embed_query
from .vectorstore import query_chunks

# Very small in-memory chat history per project, keyed by project_id.
# A production build would persist this alongside project metadata.
_history = {}

SYSTEM_PROMPT = """\
You are an expert software engineer and code reviewer. \
You are given relevant excerpts from a real codebase and must answer the user's question clearly and concisely.

Rules:
- Write a proper, human-readable explanation — do NOT just repeat or paste the code chunks back.
- Synthesize the information from the provided code to give a meaningful answer.
- Mention which file(s) the answer comes from only when it adds useful context.
- If the code chunks are not relevant enough to answer the question, say so honestly.
- Keep answers concise but complete. Use bullet points or numbered lists when helpful.
"""


def _build_prompt(question: str, chunks: list, history: list, file_tree: str = "Unknown") -> list:
    """Returns a messages list for the chat completions API."""
    # Use short relative-style paths to reduce noise in the context
    context_parts = []
    for c in chunks:
        short_path = os.path.basename(c["file_path"])
        context_parts.append(f"--- {short_path} ---\n{c['text']}")
    context = "\n\n".join(context_parts)

    system_prompt = f"{SYSTEM_PROMPT}\n\nRepository File Tree:\n{file_tree}"
    messages = [{"role": "system", "content": system_prompt}]

    # Inject prior conversation turns
    for h in history[-6:]:
        role = "user" if h["role"] == "user" else "assistant"
        messages.append({"role": role, "content": h["text"]})

    # Final user turn with context + question
    user_content = (
        f"Here are the relevant code excerpts from the repository:\n\n"
        f"{context}\n\n"
        f"Question: {question}"
    )
    messages.append({"role": "user", "content": user_content})
    return messages


def answer_question(project_id: str, question: str) -> dict:
    from .vectorstore import get_project_meta
    
    query_vector = embed_query(question)
    results = query_chunks(project_id, query_vector, top_k=5)

    documents = (results.get("documents") or [[]])[0]
    metadatas = (results.get("metadatas") or [[]])[0]
    chunks = [{"text": d, "file_path": m.get("file_path", "unknown")} for d, m in zip(documents, metadatas)]

    # Retrieve project metadata to get the file tree
    meta = get_project_meta(project_id)
    file_tree = meta.get("file_tree", "File tree not available.") if meta else "File tree not available."

    history = _history.setdefault(project_id, [])
    messages = _build_prompt(question, chunks, history, file_tree)

    answer = _call_cloud_llm(messages)

    history.append({"role": "user", "text": question})
    history.append({"role": "assistant", "text": answer})

    sources = sorted({c["file_path"] for c in chunks})
    return {"answer": answer, "sources": sources}


def _call_cloud_llm(messages: list) -> str:
    import requests

    headers = {
        "Authorization": f"Bearer {config.CLOUD_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": config.CLOUD_MODEL,
        "messages": messages,
        "temperature": 0.2,
    }

    resp = requests.post(
        f"{config.CLOUD_API_URL}/chat/completions",
        headers=headers,
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()
