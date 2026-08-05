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

You also have access to an automated Semgrep vulnerability report for this project. If the user asks about security issues, reference this report to provide accurate answers.

Rules:
- Write a proper, human-readable explanation — do NOT just repeat or paste the code chunks back.
- Synthesize the information from the provided code and vulnerability report to give a meaningful answer.
- Mention which file(s) the answer comes from only when it adds useful context.
- If the code chunks and report are not relevant enough to answer the question, say so honestly.
- Keep answers concise but complete. Use bullet points or numbered lists when helpful.
"""
def _get_vulnerability_summary(project_id: str) -> str:
    import json
    report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
    if not os.path.exists(report_path):
        return "No vulnerability report available."
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        results = data.get("results", [])
        if not results:
            return "No vulnerabilities found."
        
        lines = []
        for r in results:
            sev = r.get("extra", {}).get("severity", "Unknown")
            path = r.get("path", "Unknown")
            line = r.get("start", {}).get("line", "?")
            msg = r.get("extra", {}).get("message", "No message").split('\n')[0]
            lines.append(f"- [{sev}] {path}:{line} - {msg}")
        return "\n".join(lines)
    except Exception:
        return "Error reading vulnerability report."


def _build_prompt(question: str, chunks: list, history: list, file_tree: str = "Unknown", vuln_summary: str = "") -> list:
    """Returns a messages list for the chat completions API."""
    # Use short relative-style paths to reduce noise in the context
    context_parts = []
    for c in chunks:
        short_path = os.path.basename(c["file_path"])
        context_parts.append(f"--- {short_path} ---\n{c['text']}")
    context = "\n\n".join(context_parts)

    system_prompt = f"{SYSTEM_PROMPT}\n\nRepository File Tree:\n{file_tree}\n\nVulnerability Report:\n{vuln_summary}"
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

    vuln_summary = _get_vulnerability_summary(project_id)

    history = _history.setdefault(project_id, [])
    messages = _build_prompt(question, chunks, history, file_tree, vuln_summary)

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


def generate_vulnerability_report(project_id: str, finding: dict) -> str:
    """Generates a detailed vulnerability report strictly following a 10-point structure."""
    system_prompt = """\
You are an expert Security Engineer and Penetration Tester.
You are writing a professional vulnerability report for a maintainer based on a static analysis finding.

IMPORTANT: When you detect exposed secrets or hardcoded passwords, you MUST explicitly classify them (e.g., AWS Access Keys, GitHub Tokens, Database Passwords, etc.) and highlight their specific blast radius, rather than grouping them generically.
You MUST strictly follow this 10-point structure:

1. Clear, specific title
2. Summary (2-3 sentences)
3. Affected component (File path, line numbers)
4. Vulnerability classification (CWE ID, CVSS estimate, OWASP category)
5. Detailed technical description (How it works, root cause)
6. Proof of Concept (PoC) (Minimal reproducible steps or exploit payload based on the code)
7. Impact assessment (What an attacker could achieve)
8. Suggested fix (Pseudocode or secure approach)
9. Timeline (Note that this was discovered via automated scanning today)
10. Contact info / credit preference (Credit: AI Source Code Analyzer)

Format the report using Markdown. Keep the tone professional, objective, and calibrated to the severity.
"""

    file_path = finding.get("path", "Unknown file")
    line = finding.get("start", {}).get("line", "Unknown line")
    message = finding.get("extra", {}).get("message", "No message provided")
    severity = finding.get("extra", {}).get("severity", "Unknown")
    code_snippet = finding.get("extra", {}).get("lines", "")

    user_content = (
        f"Please generate a detailed vulnerability report for the following finding:\n\n"
        f"**File:** `{file_path}` (Line {line})\n"
        f"**Severity:** {severity}\n"
        f"**Message:** {message}\n\n"
        f"**Code Snippet:**\n```\n{code_snippet}\n```"
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]

    return _call_cloud_llm(messages)

