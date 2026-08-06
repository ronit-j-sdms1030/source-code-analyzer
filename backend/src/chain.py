import os

from . import config
from .embeddings import embed_query
from .vectorstore import query_chunks

def _get_history(project_id: str) -> list:
    import json
    import os
    path = os.path.join(config.REPORTS_DIR, f"{project_id}_history.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return []

def _append_history(project_id: str, message: dict):
    import json
    import os
    history = _get_history(project_id)
    history.append(message)
    path = os.path.join(config.REPORTS_DIR, f"{project_id}_history.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

SYSTEM_PROMPT = """\
You are a Source Code Analyzer and Reviewer, not a large language model. \
You are given relevant excerpts from a real codebase and must answer the user's question clearly and concisely.

You also have access to an automated Semgrep vulnerability report for this project. If the user asks about security issues, reference this report to provide accurate answers.

Rules:
- Write a proper, human-readable explanation — do NOT just repeat or paste the code chunks back.
- Synthesize the information from the provided code and vulnerability report to give a meaningful answer.
- Mention which file(s) the answer comes from only when it adds useful context.
- If the code chunks and report are not relevant enough to answer the question, say so honestly.
- Keep answers concise but complete. Use bullet points or numbered lists when helpful.
- Treat the words "risk" and "risks" as completely synonymous with "vulnerability" and "vulnerabilities".
- If the user asks what vulnerabilities/risks exist or for a list of them, you MUST list EVERY single vulnerability from the Vulnerability Report (do not group them, do not skip any).
- When listing vulnerabilities/risks, you MUST always order them by severity: High first, then Medium, then Low.
- If the user asks about a specific severity (e.g., high, medium, or low risk), you MUST state the exact count of those specific vulnerabilities found in the report before listing them. When listing a filtered subset, renumber the list to start from 1.
- ALWAYS rely on the `Vulnerability Report` section provided in this system prompt for the current state of vulnerabilities, EXCEPT when the user asks what was just fixed.
- CRITICAL EXCEPTION: If the user explicitly asks "what was fixed", "which vulnerabilities were just fixed", or similar, you MUST read the conversation history for recent 'Fix Applied' messages. Do NOT look at the current Vulnerability Report (which will be clean). Summarize the fixes you see in the chat history. Do not claim there are no vulnerabilities to fix.
- If the user asks you to fix a vulnerability, you MUST inform them that fixes can only be applied through the "View Report" modal. Instruct them to open the Vulnerability Report and use the "Evaluate Fix" workflow. Do not attempt to output any fix buttons or fix tokens.
"""
def _get_vulnerability_summary(project_id: str) -> str:
    import json
    import os
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
        for i, r in enumerate(results, start=1):
            sev = r.get("extra", {}).get("severity", "Unknown").upper()
            if sev == "ERROR":
                sev_label = "High"
            elif sev == "WARNING":
                sev_label = "Medium"
            elif sev == "INFO":
                sev_label = "Low"
            else:
                sev_label = sev
                
            path = r.get("path", "Unknown")
            parts = path.split(f"/{project_id}/")
            if len(parts) > 1:
                path = parts[-1]
            else:
                path = os.path.basename(path)
                
            line = r.get("start", {}).get("line", "?")
            msg = r.get("extra", {}).get("message", "No message").split('\n')[0]
            lines.append(f"{i}. [{sev_label} Risk] {path}:{line} - {msg}")
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


def _rewrite_query(history: list, question: str) -> str:
    if not history:
        return question
    
    prompt = """\
Given the following conversation history and the user's latest question, rewrite the question so that it is a standalone query capable of being used for a semantic search over a codebase.
Do not answer the question. Only output the rewritten search query. If the question is already standalone, just output the original question.
"""
    messages = [{"role": "system", "content": prompt}]
    for h in history[-4:]:
        role = "user" if h["role"] == "user" else "assistant"
        # truncate long assistant responses to save context/latency
        text = h["text"]
        if len(text) > 500:
            text = text[:500] + "..."
        messages.append({"role": role, "content": text})
        
    messages.append({"role": "user", "content": question})
    
    rewritten = _call_cloud_llm(messages).strip()
    if rewritten.startswith('"') and rewritten.endswith('"'):
        rewritten = rewritten[1:-1]
    return rewritten


def answer_question(project_id: str, question: str) -> dict:
    from .vectorstore import get_project_meta
    
    history = _get_history(project_id)
    search_query = _rewrite_query(history, question)
    
    query_vector = embed_query(search_query)
    results = query_chunks(project_id, query_vector, top_k=5)

    documents = (results.get("documents") or [[]])[0]
    metadatas = (results.get("metadatas") or [[]])[0]
    chunks = [{"text": d, "file_path": m.get("file_path", "unknown")} for d, m in zip(documents, metadatas)]

    # Retrieve project metadata to get the file tree
    meta = get_project_meta(project_id)
    file_tree = meta.get("file_tree", "File tree not available.") if meta else "File tree not available."

    vuln_summary = _get_vulnerability_summary(project_id)

    messages = _build_prompt(question, chunks, history, file_tree, vuln_summary)

    answer = _call_cloud_llm(messages)

    _append_history(project_id, {"role": "user", "text": question})
    _append_history(project_id, {"role": "assistant", "text": answer})

    sources = sorted({c["file_path"] for c in chunks})
    return {"answer": answer, "sources": sources}


def _call_cloud_llm(messages: list, model_name: str = None) -> str:
    import requests

    headers = {
        "Authorization": f"Bearer {config.CLOUD_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model_name or config.CLOUD_MODEL,
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

IMPORTANT: When you detect exposed secrets or hardcoded passwords, you MUST explicitly classify them (e.g., AWS Access Keys, GitHub Tokens, Database Passwords, etc.) and highlight their specific blast radius.

CRITICAL CLASSIFICATION RULES:
0. FALSE POSITIVE CHECK: If the snippet contains 'INSERT_', 'YOUR_', '<>', 'xxxxxx', 'changeme', or is an empty string, it is a FALSE POSITIVE. You MUST NOT generate a vulnerability report. You MUST ONLY output the phrase `**FALSE POSITIVE**` followed by a one-sentence explanation.
1. VERIFY FIRST & SHOW EVIDENCE: Do not assume Semgrep is correct. Read the code snippet. If it is a real secret, you MUST quote the exact (redacted) variable name (e.g., `API_KEY=...`) to prove it is a live secret.
2. CWE ID: Pick the MOST SPECIFIC match based on actual code behavior (e.g., do not confuse CWE-798 Hardcoded Credentials with CWE-200 Sensitive Data Exposure).
3. CVSS 3.1 & MATH: Calculate the exact CVSS 3.1 vector string by walking through AV, AC, PR, UI, S, C, I, A. Ensure you use the exact keys, for example Scope is `S:C` or `S:U` (NOT `SC:C`). Your numerical score MUST logically and mathematically match the vector. For example, if PR:H (High Privileges Required), you cannot score a 10.0. Ensure your impact logically matches the privileges required.
4. ENVIRONMENT CONTEXT: You must heavily weigh the environment based on the file path. A secret in a `.env.dev` or `.test` file has significantly lower severity than production code. Consider whether the file is tracked in git or just local.
5. CONCRETE PoC: Your Proof of Concept must not be generic bullet points. Show actual (redacted) data formats or a specific, concrete exploitation scenario (like a specific curl command).

You MUST strictly follow this 10-point structure (UNLESS it is a false positive):

If you determined this is a FALSE POSITIVE based on the rules above, you MUST NOT use the 10-point structure. Instead, simply write a 1-paragraph explanation of why it is a false positive, starting with the exact text `**FALSE POSITIVE**`.
Example:
**FALSE POSITIVE**
The detected snippet `password = "INSERT_YOUR_PASSWORD_HERE"` is clearly a dummy placeholder and not a real hardcoded credential. No actual sensitive data is exposed.

If it is a real vulnerability, follow this structure exactly:

1. Clear, specific title
2. Summary (2-3 sentences)
3. Affected component (File path, line numbers)
4. Vulnerability classification (CWE ID exact match, CVSS 3.1 vector string, exact mathematically correct score, and OWASP category)
5. Detailed technical description (How it works, root cause)
6. Proof of Concept (PoC) (Concrete scenario, not generic bullets)
7. Impact assessment (What an attacker could achieve based on actual reachability and environment)
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
        f"**Code Snippet:**\n```\n{code_snippet}\n```\n\n"
        f"Remember to classify this correctly. If it is an obvious placeholder or dummy value, strictly output ONLY a FALSE POSITIVE paragraph as instructed."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]

    return _call_cloud_llm(messages)


def apply_auto_fix(project_id: str, finding: dict) -> dict:
    """Generates a fix for the vulnerability and applies it directly to the file on disk."""
    import os
    file_path = finding.get("path", "")
    if not file_path:
        raise ValueError("Finding does not contain a file path.")
    
    full_path = os.path.join(config.REPOS_DIR, project_id, file_path)
    if not os.path.exists(full_path):
        raise ValueError(f"File not found on disk: {file_path}")
        
    with open(full_path, "r", encoding="utf-8") as f:
        file_content = f.read()
        
    message = finding.get("extra", {}).get("message", "No message provided")
    line = finding.get("start", {}).get("line", "?")
    
    system_prompt = """\
You are an expert Security Engineer and software developer.
You will be provided with the full content of a source code file that contains a security vulnerability.
Your task is to fix the vulnerability by rewriting the entire file securely.

Rules:
1. First, write a brief 1-3 sentence description of exactly how you fixed the vulnerability.
2. Then, output the ENTIRE, fully fixed file contents inside a standard markdown code block.
3. You MUST output the COMPLETE file from top to bottom. Do NOT truncate the file or use placeholders like `// ... rest of code`.

Security Guidelines:
- Dockerfile Root Vulnerabilities: If fixing a container running as root, you MUST create a non-root user (e.g., `RUN useradd -m appuser`) AND explicitly switch to it using the `USER appuser` directive.
- CDN Integrity Hashes (SRI): If fixing a missing `integrity` attribute, DO NOT add a fake or hallucinated hash. If you do not know the exact real hash, simply write a comment in the code (e.g. `<!-- TODO: Add SRI hash -->`).

Format your response EXACTLY like this:

Brief description of the fix.

```[language]
[ENTIRE fully fixed file contents here]
```
"""
    
    user_content = (
        f"Vulnerability Message: {message}\n"
        f"Line Number: {line}\n\n"
        f"File Content:\n```\n{file_content}\n```"
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]
    
    response = _call_cloud_llm(messages, model_name=config.CLOUD_FIX_MODEL)
    
    # Extract the description and the code block from the response
    # Extract the description and the code block from the response
    parts = response.split("```")
    if len(parts) >= 3:
        description = parts[0].strip() or "Fixed the vulnerability."
        lines = parts[1].split("\n")
        # Remove language identifier if present
        if lines and not lines[0].strip().startswith(("import", "def", "class", "/", "*", "<")):
            lines = lines[1:]
        fixed_content = "\n".join(lines).strip()
        
        # Sanity check: don't wipe the file if the model only generated a tiny snippet
        if len(fixed_content) < len(file_content) * 0.2:
            description = f"**Autofix failed:** The AI output a partial snippet instead of the full file.\n\n**Vulnerability:** {message}\n\n**Manual Solution Suggested by AI:**\n{response}"
            fixed_content = file_content
    else:
        description = f"**Autofix failed:** The AI did not output a valid code block.\n\n**Vulnerability:** {message}\n\n**Manual Solution Suggested by AI:**\n{response}"
        fixed_content = file_content
        
    # Write the fixed content back to disk
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(fixed_content)
        
    import difflib
    diff = list(difflib.unified_diff(
        file_content.splitlines(keepends=True),
        fixed_content.splitlines(keepends=True),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}"
    ))
    diff_text = "".join(diff)
    
    additions = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
    deletions = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
    
    # Strip any dangling trailing prompts from the description
    description = description.replace("Fixed File Content:", "").strip()
    
    if diff_text:
        final_message = f"{description}\n\n**Changes in `{file_path}` (+{additions}, -{deletions}):**\n```diff\n{diff_text}\n```"
    else:
        final_message = description
        
    return {"status": "success", "file": file_path, "message": final_message}


def evaluate_auto_fix(project_id: str, finding: dict) -> dict:
    """Evaluates the fix for a vulnerability, returning the risk assessment and fixed code without applying it."""
    import os
    file_path = finding.get("path", "")
    if not file_path:
        raise ValueError("Finding does not contain a file path.")
    
    full_path = os.path.join(config.REPOS_DIR, project_id, file_path)
    if not os.path.exists(full_path):
        raise ValueError(f"File not found on disk: {file_path}")
        
    with open(full_path, "r", encoding="utf-8") as f:
        file_content = f.read()
        
    message = finding.get("extra", {}).get("message", "No message provided")
    line = finding.get("start", {}).get("line", "?")
    
    system_prompt = """\
You are an expert Security Engineer and software developer.
You will be provided with the full content of a source code file that contains a security vulnerability.
Your task is to fix the vulnerability by rewriting the entire file securely, BUT FIRST you must evaluate what new vulnerabilities or side-effects this fix might lead to.

Rules:
1. First, write a detailed Markdown section starting with `### Risk Assessment`. 
2. Inside the Risk Assessment, you MUST explicitly identify and list the EXACT vulnerabilities (risks) that will be caused or introduced if the user fixes this error. Format this as a warning (e.g., `> [!WARNING]`).
3. Explain any other potential side effects of your proposed fix (e.g., backward compatibility, deployment issues).
4. Then, output the ENTIRE, fully fixed file contents inside a standard markdown code block.
5. You MUST output the COMPLETE file from top to bottom. Do NOT truncate the file or use placeholders like `// ... rest of code`.

Format your response EXACTLY like this:

### Risk Assessment
> [!WARNING]
> **Potential New Vulnerabilities:** 
> - [List exact vulnerabilities here...]

[Your detailed explanation of other side effects...]

```[language]
[ENTIRE fully fixed file contents here]
```
"""
    
    user_content = (
        f"Vulnerability Message: {message}\n"
        f"Line Number: {line}\n\n"
        f"File Content:\n```\n{file_content}\n```"
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]
    
    response = _call_cloud_llm(messages, model_name=config.CLOUD_FIX_MODEL)
    
    parts = response.split("```")
    if len(parts) >= 3:
        risk_assessment = parts[0].strip() or "No risk assessment provided."
        lines = parts[1].split("\n")
        if lines and not lines[0].strip().startswith(("import", "def", "class", "/", "*", "<")):
            lines = lines[1:]
        fixed_content = "\n".join(lines).strip()
        
        if len(fixed_content) < len(file_content) * 0.2:
            return {
                "error": "The AI output a partial snippet instead of the full file.",
                "risk_assessment": risk_assessment
            }
            
        return {
            "risk_assessment": risk_assessment,
            "fixed_content": fixed_content
        }
    else:
        return {
            "error": "The AI did not output a valid code block.",
            "risk_assessment": response
        }
