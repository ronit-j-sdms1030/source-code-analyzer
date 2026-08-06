import os

from . import config
from .embeddings import embed_query
from .vectorstore import query_chunks

def _get_history(project_id: str) -> list:
    # Deprecated: use memory.py
    return []

def _append_history(project_id: str, message: dict):
    # Deprecated: use memory.py
    pass

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


def answer_question(project_id: str, question: str, session_id: str) -> dict:
    import time
    from .vectorstore import get_project_meta, query_findings, query_memory, write_memory, query_chunks
    from .memory import get_session_history, append_to_session
    from .intent import classify_intent
    import uuid
    
    history = get_session_history(session_id)
    intent_data = classify_intent(history, question)
    
    intent = intent_data.get("intent", "general_code")
    entities = intent_data.get("entities", {})
    inferred = intent_data.get("inferred_from_history", [])
    
    debug_context = {"intent": intent_data}
    sources = []

    # Build a transparency prefix when the classifier inferred entity values
    # from session history rather than the current message.
    def _inference_prefix() -> str:
        if not inferred:
            return ""
        detail_parts = []
        if "file_path" in inferred and entities.get("file_path"):
            detail_parts.append(f"`{entities['file_path']}`")
        if "cwe_or_keyword" in inferred and entities.get("cwe_or_keyword"):
            detail_parts.append(entities["cwe_or_keyword"])
        if "line_number" in inferred and entities.get("line_number"):
            detail_parts.append(f"line {entities['line_number']}")
        detail = ", ".join(detail_parts) if detail_parts else "some context"
        return (
            f"*(Based on our earlier discussion, I inferred {detail} from the "
            f"conversation history — not from your current message. "
            f"Let me know if you meant a different finding.)*\n\n"
        )
    
    # 1. Handle Long-Term Memory Save
    memory_trigger = entities.get("memory_trigger")
    if memory_trigger:
        mem_id = uuid.uuid4().hex
        write_memory(project_id, mem_id, memory_trigger, embed_query(memory_trigger), {"timestamp": time.time(), "session_id": session_id})
        debug_context["saved_memory"] = memory_trigger

    # 2. Handle Long-Term Memory Retrieve
    long_term_prefs = ""
    if entities.get("requires_long_term_memory"):
        mem_results = query_memory(project_id, embed_query(question), top_k=2)
        mem_docs = (mem_results.get("documents") or [[]])[0]
        if mem_docs:
            long_term_prefs = "User Preferences / Context:\n" + "\n".join(mem_docs)
            debug_context["retrieved_memory"] = mem_docs

    # 3. Handle Retrieval
    chunks = []
    vuln_summary = _get_vulnerability_summary(project_id)
    
    if intent == "specific_finding" or intent == "fix_request":
        where_clause = None
        if entities.get("finding_id"):
            where_clause = {"finding_id": entities["finding_id"]}
        elif entities.get("file_path"):
            conditions = [{"file_path": {"$eq": entities["file_path"]}}]
            if entities.get("line_number"):
                conditions.append({"line_number": {"$eq": entities["line_number"]}})
            elif entities.get("cwe_or_keyword") and entities["cwe_or_keyword"].startswith("CWE-"):
                # Only strictly filter by CWE if it looks like a real CWE ID, since keyword won't exact-match cwe_id.
                conditions.append({"cwe_id": {"$eq": entities["cwe_or_keyword"]}})
            if len(conditions) > 1:
                where_clause = {"$and": conditions}
            else:
                where_clause = conditions[0]
                
        if where_clause:
            results = query_findings(project_id, where=where_clause)
            docs = (results.get("documents") or [[]])[0]
            metas = (results.get("metadatas") or [[]])[0]
            if not docs:
                append_to_session(session_id, {"role": "user", "text": question})
                ans = "I cannot find a finding matching that description."
                append_to_session(session_id, {"role": "assistant", "text": ans})
                return {"answer": ans, "sources": [], "debug_context": debug_context}
            elif len(docs) > 1:
                # Disambiguate
                append_to_session(session_id, {"role": "user", "text": question})
                opts = []
                for m in metas:
                    opts.append(f"Line {m.get('line_number')} ({m.get('cwe_id')})")
                ans = f"There are multiple matching findings in `{entities.get('file_path')}`. Did you mean: " + ", ".join(opts) + "?"
                append_to_session(session_id, {"role": "assistant", "text": ans})
                return {"answer": ans, "sources": [], "debug_context": debug_context}
            else:
                chunks = [{"text": docs[0], "file_path": metas[0].get("file_path", "unknown")}]
                debug_context["retrieved_findings"] = metas
                
                # If inferred, add to debug_context so frontend can surface this
                if inferred:
                    debug_context["inferred_from_history"] = inferred
                
                # If intent == fix_request, bypass normal pipeline
                if intent == "fix_request":
                    return _handle_fix_request(project_id, question, session_id, history, metas[0], debug_context, _inference_prefix())
                    
        else:
            # Not enough info to filter
            ans = "Could you please specify the file path or line number for the finding?"
            append_to_session(session_id, {"role": "user", "text": question})
            append_to_session(session_id, {"role": "assistant", "text": ans})
            return {"answer": ans, "sources": [], "debug_context": debug_context}
            
    elif intent == "general_findings":
        where_clause = None if entities.get("include_false_positives") else {"status": {"$ne": "false_positive"}}
        results = query_findings(project_id, query_vector=embed_query(question), where=where_clause, top_k=5)
        docs = (results.get("documents") or [[]])[0]
        metas = (results.get("metadatas") or [[]])[0]
        chunks = [{"text": d, "file_path": m.get("file_path", "unknown")} for d, m in zip(docs, metas)]
        debug_context["retrieved_findings"] = metas
        
    else:
        # general_code or compare_scans fallback
        search_query = _rewrite_query(history, question)
        results = query_chunks(project_id, embed_query(search_query), top_k=5)
        docs = (results.get("documents") or [[]])[0]
        metas = (results.get("metadatas") or [[]])[0]
        chunks = [{"text": d, "file_path": m.get("file_path", "unknown")} for d, m in zip(docs, metas)]
        debug_context["retrieved_chunks"] = metas

    # Retrieve project metadata to get the file tree
    meta = get_project_meta(project_id)
    file_tree = meta.get("file_tree", "File tree not available.") if meta else "File tree not available."

    # Build prompt
    prompt_vuln_summary = vuln_summary
    if long_term_prefs:
        prompt_vuln_summary += f"\n\n{long_term_prefs}"
        
    messages = _build_prompt(question, chunks, history, file_tree, prompt_vuln_summary)
    answer = _call_cloud_llm(messages)

    # Prepend inference transparency notice if any entities came from history
    prefix = _inference_prefix()
    if prefix:
        answer = prefix + answer
        debug_context["inferred_from_history"] = inferred

    append_to_session(session_id, {"role": "user", "text": question})
    append_to_session(session_id, {"role": "assistant", "text": answer})

    sources = sorted({c["file_path"] for c in chunks})
    return {"answer": answer, "sources": sources, "debug_context": debug_context}

def _handle_fix_request(project_id: str, question: str, session_id: str, history: list, finding_meta: dict, debug_context: dict, inference_prefix: str = "") -> dict:
    from .memory import append_to_session
    import os
    import json
    
    file_path = finding_meta.get("file_path", "")
    full_path = os.path.join(config.REPOS_DIR, project_id, file_path)
    if not os.path.exists(full_path):
        ans = f"Cannot apply fix: file {file_path} not found on disk."
        append_to_session(session_id, {"role": "user", "text": question})
        append_to_session(session_id, {"role": "assistant", "text": ans})
        return {"answer": ans, "sources": [], "debug_context": debug_context}
        
    with open(full_path, "r", encoding="utf-8") as f:
        file_content = f.read()
        
    # Get the full finding details from report
    report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
    message = finding_meta.get("cwe_id", "Unknown vulnerability")
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)
            for r in report_data.get("results", []):
                if r.get("path") == file_path and r.get("start", {}).get("line") == finding_meta.get("line_number"):
                    message = r.get("extra", {}).get("message", message)
                    break
                    
    # Qwen Coder fix generation
    qwen_sys = """\
You are an expert Security Engineer. Fix the following vulnerability in the provided file.
Output a targeted patch or unified diff showing only the specific changes needed, along with a few lines of surrounding context. Do not rewrite the entire file.
"""
    qwen_user = f"Vulnerability Message: {message}\nLine Number: {finding_meta.get('line_number')}\n\nFile Content:\n```\n{file_content}\n```"
    qwen_msg = [{"role": "system", "content": qwen_sys}, {"role": "user", "content": qwen_user}]
    
    diff_output = _call_cloud_llm(qwen_msg, model_name=config.CLOUD_FIX_MODEL)
    
    # Llama 3.1 8B Summarization
    llama_sys = """\
You are a Source Code Analyzer assistant. A dedicated fixing model has just generated a code fix for a vulnerability.
Explain conversationally to the user how the vulnerability was fixed. Do not output code blocks of the entire file, just summarize the approach.
"""
    llama_user = f"Here is the vulnerability: {message}\nHere is the diff of the fix:\n{diff_output}"
    llama_msg = [{"role": "system", "content": llama_sys}, {"role": "user", "content": llama_user}]
    
    llama_summary = _call_cloud_llm(llama_msg)
    
    # Combine — prepend inference transparency notice if applicable
    final_answer = f"{inference_prefix}{llama_summary}\n\n**Proposed Patch:**\n\n{diff_output}"
    
    append_to_session(session_id, {"role": "user", "text": question})
    append_to_session(session_id, {"role": "assistant", "text": final_answer})
    
    return {"answer": final_answer, "sources": [file_path], "debug_context": debug_context}


def _call_cloud_llm(messages: list, model_name: str = None) -> str:
    import requests

    headers = {
        "Authorization": f"Bearer {config.CLOUD_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": model_name or config.CLOUD_MODEL,
        "messages": messages,
        "temperature": 0.0,
    }

    try:
        resp = requests.post(
            f"{config.CLOUD_API_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
    except Exception as e:
        print(f"[LLM Error] {e}", flush=True)
        return "I'm sorry, I'm having trouble analyzing the source code right now."
        
    try:
        content = resp.json()["choices"][0]["message"].get("content")
        if content is None:
            return ""
        return content.strip()
    except Exception as e:
        print(f"[LLM Error - Parsing Response] {e}\nResponse: {resp.text}", flush=True)
        return "I'm sorry, I received an invalid response format from the AI."


def generate_vulnerability_report(project_id: str, finding: dict) -> str:
    """Generates a detailed vulnerability report strictly following a 10-point structure."""
    system_prompt = """\
You are an expert Security Engineer and Penetration Tester.
You are writing a professional vulnerability report for a maintainer based on a static analysis finding.

IMPORTANT: When you detect exposed secrets or hardcoded passwords, you MUST explicitly classify them (e.g., AWS Access Keys, GitHub Tokens, Database Passwords, etc.) and highlight their specific blast radius.

CRITICAL CLASSIFICATION RULES:
0. FALSE POSITIVE CHECK: If the snippet contains 'INSERT_', 'YOUR_', '<>', 'xxxxxx', 'changeme', or is an empty string, it is a FALSE POSITIVE. You MUST NOT generate a vulnerability report. You MUST ONLY output the phrase `**FALSE POSITIVE**` followed by a one-sentence explanation. NOTE: If the value is a realistic mock credential matching a valid format (e.g., an AWS key ending in EXAMPLE), you MUST treat it as a real vulnerability, NOT a false positive.
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

    import re
    # Extract the value from the code snippet if it looks like an assignment
    value = code_snippet
    m = re.search(r'=\s*["\']([^"\']+)["\']', code_snippet)
    if m:
        value = m.group(1)

    is_dummy = False
    dummy_reason = ""
    
    if len(value) >= 8 and (value[:len(value)//2] == value[len(value)//2:]):
        is_dummy = True
        dummy_reason = f"The value `{value}` consists of a repeated substring, which is a common placeholder convention, not a cryptographically random key."
    elif re.search(r'^(1234|abcd|0123|qwerty|asdf)', value.lower()):
        is_dummy = True
        dummy_reason = f"The value `{value}` follows a simple sequential or keyboard pattern, which is a common placeholder convention."
    elif any(x in value.lower() for x in ['insert_', 'your_', '<>', 'xxxxxx', 'changeme', 'placeholder']):
        is_dummy = True
        dummy_reason = f"The value `{value}` contains explicit placeholder text."
    elif len(set(value)) <= 3 and len(value) > 5:
        is_dummy = True
        dummy_reason = f"The value `{value}` has extremely low entropy (only {len(set(value))} unique characters), which is uncharacteristic of a real secret."

    if is_dummy:
        return f"**FALSE POSITIVE**\nThe detected snippet `{code_snippet.strip()}` is clearly a dummy placeholder and not a real hardcoded credential. {dummy_reason} No actual sensitive data is exposed."

    user_content = (
        f"Please generate a detailed vulnerability report for the following finding:\n\n"
        f"**File:** `{file_path}` (Line {line})\n"
        f"**Severity:** {severity}\n"
        f"**Message:** {message}\n\n"
        f"**Code Snippet:**\n```\n{code_snippet}\n```\n\n"
        f"Evaluate the snippet. If it is a real vulnerability, use the 10-point structure. If it is an obvious dummy/placeholder, strictly output the FALSE POSITIVE paragraph."
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
