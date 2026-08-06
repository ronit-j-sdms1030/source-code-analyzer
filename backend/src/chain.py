import os

from . import config
from .embeddings import embed_query
from .vectorstore import query_chunks

# Well-known vendor-published documentation/example keys that are deliberately
# fake and safe. Published by the vendor in their own official documentation.
# The canonical AWS example key (AKIAIOSFODNN7EXAMPLE) is the primary case;
# include close variants and other vendors' official placeholder values.
_KNOWN_VENDOR_EXAMPLE_KEYS = {
    # AWS — official AWS documentation example keys
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # GCP — placeholder service account keys used in GCP documentation
    "YOUR_API_KEY",
    "AIzaSyD-EXAMPLE-KEY",
    # Stripe — test mode keys (always start with sk_test_ or pk_test_)
    "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "pk_test_" + "TYooMQauvdEDq54NiTphI7jx",
    # GitHub — documented example PATs
    "ghp_EXAMPLE000000000000000000000000000",
    # Twilio — documented example SID / Auth token
    "AC" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "your_auth_token",
}

# ── AUTHORITATIVE OWASP TOP 10 (2021) ────────────────────────────────────────
# Keyed by lowercase keyword fragments for fuzzy matching against LLM output.
# Values are the exact canonical label strings the model must output.
_OWASP_2021 = {
    "broken access control":              "A01:2021 \u2013 Broken Access Control",
    "cryptographic failure":              "A02:2021 \u2013 Cryptographic Failures",
    "sensitive data exposure":            "A02:2021 \u2013 Cryptographic Failures",
    "injection":                          "A03:2021 \u2013 Injection",
    "sqli":                               "A03:2021 \u2013 Injection",
    "command injection":                  "A03:2021 \u2013 Injection",
    "xss":                                "A03:2021 \u2013 Injection",
    "cross-site scripting":               "A03:2021 \u2013 Injection",
    "ssti":                               "A03:2021 \u2013 Injection",
    "template injection":                 "A03:2021 \u2013 Injection",
    "insecure design":                    "A04:2021 \u2013 Insecure Design",
    "security misconfiguration":          "A05:2021 \u2013 Security Misconfiguration",
    "configuration":                      "A05:2021 \u2013 Security Misconfiguration",
    "hardcoded":                          "A05:2021 \u2013 Security Misconfiguration",
    "hardcoded credential":               "A05:2021 \u2013 Security Misconfiguration",
    "exposed secret":                     "A05:2021 \u2013 Security Misconfiguration",
    "misconfiguration":                   "A05:2021 \u2013 Security Misconfiguration",
    "vulnerable and outdated":            "A06:2021 \u2013 Vulnerable and Outdated Components",
    "outdated component":                 "A06:2021 \u2013 Vulnerable and Outdated Components",
    "identification and authentication":  "A07:2021 \u2013 Identification and Authentication Failures",
    "authentication failure":             "A07:2021 \u2013 Identification and Authentication Failures",
    "broken authentication":              "A07:2021 \u2013 Identification and Authentication Failures",
    "software and data integrity":        "A08:2021 \u2013 Software and Data Integrity Failures",
    "insecure deserialization":           "A08:2021 \u2013 Software and Data Integrity Failures",
    "deserialization":                    "A08:2021 \u2013 Software and Data Integrity Failures",
    "security logging":                   "A09:2021 \u2013 Security Logging and Monitoring Failures",
    "monitoring failure":                 "A09:2021 \u2013 Security Logging and Monitoring Failures",
    "server-side request forgery":        "A10:2021 \u2013 Server-Side Request Forgery (SSRF)",
    "ssrf":                               "A10:2021 \u2013 Server-Side Request Forgery (SSRF)",
}

# Exact valid labels (for output-side validation after LLM generates a category)
_OWASP_2021_VALID = set(_OWASP_2021.values())


def _compute_cvss31_score(vector: str) -> float | None:
    """Compute the real CVSS 3.1 base score from a vector string.

    Implements the exact CVSS 3.1 formula from first.org/cvss/v3.1/specification-document.
    The LLM is NOT trusted to compute this — it only outputs the vector string,
    and this function produces the authoritative score.

    Returns the score (0.0–10.0, rounded up to 1 decimal) or None on parse error.
    """
    import math, re

    AV_W  = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
    AC_W  = {'L': 0.77, 'H': 0.44}
    PR_WU = {'N': 0.85, 'L': 0.62, 'H': 0.27}  # Scope Unchanged
    PR_WC = {'N': 0.85, 'L': 0.68, 'H': 0.50}  # Scope Changed
    UI_W  = {'N': 0.85, 'R': 0.62}
    CIA_W = {'N': 0.00, 'L': 0.22, 'H': 0.56}

    # Strip optional "CVSS:3.1/" prefix
    v = re.sub(r'^CVSS:3\.1/', '', vector.strip())

    try:
        parts = dict(p.split(':') for p in v.split('/'))
        s  = parts['S']
        av = AV_W[parts['AV']]
        ac = AC_W[parts['AC']]
        pr = (PR_WC if s == 'C' else PR_WU)[parts['PR']]
        ui = UI_W[parts['UI']]
        c  = CIA_W[parts['C']]
        i  = CIA_W[parts['I']]
        a  = CIA_W[parts['A']]
    except (KeyError, ValueError):
        return None

    isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

    if s == 'U':
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if s == 'U':
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)

    # CVSS 3.1 uses "round up" (ceiling to 1 decimal)
    return math.ceil(raw * 10) / 10.0


def _resolve_owasp_category(llm_owasp_text: str) -> str | None:
    """Given whatever OWASP text the LLM produced, return the correct 2021 label.

    Strategy:
    1. If it already matches a valid 2021 label exactly, return it as-is.
    2. Otherwise, scan the keyword table for the best fuzzy match.
    3. Return None if nothing matches (caller will leave text unchanged).
    """
    if not llm_owasp_text:
        return None
    clean = llm_owasp_text.strip()
    if clean in _OWASP_2021_VALID:
        return clean  # Already correct
    lower = clean.lower()
    # Longest-match wins to avoid "injection" matching "command injection" when the
    # full phrase is present
    best_key, best_label = "", None
    for kw, label in _OWASP_2021.items():
        if kw in lower and len(kw) > len(best_key):
            best_key, best_label = kw, label
    return best_label


def _postprocess_report(report_text: str) -> str:
    """Post-process a raw LLM vulnerability report to enforce correctness of:

    1. CVSS 3.1 score  — extracted from the vector string, recomputed via formula,
                         then the LLM's claimed score is replaced with the real one.
    2. OWASP category  — validated against the authoritative 2021 list and corrected
                         if the LLM produced a wrong year (2017), paraphrased name,
                         or invented a non-existent category/year combination.

    This function is the final quality gate: it runs AFTER the LLM call and BEFORE
    the report reaches the user, ensuring classification metadata is always accurate
    regardless of LLM output quality.
    """
    import re

    text = report_text

    # ── 1. CVSS SCORE CORRECTION ─────────────────────────────────────────────
    # Find the CVSS 3.1 vector string in the report.
    vector_re = re.compile(
        r'(CVSS:3\.1/)?(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[CU]/C:[NLH]/I:[NLH]/A:[NLH])',
        re.IGNORECASE
    )
    vec_match = vector_re.search(text)
    if vec_match:
        raw_vector = vec_match.group(0).upper()
        computed = _compute_cvss31_score(raw_vector)
        if computed is not None:
            severity = "Critical" if computed >= 9.0 else \
                       "High"     if computed >= 7.0 else \
                       "Medium"   if computed >= 4.0 else "Low"
            # Pattern allows for markdown asterisks anywhere around the label/colon
            score_re = re.compile(
                r'((?:CVSS[\s\*]*3\.1[\s\*]*)?(?:Base[\s\*]*)?Score[\s\*]*[:\-][\s\*]*)(\[COMPUTED\]|\d+\.\d+)[\s\*]*(\([^)]+\))?',
                re.IGNORECASE
            )
            replacement = rf'\g<1>{computed} ({severity})'
            new_text = score_re.sub(replacement, text)
            if new_text != text:
                text = new_text
            else:
                # Score wasn't found in expected format — append a correction note
                text = text.replace(
                    raw_vector,
                    f"{raw_vector} *(Computed Score: **{computed}** ({severity}))*"
                )

    # ── 2. OWASP CATEGORY CORRECTION ─────────────────────────────────────────
    # Find whatever the LLM wrote after "OWASP" or "OWASP Category:"
    owasp_re = re.compile(
        r'(OWASP[\s\*]*(?:Top[\s\*]*10[\s\*]*)?(?:Category|Label|Classification)?[\s\*]*[:\u2013\-][\s\*]*)([^\n]+)',
        re.IGNORECASE
    )
    owasp_match = owasp_re.search(text)
    if owasp_match:
        llm_owasp = owasp_match.group(2).strip()
        corrected = _resolve_owasp_category(llm_owasp)
        if corrected and corrected != llm_owasp:
            text = text[:owasp_match.start(2)] + corrected + text[owasp_match.end(2):]

    return text



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
    
    # ── Ordinal and Plural Resolution Logic ──
    import re
    ordinal_idx = None
    resolved_findings = []
    
    ordinal_match = re.search(r'(?:risk|finding|issue|number|#)\s*(\d+)', question.lower())
    if ordinal_match:
        ordinal_idx = int(ordinal_match.group(1)) - 1
    else:
        text_ordinals = {"first": 1, "1st": 1, "second": 2, "2nd": 2, "third": 3, "3rd": 3, "fourth": 4, "4th": 4, "fifth": 5, "5th": 5}
        for word, num in text_ordinals.items():
            if re.search(rf'\b{word}\b', question.lower()):
                ordinal_idx = num - 1
                break

    is_plural_or_all = any(w in question.lower() for w in ["risks", "findings", "issues", "all of them", "these", "all fixes", "them", "all"])
    is_fix = any(w in question.lower() for w in ["fix", "patch", "resolve", "correct", "repair"])

    if ordinal_idx is not None or (is_plural_or_all and is_fix):
        last_listed = None
        for msg in reversed(history):
            if msg.get("role") == "assistant" and "listed_findings" in msg:
                last_listed = msg["listed_findings"]
                break
        
        if last_listed:
            if ordinal_idx is not None:
                if 0 <= ordinal_idx < len(last_listed):
                    resolved_findings = [last_listed[ordinal_idx]]
                else:
                    ans = f"You referred to finding number {ordinal_idx + 1}, but I only listed {len(last_listed)} findings. Could you clarify?"
                    append_to_session(session_id, {"role": "user", "text": question})
                    append_to_session(session_id, {"role": "assistant", "text": ans})
                    return {"answer": ans, "sources": [], "debug_context": {}}
            else:
                resolved_findings = last_listed
        else:
            ans = "I'm not sure which finding you are referring to. Could you ask me to list the risks first?"
            append_to_session(session_id, {"role": "user", "text": question})
            append_to_session(session_id, {"role": "assistant", "text": ans})
            return {"answer": ans, "sources": [], "debug_context": {}}

    if resolved_findings:
        if is_fix and len(resolved_findings) > 1:
            return _handle_multiple_fix_requests(project_id, question, session_id, history, resolved_findings, {"intent": {"intent": "fix_request"}})
        else:
            intent_data = {
                "intent": "fix_request" if is_fix else "specific_finding", 
                "entities": {"finding_id": resolved_findings[0].get("finding_id")}
            }
    else:
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
        elif entities.get("file_path") or entities.get("severity") or (entities.get("cwe_or_keyword") and entities["cwe_or_keyword"].startswith("CWE-")):
            conditions = []
            if entities.get("file_path"):
                conditions.append({"file_path": {"$eq": entities["file_path"]}})
            if entities.get("severity"):
                sev = entities["severity"].upper()
                if sev == "HIGH": sev = "ERROR"
                elif sev == "MEDIUM": sev = "WARNING"
                elif sev == "LOW": sev = "INFO"
                conditions.append({"severity": {"$eq": sev}})
            if entities.get("line_number"):
                conditions.append({"line_number": {"$eq": entities["line_number"]}})
            if entities.get("cwe_or_keyword") and entities["cwe_or_keyword"].startswith("CWE-"):
                conditions.append({"cwe_id": {"$eq": entities["cwe_or_keyword"]}})
                
            if len(conditions) > 1:
                where_clause = {"$and": conditions}
            elif len(conditions) == 1:
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
                    opts.append(f"`{m.get('file_path')}` (Line {m.get('line_number')})")
                if entities.get('file_path'):
                    ans = f"There are multiple matching findings in `{entities.get('file_path')}`. Did you mean: " + ", ".join(opts[:3]) + ("?" if len(opts) <= 3 else ", ...?")
                else:
                    ans = f"There are multiple matching findings. Did you mean: " + ", ".join(opts[:3]) + ("?" if len(opts) <= 3 else ", ...?")
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
    
    asst_msg = {"role": "assistant", "text": answer}
    if intent == "general_findings" and debug_context.get("retrieved_findings"):
        asst_msg["listed_findings"] = debug_context["retrieved_findings"]
    append_to_session(session_id, asst_msg)

    sources = sorted({c["file_path"] for c in chunks})
    return {"answer": answer, "sources": sources, "debug_context": debug_context}

def _handle_fix_request(project_id: str, question: str, session_id: str, history: list, finding_meta: dict, debug_context: dict, inference_prefix: str = "") -> dict:
    from .memory import append_to_session
    import os
    import json
    import re

    # ── FALSE POSITIVE GATE ──────────────────────────────────────────────────
    # If this finding was already classified as a false positive, do not
    # generate fix content. Return an explanation instead.
    fp_status = finding_meta.get("status", "") or ""
    fp_message = finding_meta.get("message", "") or ""
    if fp_status == "false_positive" or "FALSE POSITIVE" in fp_message.upper():
        ans = (
            "⚠️ **No action needed.** This finding was already classified as a "
            "**false positive** — it is not a real vulnerability. No fix needs to be applied."
        )
        append_to_session(session_id, {"role": "user", "text": question})
        append_to_session(session_id, {"role": "assistant", "text": ans})
        return {"answer": ans, "sources": [], "debug_context": debug_context}
    # ── END GATE ─────────────────────────────────────────────────────────────

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


def _handle_multiple_fix_requests(project_id: str, question: str, session_id: str, history: list, finding_metas: list, debug_context: dict) -> dict:
    from .memory import append_to_session
    import os
    import json
    
    append_to_session(session_id, {"role": "user", "text": question})
    
    combined_answers = []
    sources = set()
    
    for idx, finding_meta in enumerate(finding_metas):
        title = f"### Fix for Finding {idx + 1} (`{finding_meta.get('file_path')}`)\n\n"
        
        fp_status = finding_meta.get("status", "") or ""
        fp_message = finding_meta.get("message", "") or ""
        if fp_status == "false_positive" or "FALSE POSITIVE" in fp_message.upper():
            combined_answers.append(title + "⚠️ **No action needed.** This finding was classified as a false positive.")
            continue
            
        file_path = finding_meta.get("file_path", "")
        full_path = os.path.join(config.REPOS_DIR, project_id, file_path)
        if not os.path.exists(full_path):
            combined_answers.append(title + f"Cannot apply fix: file {file_path} not found on disk.")
            continue
            
        with open(full_path, "r", encoding="utf-8") as f:
            file_content = f.read()
            
        report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
        message = finding_meta.get("cwe_id", "Unknown vulnerability")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
                for r in report_data.get("results", []):
                    if r.get("path") == file_path and r.get("start", {}).get("line") == finding_meta.get("line_number"):
                        message = r.get("extra", {}).get("message", message)
                        break
                        
        qwen_sys = "You are an expert Security Engineer. Fix the following vulnerability in the provided file.\nOutput a targeted patch or unified diff showing only the specific changes needed, along with a few lines of surrounding context. Do not rewrite the entire file."
        qwen_user = f"Vulnerability Message: {message}\nLine Number: {finding_meta.get('line_number')}\n\nFile Content:\n```\n{file_content}\n```"
        qwen_msg = [{"role": "system", "content": qwen_sys}, {"role": "user", "content": qwen_user}]
        diff_output = _call_cloud_llm(qwen_msg, model_name=config.CLOUD_FIX_MODEL)
        
        llama_sys = "You are a Source Code Analyzer assistant. A dedicated fixing model has just generated a code fix for a vulnerability.\nExplain conversationally to the user how the vulnerability was fixed. Do not output code blocks of the entire file, just summarize the approach."
        llama_user = f"Here is the vulnerability: {message}\nHere is the diff of the fix:\n{diff_output}"
        llama_msg = [{"role": "system", "content": llama_sys}, {"role": "user", "content": llama_user}]
        llama_summary = _call_cloud_llm(llama_msg)
        
        combined_answers.append(title + f"{llama_summary}\n\n**Proposed Patch:**\n\n{diff_output}")
        sources.add(file_path)
        
    final_answer = "\n\n---\n\n".join(combined_answers)
    append_to_session(session_id, {"role": "assistant", "text": final_answer})
    
    return {"answer": final_answer, "sources": sorted(sources), "debug_context": debug_context}


def _is_false_positive(code_snippet: str, message: str) -> bool:
    """Shared false-positive gate used by all content-generation paths.

    Returns True ONLY for secrets-class findings whose snippet looks like
    a placeholder. Non-secrets vuln classes (SSTI, SQLi, XSS, etc.) always
    return False — they are never false positives.
    """
    import re
    secrets_keywords = ['secret', 'password', 'token', 'credential', 'api.key', 'apikey', 'hardcoded']
    if not any(kw in message.lower() for kw in secrets_keywords):
        return False  # Not a secrets finding — skip the placeholder gate entirely

    value = code_snippet
    m = re.search(r'=\s*["\']([^"\']+)["\']', code_snippet)
    if m:
        value = m.group(1)

    # Well-known vendor documentation placeholder keys
    if value in _KNOWN_VENDOR_EXAMPLE_KEYS:
        return True
    if len(value) >= 8 and (value[:len(value)//2] == value[len(value)//2:]):
        return True
    if re.search(r'^(1234|abcd|0123|qwerty|asdf)', value.lower()):
        return True
    if any(x in value.lower() for x in ['insert_', 'your_', '<>', 'xxxxxx', 'changeme', 'placeholder']):
        return True
    if len(set(value)) <= 3 and len(value) > 5:
        return True
    return False


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
    """Generates a detailed vulnerability report strictly following a 10-point structure.

    Three pipeline-wide fixes applied here (apply to ALL finding types, not just secrets):
    1. FALSE POSITIVE decision is made exclusively in Python before the LLM is called.
       The LLM is never asked to decide FALSE POSITIVE — it only ever sees real findings.
    2. CWE selection is constrained via a lookup table injected into the user message,
       eliminating free-recall errors (e.g. CWE-200 for SSTI instead of CWE-1336).
    3. CVSS math rules are enforced with explicit constraints (e.g. PR:H caps score at 8.0).
    """
    system_prompt = """\
You are an expert Security Engineer and Penetration Tester.
You are writing a professional vulnerability report for a maintainer based on a static analysis finding.

IMPORTANT: When you detect exposed secrets or hardcoded passwords, explicitly classify them
(e.g., AWS Access Keys, GitHub Tokens, Database Passwords) and highlight the specific blast radius.

CRITICAL — FALSE POSITIVE HANDLING:
You will NEVER output "FALSE POSITIVE" or any variant of it. False-positive classification
has already been done deterministically by the Python layer before this prompt was sent.
If you are reading this prompt, the finding is CONFIRMED REAL. Treat it as a true positive
and generate the full 10-point report. Do NOT second-guess the classification — you do not
have access to the pre-filter logic and your judgment on this is unreliable.

You MUST strictly follow this 10-point structure for ALL vulnerability types:

1. Problem
2. Summary (2-3 sentences)
3. Affected component (File path, line numbers)
4. Vulnerability classification (CWE ID from the lookup table, CVSS 3.1 vector string, and OWASP category)
5. Detailed technical description (How it works, root cause)
6. Proof of Concept (PoC) — Concrete scenario, e.g. a specific curl command or payload, NOT generic bullets
7. Impact assessment (What an attacker can achieve based on actual reachability and environment)
8. Suggested fix (Pseudocode or secure approach)
9. Timeline (Note: discovered via automated scanning today)
10. Contact info / credit: AI Source Code Analyzer

Format the report using Markdown. Keep the tone professional, objective, and calibrated to the severity.
"""

    file_path = finding.get("path", "Unknown file")
    line = finding.get("start", {}).get("line", "Unknown line")
    message = finding.get("extra", {}).get("message", "No message provided")
    severity = finding.get("extra", {}).get("severity", "Unknown")
    code_snippet = finding.get("extra", {}).get("lines", "")

    import re

    # ── BUG FIX 1: FALSE POSITIVE GATE (PYTHON LAYER — SINGLE SOURCE OF TRUTH) ─
    # The LLM is ONLY called when we are certain the finding is real.
    # This prevents the model from contradicting itself (outputting "FALSE POSITIVE"
    # while also generating a full 10-point report body in the same response).
    value = code_snippet
    m = re.search(r'=\s*["\']([^"\']+)["\']', code_snippet)
    if m:
        value = m.group(1)

    is_dummy = False
    dummy_reason = ""
    if len(value) >= 8 and (value[:len(value)//2] == value[len(value)//2:]):
        is_dummy = True
        dummy_reason = f"The value `{value}` consists of a repeated substring, a common placeholder convention."
    elif re.search(r'^(1234|abcd|0123|qwerty|asdf)', value.lower()):
        is_dummy = True
        dummy_reason = f"The value `{value}` follows a simple sequential or keyboard pattern."
    elif any(x in value.lower() for x in ['insert_', 'your_', '<>', 'xxxxxx', 'changeme', 'placeholder']):
        is_dummy = True
        dummy_reason = f"The value `{value}` contains explicit placeholder text."
    elif len(set(value)) <= 3 and len(value) > 5:
        is_dummy = True
        dummy_reason = f"The value `{value}` has extremely low entropy ({len(set(value))} unique chars)."
    # Well-known vendor-published example / documentation keys — these are
    # deliberately fake and safe, published by AWS, GCP, etc. in their own docs.
    elif value in _KNOWN_VENDOR_EXAMPLE_KEYS:
        is_dummy = True
        dummy_reason = f"The value `{value}` is a well-known vendor-published documentation placeholder key."

    # Apply false-positive gate ONLY to secrets-class findings.
    # Non-secrets vuln classes (SSTI, SQLi, XSS, SSRF, etc.) are always real.
    secrets_keywords = ['secret', 'password', 'token', 'credential', 'api.key', 'apikey', 'hardcoded']
    is_secrets_finding = any(kw in message.lower() for kw in secrets_keywords)
    if is_dummy and is_secrets_finding:
        return (
            f"**FALSE POSITIVE**\n"
            f"The detected snippet `{code_snippet.strip()}` is clearly a dummy placeholder "
            f"and not a real hardcoded credential. {dummy_reason} No actual sensitive data is exposed."
        )

    # BUG FIX 2 & 3: CWE constraint table + CVSS math rules injected into user message
    # so they apply to ALL finding types (SSTI, SQLi, XSS, secrets, etc.)
    cwe_and_cvss_rules = """\
MANDATORY CWE LOOKUP TABLE - pick from this list ONLY. Do NOT use free recall.
| Vulnerability Class                        | Correct CWE        |
|--------------------------------------------|--------------------|
| Hardcoded credentials / secrets            | CWE-798            |
| SQL Injection                              | CWE-89             |
| Command Injection / OS Command             | CWE-78             |
| Server-Side Template Injection (SSTI)      | CWE-1336           |
| Cross-Site Scripting (XSS)                 | CWE-79             |
| Path Traversal / Directory Traversal       | CWE-22             |
| Insecure Deserialization                   | CWE-502            |
| XML External Entity (XXE)                  | CWE-611            |
| Open Redirect                              | CWE-601            |
| Sensitive Data Exposure (catch-all only)   | CWE-200            |
| Broken Authentication                      | CWE-287            |
| Missing Authorization                      | CWE-862            |
| Weak Cryptography / Weak Hash              | CWE-327 / CWE-328  |
| SSRF                                       | CWE-918            |
| Use of Dangerous Function (eval, exec)     | CWE-94             |
| Race Condition                             | CWE-362            |
| Improper Input Validation (generic)        | CWE-20             |

MANDATORY OWASP TOP 10 (2021) LOOKUP TABLE - use the EXACT label below. Do NOT paraphrase or abbreviate.
| Vulnerability Class                                     | Correct OWASP Label                      |
|---------------------------------------------------------|------------------------------------------|
| Broken Access Control                                   | A01:2021 – Broken Access Control         |
| Cryptographic Failures / Sensitive Data Exposure        | A02:2021 – Cryptographic Failures        |
| Injection (SQLi, CMDi, SSTI, XSS, etc.)                | A03:2021 – Injection                     |
| Insecure Design / Missing security controls             | A04:2021 – Insecure Design               |
| Security Misconfiguration / Hardcoded secrets           | A05:2021 – Security Misconfiguration     |
| Vulnerable and Outdated Components                      | A06:2021 – Vulnerable and Outdated Components |
| Identification and Authentication Failures              | A07:2021 – Identification and Authentication Failures |
| Software and Data Integrity Failures / Deserialization  | A08:2021 – Software and Data Integrity Failures |
| Security Logging and Monitoring Failures                | A09:2021 – Security Logging and Monitoring Failures |
| Server-Side Request Forgery (SSRF)                      | A10:2021 – Server-Side Request Forgery   |

MANDATORY CVSS 3.1 MATH RULES - apply BEFORE choosing a score:
- Walk through AV, AC, PR, UI, S, C, I, A in order.
- Use ONLY: AV:N/A/L/P | AC:L/H | PR:N/L/H | UI:N/R | S:C/U | C:H/L/N | I:H/L/N | A:H/L/N
- PR:H caps the max base score at ~8.0. NEVER output a score above 8.0 if PR:H.
- PR:L caps the max base score at ~9.0.
- A score of 9.8 REQUIRES PR:N AND UI:N AND AC:L simultaneously.
- S:U (Unchanged Scope) prevents a score of 10.0.
- UI:R reduces the score - you CANNOT combine UI:R with a score of 9.8.
- Reference calibration:
    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
    AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H = 9.6
    AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.0
    AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H = 9.0  (Scope Changed softens PR:H penalty)
    AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H = 7.2  (PR:H + Unchanged Scope)
    AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.1
    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
"""

    user_content = (
        f"Please generate a detailed vulnerability report for the following finding:\n\n"
        f"**File:** `{file_path}` (Line {line})\n"
        f"**Severity:** {severity}\n"
        f"**Message:** {message}\n\n"
        f"**Code Snippet:**\n```\n{code_snippet}\n```\n\n"
        f"{cwe_and_cvss_rules}\n"
        f"Select the CWE from the CWE lookup table above. "
        f"Select the OWASP label from the OWASP Top 10 (2021) lookup table above — "
        f"use the EXACT label format (e.g. 'A05:2021 \u2013 Security Misconfiguration'), do NOT paraphrase or abbreviate it. "
        f"For CVSS: output ONLY the vector string (e.g. AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H) — "
        f"do NOT compute or write the numerical score yourself. The score will be computed programmatically from your vector. "
        f"Write 'CVSS 3.1 Score: [COMPUTED]' as a placeholder where the score would go."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]
    # _postprocess_report() is the final quality gate:
    # — recomputes CVSS score from the vector using the real formula
    # — validates and corrects the OWASP category against the 2021 list
    # This runs AFTER the LLM call so classification metadata is always accurate.
    return _postprocess_report(_call_cloud_llm(messages))


def apply_auto_fix(project_id: str, finding: dict) -> dict:
    """Generates a fix for the vulnerability and applies it directly to the file on disk."""
    import os
    import re
    file_path = finding.get("path", "")
    if not file_path:
        raise ValueError("Finding does not contain a file path.")

    # ── FALSE POSITIVE GATE ──────────────────────────────────────────────────
    # Do not apply any fix — or even call the LLM — for false-positive findings.
    code_snippet = finding.get("extra", {}).get("lines", "")
    message_text = finding.get("extra", {}).get("message", "")
    if _is_false_positive(code_snippet, message_text):
        return {
            "status": "skipped",
            "file": file_path,
            "message": (
                "⚠️ **No action needed.** This finding was classified as a "
                "**false positive** — the code snippet contains a placeholder value, "
                "not a real secret or vulnerability. No fix was applied."
            )
        }
    # ── END GATE ─────────────────────────────────────────────────────────────
    
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

    # ── FALSE POSITIVE GATE ──────────────────────────────────────────────────
    # The Risk Assessment panel MUST NOT generate fix commentary for false
    # positives. Otherwise the UI shows an actionable "Accept & Apply Fix"
    # button for a finding the pipeline itself dismissed as non-real.
    code_snippet = finding.get("extra", {}).get("lines", "")
    message_text = finding.get("extra", {}).get("message", "")
    if _is_false_positive(code_snippet, message_text):
        return {
            "false_positive": True,
            "risk_assessment": (
                "### ✅ No Action Needed\n"
                "This finding was classified as a **false positive** — "
                "the code snippet contains a placeholder or dummy value, not a real secret or vulnerability.\n\n"
                "No fix needs to be applied. The \"Accept & Apply Fix\" action has been disabled."
            ),
            "fixed_content": None
        }
    # ── END GATE ─────────────────────────────────────────────────────────────
    
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
