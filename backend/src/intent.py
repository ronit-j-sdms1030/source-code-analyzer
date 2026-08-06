import json
from .chain import _call_cloud_llm

def classify_intent(history: list, question: str) -> dict:
    system_prompt = """\
You are an Intent Classifier for a source code analyzer AI.
Given the conversation history and the user's latest question, determine the intent.
Output ONLY valid JSON matching this schema exactly:

{
  "intent": "general_code" | "specific_finding" | "general_findings" | "fix_request" | "compare_scans",
  "entities": {
    "file_path": "string or null",
    "finding_id": "string or null",
    "line_number": "integer or null",
    "cwe_or_keyword": "string or null",
    "include_false_positives": true|false,
    "memory_trigger": "string or null (if the user asked to remember a preference or rule)",
    "requires_long_term_memory": true|false
  },
  "inferred_from_history": ["list of entity key names that were NOT explicitly stated in the current message but were inferred from prior conversation turns. Empty list if all entities came directly from the current message."]
}

Intent Guide:
- "specific_finding": User asks about a specific vulnerability or finding (e.g. "tell me about the hardcoded key in app.py", "is finding X a false positive?").
- "general_findings": User asks about the security posture or vulnerabilities generally (e.g. "what are the highest risks?", "show me all SQL injection vulnerabilities").
- "fix_request": User explicitly asks to fix a vulnerability, write a patch, or remediate a finding.
- "compare_scans": User asks how vulnerabilities changed over time (reserved for future use).
- "general_code": User asks a general question about the codebase (e.g. "how does the auth work?", "where is the router?").

Entity Extraction Guide:
- extract file_path, finding_id, line_number, and cwe_or_keyword ONLY if they are explicitly stated in the current message.
- If an entity value (e.g. a CWE ID or line number) is NOT in the current message but could be inferred from a previous turn, you MAY still extract it — but you MUST include its key name in the "inferred_from_history" list.
- include_false_positives: true ONLY if the user explicitly asks to see dismissed, false positive, or ignored findings.
- memory_trigger: A concise summary of a preference if the user says "remember that I prefer X" or "always do Y". Otherwise null.
- requires_long_term_memory: true if the user's query depends on their personal preferences or past instructions. Otherwise false.

Examples:
- User says "tell me about the vulnerability in auth.py" with no prior context -> file_path="auth.py", cwe_or_keyword=null, line_number=null, inferred_from_history=[]
- User says "tell me about it" after discussing CWE-89 in auth.py -> file_path="auth.py", cwe_or_keyword="CWE-89", inferred_from_history=["file_path", "cwe_or_keyword"]
- User says "fix the hardcoded credential in app.py line 12" -> file_path="app.py", line_number=12, cwe_or_keyword="hardcoded credential", inferred_from_history=[]
"""
    
    messages = [{"role": "system", "content": system_prompt}]
    for h in history[-4:]:
        role = "user" if h["role"] == "user" else "assistant"
        text = h["text"]
        if len(text) > 500: text = text[:500] + "..."
        messages.append({"role": role, "content": text})
        
    messages.append({"role": "user", "content": question})
    
    raw_response = _call_cloud_llm(messages).strip()
    
    # Clean markdown if present
    if raw_response.startswith("```json"):
        raw_response = raw_response[7:]
    if raw_response.endswith("```"):
        raw_response = raw_response[:-3]
    raw_response = raw_response.strip()
    
    try:
        data = json.loads(raw_response)
        if "intent" not in data or "entities" not in data:
            raise ValueError("Missing required keys")

        # ── Deterministic inference detection ──────────────────────────────
        # Don't trust the LLM to self-report which entities were inferred.
        # Instead, check each non-null entity value against the raw current
        # message. If the value doesn't appear in the message text, it was
        # derived from session history — flag it.
        entities = data.get("entities", {})
        q_lower = question.lower()
        inferred = []

        def _in_message(val) -> bool:
            if val is None:
                return True  # null entity → not inferred
            return str(val).lower() in q_lower

        for key in ("file_path", "finding_id", "cwe_or_keyword"):
            val = entities.get(key)
            if val and not _in_message(val):
                inferred.append(key)

        # line_number: also check numeric string form
        ln = entities.get("line_number")
        if ln is not None and str(ln) not in question:
            inferred.append("line_number")

        data["inferred_from_history"] = inferred
        return data

    except Exception as e:
        print(f"[INTENT ERROR] Failed to parse intent JSON: {e}\nRaw: {raw_response}", flush=True)
        return {
            "intent": "general_code",
            "entities": {
                "file_path": None,
                "finding_id": None,
                "line_number": None,
                "cwe_or_keyword": None,
                "include_false_positives": False,
                "memory_trigger": None,
                "requires_long_term_memory": False
            },
            "inferred_from_history": [],
            "error": "Failed to parse intent, defaulted to general_code"
        }
