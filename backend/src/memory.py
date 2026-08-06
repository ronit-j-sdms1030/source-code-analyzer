import json
import time
from . import config
from .chain import _call_cloud_llm

_redis_client = None
_redis_available = None  # None = not yet tested, True/False = cached result


def _check_redis():
    """Lazily test if Redis is reachable and cache the result."""
    global _redis_available, _redis_client
    if _redis_available is not None:
        return _redis_available
    try:
        import redis
        client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        client.ping()
        _redis_client = client
        _redis_available = True
    except Exception:
        _redis_available = False
    return _redis_available


def get_redis_client():
    _check_redis()
    return _redis_client


# ── File-based fallback (same logic as the old chain.py) ─────────────────────

def _file_path(session_id: str) -> str:
    import os
    return os.path.join(config.REPORTS_DIR, f"{session_id}_history.json")


def _file_get(session_id: str) -> list:
    import os
    path = _file_path(session_id)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _file_save(session_id: str, history: list):
    path = _file_path(session_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


# ── Public API ────────────────────────────────────────────────────────────────

def get_session_history(session_id: str) -> list:
    """Returns the chat history for a session."""
    if _check_redis():
        key = f"session:{session_id}"
        raw = _redis_client.get(key)
        if not raw:
            return []
        return json.loads(raw)
    else:
        return _file_get(session_id)


def save_session_history(session_id: str, history: list):
    """Saves the history with a 48h TTL (Redis) or to a JSON file (fallback)."""
    if _check_redis():
        key = f"session:{session_id}"
        _redis_client.setex(key, 48 * 3600, json.dumps(history))
    else:
        _file_save(session_id, history)


def append_to_session(session_id: str, message: dict):
    """Appends a message to the session history. Summarizes if it exceeds 10 turns."""
    history = get_session_history(session_id)
    history.append(message)

    # Each turn is user+assistant, so 10 turns = 20 messages, plus maybe system prompts.
    # Let's say if it exceeds 10 messages, we summarize the oldest 6.
    if len(history) > 10:
        _summarize_history(history)

    save_session_history(session_id, history)


def _summarize_history(history: list):
    """Condenses the oldest 6 turns into a summary and replaces them."""
    # Leave the most recent 4 messages intact
    to_summarize = history[:-4]

    prompt = """\
You are summarizing an ongoing chat between a user and a source code analyzer AI.
Condense the following older conversation turns into a brief summary of what has been discussed so far.
Focus on preserving context, stated preferences, and current context state.
"""

    messages = [{"role": "system", "content": prompt}]
    for msg in to_summarize:
        role = "user" if msg["role"] == "user" else "assistant"
        messages.append({"role": role, "content": msg["text"]})

    summary_text = _call_cloud_llm(messages)

    # Replace the summarized portion with a single assistant message
    summary_msg = {
        "role": "assistant",
        "text": f"[System: Condensed history of previous turns]\n{summary_text}"
    }

    # New history is the summary + the last 4 messages
    history[:] = [summary_msg] + history[-4:]
