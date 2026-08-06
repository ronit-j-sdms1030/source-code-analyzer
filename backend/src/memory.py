import json
import redis
import time
from . import config
from .chain import _call_cloud_llm

_redis_client = None

def get_redis_client():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    return _redis_client

def get_session_history(session_id: str) -> list:
    """Returns the chat history for a session."""
    client = get_redis_client()
    key = f"session:{session_id}"
    raw = client.get(key)
    if not raw:
        return []
    return json.loads(raw)

def save_session_history(session_id: str, history: list):
    """Saves the history to Redis with a 48h TTL."""
    client = get_redis_client()
    key = f"session:{session_id}"
    client.setex(key, 48 * 3600, json.dumps(history))

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
