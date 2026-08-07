import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.memory import append_to_session, get_session_history
import src.config as config

@pytest.fixture(autouse=True)
def isolated_storage(monkeypatch, tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    monkeypatch.setattr(config, "REPORTS_DIR", str(reports_dir))

def test_session_history_persistence():
    session_id = "test_session_1"
    # Ensure fresh
    history = get_session_history(session_id)
    assert history == []
    
    append_to_session(session_id, {"role": "user", "content": "tell me risks"})
    append_to_session(session_id, {"role": "assistant", "content": "here are risks"})
    
    history = get_session_history(session_id)
    assert len(history) == 2
    assert history[0]["content"] == "tell me risks"
    assert history[1]["content"] == "here are risks"

def test_session_isolation():
    session_a = "test_session_A"
    session_b = "test_session_B"
    
    append_to_session(session_a, {"role": "user", "content": "hello A"})
    append_to_session(session_b, {"role": "user", "content": "hello B"})
    
    history_a = get_session_history(session_a)
    history_b = get_session_history(session_b)
    
    assert len(history_a) == 1
    assert history_a[0]["content"] == "hello A"
    assert len(history_b) == 1
    assert history_b[0]["content"] == "hello B"

def test_history_truncation():
    # Simulate a long conversation exceeding the token/length guard threshold
    session_id = "test_session_long"
    for i in range(25):
        append_to_session(session_id, {"role": "user", "content": f"msg {i}"})
        append_to_session(session_id, {"role": "assistant", "content": f"reply {i}"})
        
    history = get_session_history(session_id)
    # The memory logic truncates or summarizes older turns rather than growing unbounded.
    # We assert it's less than or equal to a reasonable cap (e.g., 20 max_turns, or summarized).
    assert len(history) <= 20
