import pytest
import sys
import os
import json
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.chain import answer_question as process_chat_message
from src.memory import append_to_session, get_session_history
import src.chain
import src.config as config

def mock_call_cloud_llm(messages, **kwargs):
    system_msg = messages[0]["content"] if messages else ""
    if "intent router" in system_msg:
        last_msg = messages[-1]["content"].lower()
        if "fifth" in last_msg or "risk 5" in last_msg:
            return json.dumps({"intent": "fix_code", "entities": {"finding_index": 5}})
        elif "first" in last_msg or "risk 1" in last_msg:
            return json.dumps({"intent": "fix_code", "entities": {"finding_index": 1}})
        elif "second" in last_msg or "risk 2" in last_msg:
            return json.dumps({"intent": "fix_code", "entities": {"finding_index": 2}})
        elif "fix" in last_msg and ("risks" in last_msg or "all" in last_msg or "these" in last_msg):
            return json.dumps({"intent": "fix_code", "entities": {"finding_index": "all"}})
        else:
            return json.dumps({"intent": "general_code", "entities": {}})
    return "1. [High Risk] `file1.js`: 10\n2. [Low Risk] `file2.js`: 20"

def mock_query_chunks(*args, **kwargs):
    return ["chunk1", "chunk2"]

def mock_query_findings(project_id, query_vector=None, where=None, top_k=5):
    where_str = str(where) if where else ""
    if "file1.js" in where_str:
        return {"documents": [["const a = 1;"]], "metadatas": [[{"check_id": "rule-1", "file_path": "file1.js", "line_number": 10}]]}
    elif "file2.js" in where_str:
        return {"documents": [["const b = 2;"]], "metadatas": [[{"check_id": "rule-2", "file_path": "file2.js", "line_number": 20}]]}
    return {"documents": [[]], "metadatas": [[]]}

def mock_evaluate_auto_fix(*args, **kwargs):
    return {"risk_assessment": "Mock risk", "fixed_content": "Mock code"}

@pytest.fixture(autouse=True)
def patch_chain(monkeypatch, tmp_path):
    monkeypatch.setattr(src.chain, "_call_cloud_llm", mock_call_cloud_llm)
    monkeypatch.setattr(src.chain, "query_chunks", mock_query_chunks)
    monkeypatch.setattr("src.vectorstore.query_findings", mock_query_findings)
    monkeypatch.setattr(src.chain, "evaluate_auto_fix", mock_evaluate_auto_fix)
    
    # Mock REPORTS_DIR to provide findings
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    monkeypatch.setattr(config, "REPORTS_DIR", str(reports_dir))
    
    # Mock REPOS_DIR to provide source files
    repos_dir = tmp_path / "repos"
    proj_dir = repos_dir / "proj-1"
    proj_dir.mkdir(parents=True)
    (proj_dir / "file1.js").write_text("const a = 1;")
    (proj_dir / "file2.js").write_text("const b = 2;")
    monkeypatch.setattr(config, "REPOS_DIR", str(repos_dir))
    
    # Create mock findings
    findings = {
        "results": [
            {"check_id": "rule-1", "path": "file1.js", "start": {"line": 10}, "lines": "const a = 1;"},
            {"check_id": "rule-2", "path": "file2.js", "start": {"line": 20}, "lines": "const b = 2;"}
        ]
    }
    with open(os.path.join(str(reports_dir), "proj-1.json"), "w") as f:
        json.dump(findings, f)

def test_intent_listed_findings():
    session_id = "test_ord_1"
    res = process_chat_message("proj-1", "tell me risks", session_id)
    history = get_session_history(session_id)
    assert any("listed_findings" in msg for msg in history if msg.get("role") == "assistant")
    
    session_id2 = "test_ord_2"
    res = process_chat_message("proj-1", "what are risks", session_id2)
    history = get_session_history(session_id2)
    assert any("listed_findings" in msg for msg in history if msg.get("role") == "assistant")

def test_fix_risk_1():
    session_id = "test_ord_3"
    process_chat_message("proj-1", "what are risks", session_id)
    res = process_chat_message("proj-1", "fix first risk", session_id)
    assert "evaluate_fix_payloads" in res
    assert len(res["evaluate_fix_payloads"]) == 1
    assert res["evaluate_fix_payloads"][0]["finding"]["check_id"] == "rule-1"

def test_risk_2_no_verb():
    session_id = "test_ord_4"
    process_chat_message("proj-1", "what are risks", session_id)
    res = process_chat_message("proj-1", "second risk", session_id)
    assert "evaluate_fix_payloads" not in res
    assert res["debug_context"]["intent"]["intent"] == "specific_finding"
    assert "retrieved_findings" in res["debug_context"]
    assert res["debug_context"]["retrieved_findings"][0]["check_id"] == "rule-2"

def test_fix_risks_plural():
    session_id = "test_ord_5"
    process_chat_message("proj-1", "what are risks", session_id)
    res = process_chat_message("proj-1", "fix risks", session_id)
    assert "evaluate_fix_payloads" in res
    assert len(res["evaluate_fix_payloads"]) == 2

def test_fix_all_phrasings():
    for phrase in ["fix all of them", "fix these", "apply all fixes"]:
        session_id = f"test_ord_6_{phrase.replace(' ', '_')}"
        process_chat_message("proj-1", "what are risks", session_id)
        res = process_chat_message("proj-1", phrase, session_id)
        assert "evaluate_fix_payloads" in res
        assert len(res["evaluate_fix_payloads"]) == 2

def test_fix_out_of_bounds():
    session_id = "test_ord_7"
    process_chat_message("proj-1", "what are risks", session_id)
    res = process_chat_message("proj-1", "fix fifth risk", session_id)
    assert "evaluate_fix_payloads" not in res
    assert "only listed 2 findings" in res["answer"].lower()

def test_fix_fresh_session():
    session_id = "test_ord_8"
    res = process_chat_message("proj-1", "fix first risk", session_id)
    assert "evaluate_fix_payloads" not in res
    assert "first" in res["answer"].lower()

def test_deterministic_resolution():
    session_id1 = "test_ord_9_A"
    res1 = process_chat_message("proj-1", "fix first risk", session_id1)
    
    session_id2 = "test_ord_9_B"
    res2 = process_chat_message("proj-1", "fix first risk", session_id2)
    
    assert res1["answer"] == res2["answer"]
