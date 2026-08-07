import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.chain import _is_generic_poc, _has_hallucinated_poc, _apply_fallback_poc

def test_poc_banned_phrase():
    assert _is_generic_poc("a specific curl command or payload can be used") == True

def test_poc_hallucinated_sqli():
    finding = {"message": "exposed secret password", "lines": "const password = req.body.password;"}
    assert _has_hallucinated_poc("the attacker can use sql injection", finding) == True

def test_poc_concrete_and_grounded():
    finding = {"message": "hardcoded api key", "lines": "API_KEY = '123'"}
    # No banned phrase, no hallucination
    assert _is_generic_poc("set AWS_SECRET_KEY = 'wJal...' in config.py:14") == False
    assert _has_hallucinated_poc("set AWS_SECRET_KEY = 'wJal...' in config.py:14", finding) == False

def test_poc_true_positive_not_flagged():
    finding = {"message": "hardcoded api key", "lines": "API_KEY = '123'"}
    assert _has_hallucinated_poc("an attacker can intercept the hardcoded token over the network", finding) == False

def test_fallback_poc_docker():
    report = "1. X\n6. Proof of Concept\nBad PoC\n7. Fix"
    new_report = _apply_fallback_poc(report, "docker-missing-user")
    assert "docker build" in new_report
    assert "docker run" in new_report
    assert "whoami" in new_report
    assert not _is_generic_poc(new_report)

def test_fallback_poc_sql():
    report = "1. X\n6. Proof of Concept\nBad PoC\n7. Fix"
    new_report = _apply_fallback_poc(report, "sql-injection")
    assert "' OR 1=1 --" in new_report
    assert not _is_generic_poc(new_report)
