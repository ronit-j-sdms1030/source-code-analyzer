import pytest
import sys
import os
from src.chain import _is_generic_poc, _has_hallucinated_poc, _apply_fallback_poc
from unittest.mock import patch

def test_generic_poc_detection():
    assert _is_generic_poc("a specific curl command or payload can be used") == True
    assert _is_generic_poc("curl -X POST -d 'test' http://localhost/") == False

def test_hallucinated_poc_detection():
    finding = {
        "message": "Exposed Database Password",
        "lines": "const password = e.target.password.value;"
    }
    
    with patch("src.chain._call_cloud_llm") as mock_llm:
        # 1. SQL Injection framing
        mock_llm.return_value = "NOT_GROUNDED: The PoC claims SQL injection but the snippet is a DOM read."
        assert _has_hallucinated_poc("the attacker can use sql injection", finding) == True
        
        # 2. Curl/grep from source framing (novel unseen phrasing)
        mock_llm.return_value = "NOT_GROUNDED: The PoC claims to grep the file for a literal password, but no literal exists."
        assert _has_hallucinated_poc("an attacker can download the JS file and grep for the hardcoded password", finding) == True
        
        # 3. Grounded PoC with no literals
        mock_llm.return_value = "GROUNDED"
        assert _has_hallucinated_poc("the attacker can read the user's password from the DOM element", finding) == False

def test_poc_true_positive_not_flagged():
    finding = {
        "message": "AWS Access Key",
        "lines": "export AWS_SECRET_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    }
    # True positives with literals should short-circuit before the LLM check.
    assert _has_hallucinated_poc("set AWS_SECRET_KEY = 'wJal...' in config.py:14", finding) == False
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
