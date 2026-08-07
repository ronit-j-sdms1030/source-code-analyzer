import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.chain import _postprocess_report, _validate_and_correct_cwe

def test_owasp_category_correction():
    report = "OWASP Category: A04:2017 Insecure Design\nCWE-1173"
    processed = _postprocess_report(report)
    assert "A04:2021" in processed

def test_owasp_hallucinated_category():
    report = "OWASP Category: Security misconfiguration\nCWE-798"
    processed = _postprocess_report(report)
    assert "A05:2021 \u2013 Security Misconfiguration" in processed

def test_cwe_disambiguation_docker():
    corrected = _validate_and_correct_cwe("CWE-798", "A05:2021 \u2013 Security Misconfiguration", rule_id="docker-missing-user")
    assert corrected == "CWE-269"

def test_cwe_valid_not_overwritten():
    corrected = _validate_and_correct_cwe("CWE-798", "A02:2021 \u2013 Cryptographic Failures", rule_id="hardcoded-secret")
    assert corrected == "CWE-798"

def test_cwe_fallback_first_valid():
    corrected = _validate_and_correct_cwe("CWE-9999", "A01:2021 \u2013 Broken Access Control", rule_id="some-rule")
    assert corrected == "CWE-22"
