import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.chain import _compute_cvss31_score

def test_cvss_9_1():
    # Given vector AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H, assert computed score is exactly 9.1.
    score = _compute_cvss31_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")
    assert score == 9.1

def test_cvss_10_0():
    # Given vector AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H, assert score is 10.0.
    score = _compute_cvss31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert score == 10.0

def test_cvss_low():
    # Given a low-severity vector AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N, assert score falls in the 2.0–2.5 low range (assert exact value once computed).
    score = _compute_cvss31_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert score == 1.8

def test_cvss_malformed():
    # Given a malformed/incomplete vector string, assert the function raises or returns a safe default.
    score = _compute_cvss31_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H")
    assert score is None

def test_cvss_scope_changed():
    # Assert Scope-Changed (S:C) vs Scope-Unchanged (S:U) produce different scores for otherwise-identical vectors
    score_c = _compute_cvss31_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    score_u = _compute_cvss31_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    assert score_c != score_u
