import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from src.chain import generate_vulnerability_report, _is_generic_poc, _apply_fallback_poc, _GENERIC_POC_PHRASES

class TestReportGeneration(unittest.TestCase):

    def setUp(self):
        # We can just test the fallback logic directly since we don't want to make real LLM calls in unit tests
        # or we mock the LLM call. Here we will test that _is_generic_poc catches the banned phrases
        # and _apply_fallback_poc applies the correct deterministic template.
        pass
        
    def test_banned_phrases_detected(self):
        for phrase in _GENERIC_POC_PHRASES:
            report = f"6. Proof of Concept\n{phrase.upper()}\n7. Impact"
            self.assertTrue(_is_generic_poc(report), f"Failed to flag generic phrase: {phrase}")

    def test_missing_user_directive_fallback(self):
        report = "6. Proof of Concept\na specific payload\n7. Impact"
        # The rule_id for docker user directive
        rule_id = "dockerfile-missing-user"
        
        fallback_report = _apply_fallback_poc(report, rule_id)
        
        self.assertFalse(_is_generic_poc(fallback_report), "Fallback report should not be generic")
        self.assertIn("docker build -t test_image .", fallback_report)
        self.assertIn("docker run --rm test_image whoami", fallback_report)
        self.assertNotIn("a specific payload", fallback_report)

    def test_hardcoded_aws_key_fallback(self):
        report = "6. Proof of Concept\nAn attacker can use a specific curl command to exploit this.\n7. Impact"
        rule_id = "hardcoded-aws-secret-key"
        
        fallback_report = _apply_fallback_poc(report, rule_id)
        
        self.assertFalse(_is_generic_poc(fallback_report), "Fallback report should not be generic")
        self.assertIn("git log -p | grep -i 'AKIA'", fallback_report)
        self.assertNotIn("a specific curl command", fallback_report)

    def test_sqli_fallback(self):
        report = "6. Proof of Concept\nmalicious code or access sensitive data\n7. Impact"
        rule_id = "python-sql-injection"
        
        fallback_report = _apply_fallback_poc(report, rule_id)
        
        self.assertFalse(_is_generic_poc(fallback_report), "Fallback report should not be generic")
        self.assertIn("' OR 1=1 --", fallback_report)
        self.assertNotIn("malicious code", fallback_report)

    def test_cwe_correction_logic(self):
        from src.chain import _validate_and_correct_cwe
        # Correctly falls back to the first mapped CWE when the generated one is totally invalid
        corrected1 = _validate_and_correct_cwe("CWE-9999", "A01:2021 – Broken Access Control", rule_id="some-rule")
        self.assertEqual(corrected1, "CWE-22")
        
        # Keeps valid CWE
        corrected2 = _validate_and_correct_cwe("CWE-284", "A01:2021 – Broken Access Control", rule_id="some-rule")
        self.assertEqual(corrected2, "CWE-284")
        
        # Disambiguates based on rule id for secrets
        corrected3 = _validate_and_correct_cwe("CWE-16", "A05:2021 – Security Misconfiguration", rule_id="hardcoded-secret")
        self.assertEqual(corrected3, "CWE-798")
        
        # Disambiguates based on rule id for SQLi
        corrected4 = _validate_and_correct_cwe("CWE-79", "A03:2021 – Injection", rule_id="java-sql-injection")
        self.assertEqual(corrected4, "CWE-89")

if __name__ == '__main__':
    unittest.main()
