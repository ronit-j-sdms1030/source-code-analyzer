import sys
import os
import json
import re

# Add the backend dir to sys.path so we can import src
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, backend_dir)

from src.ingestion import rescan_vulnerabilities, _run_semgrep
from src.chain import generate_vulnerability_report, _compute_cvss31_score, _has_hallucinated_poc, _OWASP_2021_VALID, _CWE_BY_OWASP, _force_classification_by_rule_id
from src import config

def extract_section(report: str, section_num: int) -> str:
    """Extract a numbered section from the markdown report."""
    pattern = rf'({section_num}\.\s*[^\n]*\n)(.*?)(?=\n(?:{section_num+1})\.|\Z)'
    m = re.search(pattern, report, re.IGNORECASE | re.DOTALL)
    return m.group(2).strip() if m else ""

def test_pipeline_live(project_id: str):
    print(f"=== Testing live pipeline for project: {project_id} ===")
    
    # Run ingestion (Semgrep + False Positive Gate)
    counts = rescan_vulnerabilities(project_id)
    
    report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
    suppressed_path = os.path.join(config.REPORTS_DIR, f"suppressed_findings_{project_id}.json")
    
    with open(report_path, "r") as f:
        valid_data = json.load(f)
        valid_findings = valid_data.get("results", [])
        
    suppressed_findings = []
    if os.path.exists(suppressed_path):
        with open(suppressed_path, "r") as f:
            suppressed_data = json.load(f)
            suppressed_findings = suppressed_data.get("results", [])
            
    # Invariant 1: Mutual exclusivity
    valid_paths_lines = {(f.get("path"), f.get("start",{}).get("line")) for f in valid_findings}
    suppressed_paths_lines = {(f.get("path"), f.get("start",{}).get("line")) for f in suppressed_findings}
    
    intersection = valid_paths_lines.intersection(suppressed_paths_lines)
    if intersection:
        print(f"[FAIL] Mutual exclusivity violated! Findings in both valid and suppressed: {intersection}")
        sys.exit(1)
        
    print(f"Ingestion complete. Valid: {len(valid_findings)}, Suppressed: {len(suppressed_findings)}")
    
    for idx, finding in enumerate(valid_findings):
        rule_id = finding.get("check_id")
        print(f"\n--- Generating live report for finding {idx+1}/{len(valid_findings)}: {rule_id} ---")
        
        # Trigger LLM generation + all post-processing gates
        final_report = generate_vulnerability_report(project_id, finding)
        
        # Parse the final report to check invariants
        
        # Invariant 3: OWASP Validity
        owasp_re = re.compile(r'(OWASP[\s\*]*(?:Top[\s\*]*10[\s\*]*)?(?:Category|Label|Classification)?[\s\*]*[:\u2013\-][\s\*]*)([^\n]+)', re.IGNORECASE)
        owasp_match = owasp_re.search(final_report)
        owasp_label = None
        if not owasp_match:
            print(f"   [WARN] Missing OWASP category in report for {rule_id}. Skipping OWASP drift check.")
        else:
            owasp_label = owasp_match.group(2).strip()
            if owasp_label not in _OWASP_2021_VALID:
                print(f"[FAIL] Invalid OWASP category: '{owasp_label}' for {rule_id}")
                sys.exit(1)
            
            raw_owasp = owasp_label[:8].upper()
            
            # Check OWASP drift against lookup
            expected_owasp, _ = _force_classification_by_rule_id(rule_id)
            if expected_owasp:
                if expected_owasp.startswith(raw_owasp[:3]):
                    pass # Valid
                else:
                    print(f"[FAIL] OWASP Drift! Expected {expected_owasp}, got {raw_owasp} for {rule_id}")
                    sys.exit(1)
            
        # Invariant 2: CWE Validity
        cwe_re = re.compile(r'(CWE[\s\*]*[:\u2013\-]?[\s\*]*)(?:CWE[\s\*]*\-[\s\*]*)?(\d+)', re.IGNORECASE)
        cwe_match = cwe_re.search(final_report)
        if not cwe_match:
            print(f"[FAIL] Missing CWE in report for {rule_id}")
            sys.exit(1)
            
        cwe_label = f"CWE-{cwe_match.group(2)}"
        if owasp_label:
            valid_cwes = _CWE_BY_OWASP.get(owasp_label, [])
            if cwe_label not in valid_cwes:
                print(f"[FAIL] Mismatched CWE for OWASP Category! rule_id: {rule_id}")
                print(f"       OWASP Category: {owasp_label}")
                print(f"       Assigned CWE: {cwe_label}")
                print(f"       Valid CWEs for this category: {valid_cwes}")
                sys.exit(1)
            
        # Invariant 4: PoC Groundedness
        poc_text = extract_section(final_report, 6)
        if _has_hallucinated_poc(final_report, finding):
            if "[FLAGGED FOR REVIEW: Hallucinated PoC]" in final_report:
                print(f"   [INFO] Hallucinated PoC was successfully caught and flagged for {rule_id}")
            else:
                print(f"[FAIL] Hallucinated PoC silently bypassed the gate for {rule_id}")
                print(f"PoC text: {poc_text}")
                sys.exit(1)
            
        # Invariant 5: CVSS Drift
        vector_re = re.compile(r'(CVSS:3\.1/)?(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[CU]/C:[NLH]/I:[NLH]/A:[NLH])', re.IGNORECASE)
        vec_match = vector_re.search(final_report)
        if not vec_match:
            print(f"   [WARN] Missing CVSS vector in report for {rule_id}. Skipping CVSS drift check.")
        else:
            raw_vector = vec_match.group(0).upper()
            computed = _compute_cvss31_score(raw_vector)
            
            score_re = re.compile(r'(Score[\s\*]*[:\-][\s\*]*)(\[COMPUTED\]|\d+\.\d+)', re.IGNORECASE)
            score_match = score_re.search(final_report)
            if not score_match:
                print(f"[FAIL] Missing CVSS numeric score in report for {rule_id}")
                print(f"--- FINAL REPORT ---\n{final_report}")
                sys.exit(1)
                
            stated_score = float(score_match.group(2))
            if abs(stated_score - computed) > 0.01:
                print(f"[FAIL] CVSS Drift! Stated: {stated_score}, Computed from vector: {computed} for {rule_id}")
                sys.exit(1)
            
        print(f"   [PASS] {rule_id} passed all invariants.")

def test_fix_sync_invariant(project_id: str):
    """
    Live invariant: after applying a fix to the first finding in the report,
    assert — within the same session and WITHOUT a manual re-scan — that:
      1. The finding count in report.json decreases by exactly 1.
      2. The source file on disk has been modified (MD5 hash differs).
    """
    import hashlib
    import app as flask_app

    print(f"\n=== Fix-sync invariant for project: {project_id} ===")

    report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
    if not os.path.exists(report_path):
        print(f"[SKIP] No report.json found for {project_id}; run a scan first.")
        return

    with open(report_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    findings = report_data.get("results", [])
    if not findings:
        print(f"[SKIP] No findings in report for {project_id}. Nothing to fix.")
        return

    # Use the first finding as the target
    finding = findings[0]
    file_path = finding.get("path", "")
    abs_file_path = os.path.join(config.REPOS_DIR, project_id, file_path)

    if not os.path.exists(abs_file_path):
        print(f"[SKIP] Source file '{file_path}' not found on disk. Skipping.")
        return

    with open(abs_file_path, "rb") as fh:
        hash_before = hashlib.md5(fh.read()).hexdigest()

    # Read the original content and append a harmless comment to simulate a fix
    with open(abs_file_path, "r", encoding="utf-8") as fh:
        original_content = fh.read()
    simulated_fix = original_content + "\n# [SECURITY FIX APPLIED - invariant test]\n"

    before_count = len(findings)

    # Call the endpoint in-process via the Flask test client
    flask_app.app.config["TESTING"] = True
    client = flask_app.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True

    response = client.post(
        f"/projects/{project_id}/vulnerabilities/apply_evaluated_fix",
        json={"finding": finding, "fixed_content": simulated_fix},
    )

    if response.status_code != 200:
        print(f"[FAIL] apply_evaluated_fix returned HTTP {response.status_code}: {response.data}")
        sys.exit(1)

    body = response.get_json()
    if body.get("status") != "success":
        print(f"[FAIL] apply_evaluated_fix returned non-success: {body}")
        sys.exit(1)

    if not body.get("removed_from_report"):
        print(f"[FAIL] removed_from_report is False or missing. Finding was not matched in report.json.")
        print(f"       Finding: path={file_path!r}, line={finding.get('start',{}).get('line')}, msg={finding.get('extra',{}).get('message','')!r}")
        sys.exit(1)

    # Re-read report WITHOUT re-scanning
    with open(report_path, "r", encoding="utf-8") as f:
        after_data = json.load(f)
    after_count = len(after_data.get("results", []))

    if after_count != before_count - 1:
        print(f"[FAIL] Fix-sync invariant: count should be {before_count - 1}, got {after_count}")
        sys.exit(1)

    # Check the file was actually modified on disk
    with open(abs_file_path, "rb") as fh:
        hash_after = hashlib.md5(fh.read()).hexdigest()

    if hash_before == hash_after:
        print(f"[FAIL] File hash unchanged after fix — fix was not written to disk.")
        sys.exit(1)

    # Restore the original file so we don't corrupt the live repo
    with open(abs_file_path, "w", encoding="utf-8") as fh:
        fh.write(original_content)

    print(f"   [PASS] fix-sync invariant: count {before_count} → {after_count}, file hash changed.")


if __name__ == "__main__":
    test_repos = ["pa91d5f6f75", "p14be7894e2"]
    for pid in test_repos:
        test_pipeline_live(pid)
        test_fix_sync_invariant(pid)
    print("\nALL REPOS PASSED LIVE INVARIANTS.")
