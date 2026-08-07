"""
Regression test for the apply_evaluated_fix endpoint.

Verifies the full real flow:
  1. Seed a known-vulnerable file + a matching report.json entry.
  2. Call POST /projects/<id>/vulnerabilities/apply_evaluated_fix via the Flask
     test client (no real Semgrep, no real rescan).
  3. Assert — WITHOUT any re-scan — that:
       a) The API returns { status: "success", removed_from_report: true }.
       b) The finding is absent from report.json.
       c) The source file on disk contains the fixed content.
"""
import json
import os
import sys
import pytest

# Ensure backend package is importable when run from the repo root.
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# ---------------------------------------------------------------------------
# Known-vulnerable snippet and its fixed version
# ---------------------------------------------------------------------------
VULN_CODE = """\
import subprocess
user_input = input("Enter command: ")
# Vulnerability: unsanitised shell=True
subprocess.run(user_input, shell=True)
"""

FIXED_CODE = """\
import subprocess
user_input = input("Enter command: ")
# Fixed: pass as list, shell=False
subprocess.run(["/bin/echo", user_input], shell=False)
"""

FINDING_PATH = "app/vuln.py"
FINDING_LINE = 4
FINDING_MSG  = "Avoid 'shell=True' in subprocess calls"
FINDING_CHECK_ID = "python.subprocess-shell-true"

SAMPLE_FINDING = {
    "check_id": FINDING_CHECK_ID,
    "path": FINDING_PATH,
    "start": {"line": FINDING_LINE, "col": 1},
    "end":   {"line": FINDING_LINE, "col": 40},
    "extra": {
        "message": FINDING_MSG,
        "severity": "ERROR",
        "lines": VULN_CODE.strip(),
    },
}

UNRELATED_FINDING = {
    "check_id": "python.hardcoded-password",
    "path": "app/settings.py",
    "start": {"line": 10, "col": 1},
    "end":   {"line": 10, "col": 30},
    "extra": {
        "message": "Hardcoded password detected",
        "severity": "WARNING",
        "lines": "PASSWORD = 'secret'",
    },
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def temp_project(tmp_path, monkeypatch):
    """
    Creates an isolated temp project environment:
    - A repos/<project_id>/ directory containing the vulnerable file.
    - A reports/<project_id>.json with two findings (one matching, one unrelated).
    Patches config.REPOS_DIR and config.REPORTS_DIR to point at tmp_path.
    Returns (client, project_id, repo_dir, report_path).
    """
    project_id = "test_fix_sync_proj"

    repos_dir   = tmp_path / "repos"
    reports_dir = tmp_path / "reports"
    repos_dir.mkdir()
    reports_dir.mkdir()

    # Create the vulnerable source file
    vuln_file_dir = repos_dir / project_id / "app"
    vuln_file_dir.mkdir(parents=True)
    vuln_file = vuln_file_dir / "vuln.py"
    vuln_file.write_text(VULN_CODE, encoding="utf-8")

    # Seed report.json with one matching + one unrelated finding
    report_path = reports_dir / f"{project_id}.json"
    report_path.write_text(
        json.dumps({"results": [SAMPLE_FINDING, UNRELATED_FINDING]}, indent=2),
        encoding="utf-8",
    )

    # Patch config paths BEFORE importing app so Flask picks them up correctly
    from src import config as cfg
    monkeypatch.setattr(cfg, "REPOS_DIR",   str(repos_dir))
    monkeypatch.setattr(cfg, "REPORTS_DIR", str(reports_dir))

    # Import app after patching
    import app as flask_app
    flask_app.app.config["TESTING"] = True
    flask_app.app.config["SECRET_KEY"] = "test-secret"

    client = flask_app.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True

    return client, project_id, str(repos_dir / project_id), str(report_path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestApplyFixReportSync:

    def test_api_returns_success_and_removed_flag(self, temp_project):
        """
        apply_evaluated_fix must return status=success and removed_from_report=True.
        """
        client, project_id, repo_dir, report_path = temp_project

        response = client.post(
            f"/projects/{project_id}/vulnerabilities/apply_evaluated_fix",
            json={"finding": SAMPLE_FINDING, "fixed_content": FIXED_CODE},
        )

        assert response.status_code == 200, (
            f"Expected 200 but got {response.status_code}: {response.data}"
        )
        body = response.get_json()
        assert body.get("status") == "success", f"Unexpected status: {body}"
        assert body.get("removed_from_report") is True, (
            "removed_from_report should be True when the finding was matched "
            f"and removed from report.json. Got: {body}"
        )

    def test_file_content_on_disk_reflects_fix(self, temp_project):
        """
        The source file on disk must contain the corrected code after the fix.
        """
        client, project_id, repo_dir, report_path = temp_project

        client.post(
            f"/projects/{project_id}/vulnerabilities/apply_evaluated_fix",
            json={"finding": SAMPLE_FINDING, "fixed_content": FIXED_CODE},
        )

        written = open(os.path.join(repo_dir, FINDING_PATH), encoding="utf-8").read()
        assert written == FIXED_CODE, (
            "File on disk does not contain the expected fixed content.\n"
            f"Got:\n{written}\n\nExpected:\n{FIXED_CODE}"
        )

    def test_fixed_finding_absent_from_report_json(self, temp_project):
        """
        After apply_evaluated_fix, report.json must NOT contain the fixed finding.
        No re-scan is triggered.
        """
        client, project_id, repo_dir, report_path = temp_project

        client.post(
            f"/projects/{project_id}/vulnerabilities/apply_evaluated_fix",
            json={"finding": SAMPLE_FINDING, "fixed_content": FIXED_CODE},
        )

        with open(report_path, encoding="utf-8") as fh:
            updated_report = json.load(fh)

        results = updated_report.get("results", [])
        fixed_sigs = {
            (r.get("path"), int(r.get("start", {}).get("line") or 0),
             r.get("extra", {}).get("message", ""))
            for r in results
        }
        assert (FINDING_PATH, FINDING_LINE, FINDING_MSG) not in fixed_sigs, (
            "Fixed finding is still present in report.json after apply_evaluated_fix.\n"
            f"Remaining findings: {[r.get('check_id') for r in results]}"
        )

    def test_unrelated_finding_preserved_in_report(self, temp_project):
        """
        The unrelated finding must remain in report.json after the fix is applied.
        """
        client, project_id, repo_dir, report_path = temp_project

        client.post(
            f"/projects/{project_id}/vulnerabilities/apply_evaluated_fix",
            json={"finding": SAMPLE_FINDING, "fixed_content": FIXED_CODE},
        )

        with open(report_path, encoding="utf-8") as fh:
            updated_report = json.load(fh)

        check_ids = [r.get("check_id") for r in updated_report.get("results", [])]
        assert UNRELATED_FINDING["check_id"] in check_ids, (
            f"Unrelated finding was incorrectly removed. Remaining: {check_ids}"
        )

    def test_report_count_decremented_by_exactly_one(self, temp_project):
        """
        The finding count in report.json must decrease by exactly 1.
        """
        client, project_id, repo_dir, report_path = temp_project

        with open(report_path, encoding="utf-8") as fh:
            before_count = len(json.load(fh).get("results", []))

        client.post(
            f"/projects/{project_id}/vulnerabilities/apply_evaluated_fix",
            json={"finding": SAMPLE_FINDING, "fixed_content": FIXED_CODE},
        )

        with open(report_path, encoding="utf-8") as fh:
            after_count = len(json.load(fh).get("results", []))

        assert after_count == before_count - 1, (
            f"Expected count to drop from {before_count} to {before_count - 1}, "
            f"but got {after_count}."
        )

    def test_float_line_number_still_matches(self, temp_project):
        """
        Regression: if the frontend sends line as a float (e.g. 4.0),
        the key-match must still succeed due to int coercion.
        """
        client, project_id, repo_dir, report_path = temp_project

        finding_with_float_line = {**SAMPLE_FINDING,
                                   "start": {"line": float(FINDING_LINE), "col": 1}}

        response = client.post(
            f"/projects/{project_id}/vulnerabilities/apply_evaluated_fix",
            json={"finding": finding_with_float_line, "fixed_content": FIXED_CODE},
        )
        body = response.get_json()
        assert body.get("removed_from_report") is True, (
            f"Float line number caused a silent key-match miss. Response: {body}"
        )

    def test_nonexistent_file_returns_400(self, temp_project):
        """
        If the finding references a file that doesn't exist on disk,
        the endpoint must return 400 (not 200 or 500).
        """
        client, project_id, repo_dir, report_path = temp_project

        bad_finding = {**SAMPLE_FINDING, "path": "does/not/exist.py"}
        response = client.post(
            f"/projects/{project_id}/vulnerabilities/apply_evaluated_fix",
            json={"finding": bad_finding, "fixed_content": FIXED_CODE},
        )
        assert response.status_code == 400, (
            f"Expected 400 for missing file but got {response.status_code}: {response.data}"
        )
