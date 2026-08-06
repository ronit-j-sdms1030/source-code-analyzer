import os
import sys
import json
import uuid
import hashlib
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src import config
from src.vectorstore import write_findings, list_projects
from src.embeddings import embed_chunks

def backfill():
    print("Starting findings backfill...")
    projects = list_projects()
    
    for project in projects:
        project_id = project["id"]
        report_path = os.path.join(config.REPORTS_DIR, f"{project_id}.json")
        if not os.path.exists(report_path):
            continue
            
        print(f"Processing project {project_id} ({project['name']})")
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        results = data.get("results", [])
        if not results:
            print("  No findings.")
            continue
            
        findings = []
        for r in results:
            path = r.get("path", "")
            line = r.get("start", {}).get("line", 0)
            cwe = r.get("check_id", "")
            severity = r.get("extra", {}).get("severity", "UNKNOWN")
            msg = r.get("extra", {}).get("message", "")
            
            # Simple deterministic finding ID
            finding_id = hashlib.md5(f"{project_id}:{path}:{line}:{cwe}".encode()).hexdigest()
            
            # Formulate semantic text
            text = f"[{severity}] Finding: {cwe} in {path}:{line}\nDescription: {msg}"
            
            findings.append({
                "finding_id": finding_id,
                "text": text,
                "metadata": {
                    "file_path": path,
                    "line_number": line,
                    "cwe_id": cwe,
                    "severity": severity,
                    "status": "needs_review", # Default to needs_review
                    "timestamp": time.time(),
                    "finding_id": finding_id
                }
            })
            
        print(f"  Embedding {len(findings)} findings...")
        vectors = embed_chunks([f["text"] for f in findings])
        write_findings(project_id, findings, vectors)
        print(f"  Successfully wrote {len(findings)} findings for {project_id}.")

if __name__ == "__main__":
    backfill()
