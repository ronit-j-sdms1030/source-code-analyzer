import os
import subprocess
import threading
import time
import requests
import uuid
from . import config
from .memory import save_quality_metrics, get_sonar_credentials, save_sonar_credentials, get_quality_metrics

def _ensure_sonar_setup(project_id: str = None) -> dict:
    """Ensures SonarQube is up, rotates the default password, and generates a scanner token."""
    creds = get_sonar_credentials()
    if creds.get("token") and creds.get("password"):
        return creds

    base_url = "http://127.0.0.1:9000"
    max_wait_polls = 100

    # 1. Wait for SonarQube to be UP (can take 1-2 mins on fresh start)
    print("Waiting for SonarQube to boot up on 127.0.0.1:9000 (this can take 3-5 minutes on first run)...")
    for i in range(max_wait_polls):
        if project_id:
            save_quality_metrics(project_id, {
                "status": "running",
                "stage": "Waiting for SonarQube to boot up (first run only)",
                "percent": round(4 * (i + 1) / max_wait_polls),
            })
        try:
            r = requests.get(f"{base_url}/api/system/status", timeout=2)
            if r.status_code == 200 and r.json().get("status") == "UP":
                break
        except Exception:
            pass
        time.sleep(3)
    else:
        raise Exception("SonarQube did not become available within 5 minutes. This might happen on slower hardware during a cold boot. Please check 'docker logs sonarqube' for details.")
        
    print("SonarQube is UP. Setting up secure credentials...")
    
    # 2. Change password from admin/admin to a secure UUID
    new_password = str(uuid.uuid4())
    try:
        r = requests.post(
            f"{base_url}/api/users/change_password",
            params={"login": "admin", "previousPassword": "admin", "password": new_password},
            auth=("admin", "admin")
        )
        if r.status_code not in (200, 204):
            # If it fails, maybe it was already changed by the user manually or from a previous run?
            # We'll just try to authenticate with the existing default pass just in case
            pass
    except Exception as e:
        print("Warning: failed to change password:", e)
        
    current_password = new_password if r.status_code in (200, 204) else "admin"

    # 3. Generate a scanner token
    token_name = f"scanner-token-{uuid.uuid4().hex[:8]}"
    token_value = None
    try:
        r = requests.post(
            f"{base_url}/api/user_tokens/generate",
            params={"name": token_name},
            auth=("admin", current_password)
        )
        if r.status_code == 200:
            token_value = r.json().get("token")
        else:
            raise Exception(f"Failed to generate token: {r.text}")
    except Exception as e:
        raise Exception(f"Token generation error: {e}")

    creds = {
        "password": current_password,
        "token": token_value
    }
    save_sonar_credentials(creds)
    print("SonarQube secure setup complete.")
    return creds


def start_quality_scan(project_id: str):
    """Kicks off an asynchronous SonarQube Community Edition code quality scan."""
    repo_path = os.path.abspath(os.path.join(config.REPOS_DIR, project_id))
    if not os.path.exists(repo_path):
        save_quality_metrics(project_id, {"status": "error", "error": "Repo not found"})
        return
        
    save_quality_metrics(project_id, {"status": "running", "stage": "Starting SonarScanner", "percent": 0})

    thread = threading.Thread(target=_run_sonar_scan, args=(project_id, repo_path))
    thread.daemon = True
    thread.start()

def _run_sonar_scan(project_id: str, repo_path: str):
    try:
        creds = _ensure_sonar_setup(project_id)
    except Exception as e:
        save_quality_metrics(project_id, {"status": "error", "error": f"Sonar setup failed: {str(e)}"})
        return

    token = creds.get("token")
    # Setup scanner container with host networking to reach localhost:9000
    cmd = [
        "docker", "run", "--rm",
        "--name", f"sonar-scanner-{project_id}",
        "-v", f"{repo_path}:/usr/src",
        "--network", "host",
        "sonarsource/sonar-scanner-cli",
        f"-Dsonar.projectKey={project_id}",
        "-Dsonar.host.url=http://127.0.0.1:9000",
        f"-Dsonar.token={token}"
    ]

    # The scanner CLI doesn't expose real-time progress, so estimate it: percent
    # climbs asymptotically toward 78% the longer the scan runs, and only completes
    # once the process actually exits. Capped short of 80% so it never looks "done"
    # while still running.
    stop_progress = threading.Event()

    def _tick_scan_progress():
        start = time.time()
        while not stop_progress.wait(2):
            if get_quality_metrics(project_id).get("status") == "cancelled":
                return
            elapsed = time.time() - start
            pct = 5 + round(73 * (1 - 0.5 ** (elapsed / 45.0)))
            save_quality_metrics(project_id, {"status": "running", "stage": "Scanning codebase", "percent": min(pct, 78)})

    try:
        save_quality_metrics(project_id, {"status": "running", "stage": "Scanning codebase", "percent": 5})
        progress_thread = threading.Thread(target=_tick_scan_progress, daemon=True)
        progress_thread.start()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
        finally:
            stop_progress.set()
            progress_thread.join(timeout=2)

        if result.returncode != 0:
            # If the container was killed by stop, it will return non-zero
            print("SonarScanner failed or was cancelled:", result.stderr)
            # Only update status to error if it wasn't already marked as cancelled
            current = get_quality_metrics(project_id)
            if current.get("status") != "cancelled":
                save_quality_metrics(project_id, {"status": "error", "error": "Scanner failed. See logs for details."})
            return

        save_quality_metrics(project_id, {"status": "running", "stage": "Processing results on SonarQube", "percent": 80})
        _poll_and_fetch_metrics(project_id, creds.get("password"), repo_path)

    except Exception as e:
        print("Exception in sonar scan:", e)
        save_quality_metrics(project_id, {"status": "error", "error": str(e)})

def cancel_quality_scan(project_id: str):
    """Cancels a running SonarQube scan by stopping its docker container."""
    save_quality_metrics(project_id, {"status": "cancelled", "error": "Scan was stopped by the user."})
    subprocess.run(["docker", "stop", f"sonar-scanner-{project_id}"], capture_output=True)

def _read_snippet(repo_path: str, rel_path: str, start_line: int, end_line: int = None, context: int = 2, cache: dict = None) -> str:
    """Reads a small window of source lines around start_line..end_line for a preview snippet."""
    if not repo_path or not rel_path or not start_line:
        return ""
    try:
        abs_path = os.path.join(repo_path, rel_path)
        if cache is not None and abs_path in cache:
            lines = cache[abs_path]
        else:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
            if cache is not None:
                cache[abs_path] = lines
        end_line = end_line or start_line
        from_idx = max(0, start_line - 1 - context)
        to_idx = min(len(lines), end_line + context)
        return "\n".join(lines[from_idx:to_idx])
    except Exception:
        return ""


def _fetch_code_smells(base_url: str, auth: tuple, project_id: str, repo_path: str = None) -> list:
    """Fetches the list of individual code smell issues for a project, with a source snippet for each."""
    smells = []
    file_cache = {}
    try:
        page = 1
        while page <= 10:  # cap at 1000 issues
            r = requests.get(
                f"{base_url}/api/issues/search",
                params={"componentKeys": project_id, "types": "CODE_SMELL", "ps": 100, "p": page},
                auth=auth,
            )
            if r.status_code != 200:
                break
            data = r.json()
            issues = data.get("issues", [])
            for issue in issues:
                component = issue.get("component", "")
                file_path = component.split(":", 1)[-1] if ":" in component else component
                line = issue.get("line")
                smells.append({
                    "rule": issue.get("rule"),
                    "message": issue.get("message"),
                    "severity": issue.get("severity"),
                    "file": file_path,
                    "line": line,
                    "snippet": _read_snippet(repo_path, file_path, line, cache=file_cache),
                })
            total = data.get("paging", {}).get("total", 0)
            if not issues or page * 100 >= total:
                break
            page += 1
    except Exception as e:
        print("Failed to fetch code smells:", e)
    return smells


def _fetch_duplications(base_url: str, auth: tuple, project_id: str, repo_path: str = None) -> list:
    """Fetches duplicated code blocks, grouped by the file that contains them."""
    duplications = []
    file_cache = {}
    try:
        r = requests.get(
            f"{base_url}/api/measures/component_tree",
            params={"component": project_id, "metricKeys": "duplicated_lines", "qualifiers": "FIL", "ps": 500},
            auth=auth,
        )
        if r.status_code != 200:
            return duplications

        dup_file_keys = []
        for comp in r.json().get("components", []):
            measures = comp.get("measures", [])
            if measures and int(measures[0].get("value", 0) or 0) > 0:
                dup_file_keys.append((comp.get("key"), comp.get("path", comp.get("key"))))

        for file_key, file_path in dup_file_keys[:50]:  # cap to avoid excessive API calls
            dr = requests.get(f"{base_url}/api/duplications/show", params={"key": file_key}, auth=auth)
            if dr.status_code != 200:
                continue
            dup_data = dr.json()
            files_by_ref = dup_data.get("files", {})
            for group in dup_data.get("duplications", []):
                blocks = []
                for b in group.get("blocks", []):
                    ref_info = files_by_ref.get(b.get("_ref", "1"), {})
                    block_file = ref_info.get("name", file_path)
                    from_line = b.get("from")
                    size = b.get("size")
                    end_line = (from_line + size - 1) if from_line and size else None
                    blocks.append({
                        "file": block_file,
                        "from_line": from_line,
                        "size": size,
                        "snippet": _read_snippet(repo_path, block_file, from_line, end_line, context=0, cache=file_cache),
                    })
                if blocks:
                    duplications.append({"source_file": file_path, "blocks": blocks})
    except Exception as e:
        print("Failed to fetch duplications:", e)
    return duplications


def _poll_and_fetch_metrics(project_id: str, password: str, repo_path: str = None):
    base_url = "http://127.0.0.1:9000"
    auth = ("admin", password)

    # Poll for CE task completion (max ~2 mins). Percent climbs 80 -> 99 deterministically
    # with each poll, since this loop has a known, fixed number of iterations.
    max_polls = 60
    for i in range(max_polls):
        time.sleep(2)
        if get_quality_metrics(project_id).get("status") == "cancelled":
            return
        save_quality_metrics(project_id, {
            "status": "running",
            "stage": "Processing results on SonarQube",
            "percent": min(80 + round(19 * (i + 1) / max_polls), 99),
        })
        try:
            r = requests.get(f"{base_url}/api/ce/component", params={"component": project_id}, auth=auth)
            if r.status_code == 200:
                data = r.json()
                queue = data.get("queue", [])
                current = data.get("current")
                if not queue and not (current and current.get("status") in ["PENDING", "IN_PROGRESS"]):
                    # Wait just a bit longer to ensure database is updated
                    time.sleep(1)
                    break
        except Exception:
            pass

    if get_quality_metrics(project_id).get("status") == "cancelled":
        return

    # Fetch final code quality measures
    metrics_keys = "sqale_rating,code_smells,duplicated_lines_density,complexity,coverage,ncloc"
    try:
        r = requests.get(f"{base_url}/api/measures/component",
                         params={"component": project_id, "metricKeys": metrics_keys},
                         auth=auth)
        if r.status_code == 200:
            if get_quality_metrics(project_id).get("status") == "cancelled":
                return
            measures = r.json().get("component", {}).get("measures", [])
            results = {"status": "complete", "percent": 100}
            for m in measures:
                results[m["metric"]] = m["value"]
            results["code_smells_list"] = _fetch_code_smells(base_url, auth, project_id, repo_path)
            results["duplications"] = _fetch_duplications(base_url, auth, project_id, repo_path)
            if get_quality_metrics(project_id).get("status") == "cancelled":
                return
            save_quality_metrics(project_id, results)
        else:
            save_quality_metrics(project_id, {"status": "error", "error": f"Failed to fetch metrics: {r.text}"})
    except Exception as e:
        save_quality_metrics(project_id, {"status": "error", "error": str(e)})
