import os
import subprocess
import threading
import time
import requests
import uuid
from . import config
from .memory import save_quality_metrics, get_sonar_credentials, save_sonar_credentials

def _ensure_sonar_setup() -> dict:
    """Ensures SonarQube is up, rotates the default password, and generates a scanner token."""
    creds = get_sonar_credentials()
    if creds.get("token") and creds.get("password"):
        return creds

    base_url = "http://127.0.0.1:9000"
    
    # 1. Wait for SonarQube to be UP (can take 1-2 mins on fresh start)
    print("Waiting for SonarQube to boot up on 127.0.0.1:9000 (this can take 3-5 minutes on first run)...")
    for _ in range(100):
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
        
    save_quality_metrics(project_id, {"status": "running", "stage": "Starting SonarScanner"})
    
    thread = threading.Thread(target=_run_sonar_scan, args=(project_id, repo_path))
    thread.daemon = True
    thread.start()

def _run_sonar_scan(project_id: str, repo_path: str):
    try:
        creds = _ensure_sonar_setup()
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
    
    try:
        save_quality_metrics(project_id, {"status": "running", "stage": "Scanning codebase"})
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            # If the container was killed by stop, it will return non-zero
            print("SonarScanner failed or was cancelled:", result.stderr)
            # Only update status to error if it wasn't already marked as cancelled
            from .memory import get_quality_metrics
            current = get_quality_metrics(project_id)
            if current.get("status") != "cancelled":
                save_quality_metrics(project_id, {"status": "error", "error": "Scanner failed. See logs for details."})
            return
            
        save_quality_metrics(project_id, {"status": "running", "stage": "Processing results on SonarQube"})
        _poll_and_fetch_metrics(project_id, creds.get("password"))
        
    except Exception as e:
        print("Exception in sonar scan:", e)
        save_quality_metrics(project_id, {"status": "error", "error": str(e)})

def cancel_quality_scan(project_id: str):
    """Cancels a running SonarQube scan by stopping its docker container."""
    save_quality_metrics(project_id, {"status": "cancelled", "error": "Scan was stopped by the user."})
    subprocess.run(["docker", "stop", f"sonar-scanner-{project_id}"], capture_output=True)

def _poll_and_fetch_metrics(project_id: str, password: str):
    base_url = "http://127.0.0.1:9000"
    auth = ("admin", password)
    
    # Poll for CE task completion (max ~2 mins)
    for _ in range(60):
        time.sleep(2)
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
            
    # Fetch final code quality measures
    metrics_keys = "sqale_rating,code_smells,duplicated_lines_density,complexity,coverage,ncloc"
    try:
        r = requests.get(f"{base_url}/api/measures/component", 
                         params={"component": project_id, "metricKeys": metrics_keys}, 
                         auth=auth)
        if r.status_code == 200:
            measures = r.json().get("component", {}).get("measures", [])
            results = {"status": "complete"}
            for m in measures:
                results[m["metric"]] = m["value"]
            save_quality_metrics(project_id, results)
        else:
            save_quality_metrics(project_id, {"status": "error", "error": f"Failed to fetch metrics: {r.text}"})
    except Exception as e:
        save_quality_metrics(project_id, {"status": "error", "error": str(e)})
