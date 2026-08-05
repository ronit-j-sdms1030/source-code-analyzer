import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

PORT = int(os.environ.get("PORT", 5000))
DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
REPOS_DIR = os.path.join(DATA_DIR, "repos")
CHROMA_DIR = os.path.join(DATA_DIR, "chroma")
REPORTS_DIR = os.path.join(DATA_DIR, "reports")

CLOUD_API_URL = os.environ.get("CLOUD_API_URL", "https://openrouter.ai/api/v1")
CLOUD_API_KEY = os.environ.get("CLOUD_API_KEY", "")
CLOUD_MODEL = os.environ.get("CLOUD_MODEL", "meta-llama/llama-3.1-8b-instruct")

EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

MAX_FILES_PER_REPO = int(os.environ.get("MAX_FILES_PER_REPO", 800))
SKIP_DIRS = {".git", "venv", ".venv", "__pycache__", "node_modules", "dist", "build"}
