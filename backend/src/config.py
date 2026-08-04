import os

PORT = int(os.environ.get("PORT", 5000))
DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"

DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
REPOS_DIR = os.path.join(DATA_DIR, "repos")
CHROMA_DIR = os.path.join(DATA_DIR, "chroma")

OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:3b")
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

MAX_FILES_PER_REPO = int(os.environ.get("MAX_FILES_PER_REPO", 800))
SKIP_DIRS = {".git", "venv", ".venv", "__pycache__", "node_modules", "dist", "build"}
