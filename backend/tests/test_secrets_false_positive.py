import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.chain import _is_false_positive

# Must NOT flag as a real secret (false positives) -> should return True
FALSE_POSITIVES = [
    "const password = e.target.password.value;",
    "const apiKey = document.getElementById('apiKeyInput').value;",
    "let token = formData.get('token');",
    "const secret = req.body.secret;",
    "const dbPassword = process.env.DB_PASSWORD;",
    "function login(password) { ... }",
    "const {password} = req.body;",
    "password = request.form['password']",
    "api_key = os.environ.get('API_KEY')",
    "secret = request.args.get('secret')",
    "token = kwargs.get('token')",
    "const password = someFunction();",
    "const token = localStorage.getItem('token');",
    "def authenticate(password): ...",
    "AKIAIOSFODNN7EXAMPLE" # Original regression
]

# Must still flag (true positives) -> should return False
TRUE_POSITIVES = [
    "const password = 'hunter2';",
    "const API_KEY = 'sk-live-abc123xyz789';",
    'const dbPassword = "prod_password_2024";',
    "password = 'admin123'",
    "AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    "DATABASE_URL = 'postgres://user:realpassword@host:5432/db'",
    "let apiKey = config.apiKey || 'default-dev-key-123';",
    "const password = btoa('admin123');",
    "const config = { apiKey: 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY' };"
]

@pytest.mark.parametrize("snippet", FALSE_POSITIVES)
def test_false_positives(snippet):
    # message contains "secret" to trigger the check
    assert _is_false_positive(snippet, "exposed secret", "test_file.js") == True, f"Failed false positive: {snippet}"

@pytest.mark.parametrize("snippet", TRUE_POSITIVES)
def test_true_positives(snippet):
    assert _is_false_positive(snippet, "exposed secret", "test_file.js") == False, f"Failed true positive: {snippet}"
