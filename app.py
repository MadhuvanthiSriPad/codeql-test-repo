"""
Vulnerable Flask application for CodeQL testing.
Contains intentional security vulnerabilities that CodeQL will detect.
"""

from flask import Flask, request, render_template_string
from markupsafe import escape
import sqlite3
import os
import subprocess
import base64
import json
import re

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef"


def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn


# VULNERABILITY 2: SQL Injection - FIXED using parameterized queries
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = get_db_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()
    conn.close()
    return str(result)


# VULNERABILITY 3: Cross-Site Scripting (XSS) - FIXED
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # Escape user input to prevent XSS
    safe_name = escape(name)
    return render_template_string(f"<h1>Hello, {safe_name}!</h1>")


# VULNERABILITY 4: Command Injection - FIXED with input validation
@app.route('/ping')
def ping():
    host = request.args.get('host')
    if not host:
        return "No host specified", 400
    # Validate host is a valid hostname or IP address (alphanumeric, dots, hyphens only)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$', host):
        return "Invalid host format", 400
    # Use subprocess with list args to prevent command injection
    result = subprocess.check_output(['ping', '-c', '1', host])
    return result


# VULNERABILITY 5: Path Traversal - FIXED with dictionary mapping
# Map user-provided keys to actual file paths (no user input in paths)
ALLOWED_FILES = {
    'config': '/var/data/config.txt',
    'data': '/var/data/data.json',
    'readme': '/var/data/readme.txt',
    'settings': '/var/data/settings.ini'
}

@app.route('/read')
def read_file():
    file_key = request.args.get('file')
    if not file_key:
        return "No file specified", 400
    # Use dictionary lookup - user input is only used as a key, not in the path
    filepath = ALLOWED_FILES.get(file_key)
    if filepath is None:
        return "File not allowed", 403
    if not os.path.isfile(filepath):
        return "File not found", 404
    with open(filepath, 'r') as f:
        return f.read()


# VULNERABILITY 6: Insecure Deserialization - FIXED
@app.route('/load')
def load_data():
    data = request.args.get('data')
    # Use JSON instead of pickle for safe deserialization
    import json
    decoded = base64.b64decode(data)
    obj = json.loads(decoded)
    return escape(str(obj))


# FIXED: Using PBKDF2 for secure password hashing
import hashlib
import secrets

@app.route('/hash')
def hash_password():
    password = request.args.get('password')
    # Using PBKDF2 with SHA-256 - computationally expensive for password hashing
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return f"{salt}:{hashed}"


if __name__ == '__main__':
    app.run(debug=False)
