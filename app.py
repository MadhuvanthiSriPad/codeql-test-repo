"""
Vulnerable Flask application for CodeQL testing.
Contains intentional security vulnerabilities that CodeQL will detect.
"""

from flask import Flask, request, render_template_string, Response
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
    # Validate host is a valid hostname or IP address (no special characters)
    # Allow only alphanumeric characters, dots, and hyphens
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$', host):
        return "Invalid host format", 400
    # Use subprocess with list args to prevent command injection
    result = subprocess.check_output(['ping', '-c', '1', host])
    return result


# VULNERABILITY 5: Path Traversal - FIXED with path validation
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    if not filename:
        return "No file specified", 400
    base_dir = '/var/data/'
    filepath = os.path.join(base_dir, filename)
    real_filepath = os.path.realpath(filepath)
    if not real_filepath.startswith(os.path.realpath(base_dir)):
        return "Access denied", 403
    with open(real_filepath, 'r') as f:
        return f.read()


# VULNERABILITY 6: Insecure Deserialization - FIXED with proper error handling
@app.route('/load')
def load_data():
    data = request.args.get('data')
    if not data:
        return "No data specified", 400
    try:
        # Use JSON instead of pickle for safe deserialization
        decoded = base64.b64decode(data)
        obj = json.loads(decoded)
        # Return as plain text with proper content type to prevent XSS
        return Response(str(obj), mimetype='text/plain')
    except (ValueError, json.JSONDecodeError, base64.binascii.Error):
        # Return generic error message to avoid exposing stack traces
        return "Invalid data format", 400


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
