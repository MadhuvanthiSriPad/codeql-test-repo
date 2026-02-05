"""
Vulnerable Flask application for CodeQL testing.
Contains intentional security vulnerabilities that CodeQL will detect.
"""

from flask import Flask, request, render_template_string
import sqlite3
import os
import subprocess
import base64
import json

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


# VULNERABILITY 3: Cross-Site Scripting (XSS)
@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    # Directly rendering user input without escaping
    return render_template_string(f"<h1>Hello, {name}!</h1>")


# VULNERABILITY 4: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Directly passing user input to shell command
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
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


# VULNERABILITY 6: Insecure Deserialization - FIXED using JSON instead of pickle
@app.route('/load')
def load_data():
    data = request.args.get('data')
    if not data:
        return "No data provided", 400
    try:
        decoded = base64.b64decode(data)
        obj = json.loads(decoded)
        return str(obj)
    except (json.JSONDecodeError, ValueError) as e:
        return f"Invalid JSON data: {str(e)}", 400


# VULNERABILITY 7: Weak Cryptography
import hashlib

@app.route('/hash')
def hash_password():
    password = request.args.get('password')
    # Using weak MD5 hash
    hashed = hashlib.md5(password.encode()).hexdigest()
    return hashed


if __name__ == '__main__':
    app.run(debug=True)
