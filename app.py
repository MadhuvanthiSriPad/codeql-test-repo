"""
Vulnerable Flask application for CodeQL testing.
Contains intentional security vulnerabilities that CodeQL will detect.
"""

from flask import Flask, request, render_template_string
from markupsafe import escape
import sqlite3
import os
import subprocess
import pickle
import base64

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-1234567890abcdef"


def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn


# VULNERABILITY 2: SQL Injection
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = get_db_connection()
    cursor = conn.cursor()
    # Directly interpolating user input into SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
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


# VULNERABILITY 4: Command Injection - FIXED
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Use subprocess with list args to prevent command injection
    result = subprocess.check_output(['ping', '-c', '1', host])
    return result


# VULNERABILITY 5: Path Traversal
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    # No validation of file path
    filepath = os.path.join('/var/data/', filename)
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
