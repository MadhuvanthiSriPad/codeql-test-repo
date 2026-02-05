"""
CodeQL Issue Fixer using Devin API
Fetches CodeQL alerts from GitHub, sends batches to Devin for fixing.
"""

import os
import sys
import json
import time
import requests
from dataclasses import dataclass
from typing import Optional


@dataclass
class CodeQLAlert:
    number: int
    rule_id: str
    severity: str
    description: str
    file_path: str
    line_number: int
    
    def to_prompt_string(self) -> str:
        return f"- [{self.severity.upper()}] {self.description} in `{self.file_path}` at line {self.line_number} (Rule: {self.rule_id})"


class GitHubClient:
    def __init__(self, token: str, repo: str):
        self.token = token
        self.repo = repo
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
    
    def get_codeql_alerts(self, state: str = "open") -> list[CodeQLAlert]:
        url = f"{self.base_url}/repos/{self.repo}/code-scanning/alerts"
        params = {"state": state, "per_page": 100}
        
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        
        alerts = []
        for alert in response.json():
            alerts.append(CodeQLAlert(
                number=alert["number"],
                rule_id=alert["rule"]["id"],
                severity=alert["rule"]["security_severity_level"] or alert["rule"]["severity"],
                description=alert["rule"]["description"],
                file_path=alert["most_recent_instance"]["location"]["path"],
                line_number=alert["most_recent_instance"]["location"]["start_line"]
            ))
        
        return alerts


class DevinClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.devin.ai/v1"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    def create_session(self, prompt: str) -> dict:
        url = f"{self.base_url}/sessions"
        payload = {"prompt": prompt}
        
        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()
    
    def get_session(self, session_id: str) -> dict:
        url = f"{self.base_url}/sessions/{session_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()


def batch_alerts(alerts: list[CodeQLAlert], batch_size: int = 3) -> list[list[CodeQLAlert]]:
    return [alerts[i:i + batch_size] for i in range(0, len(alerts), batch_size)]


def create_fix_prompt(alerts: list[CodeQLAlert], repo: str) -> str:
    alerts_text = "\n".join(alert.to_prompt_string() for alert in alerts)
    
    return f"""You are fixing security vulnerabilities detected by CodeQL in the repository: https://github.com/{repo}

Here are the issues to fix:

{alerts_text}

Instructions:
1. Clone the repository from GitHub
2. For each issue, implement a secure fix following security best practices
3. Make sure fixes don't break existing functionality
4. Create a single pull request with all fixes
5. In the PR description, explain each fix

Security fix guidelines:
- SQL Injection: Use parameterized queries
- XSS: Escape user input, use safe templating
- Command Injection: Use subprocess with list args, avoid shell=True
- Path Traversal: Validate and sanitize file paths
- Insecure Deserialization: Avoid pickle with untrusted data, use JSON
- Weak Crypto: Use SHA-256 or better, not MD5
- Hardcoded Secrets: Use environment variables

Create the PR against the main branch."""


def main():
    github_token = os.environ.get("GITHUB_TOKEN")
    devin_api_key = os.environ.get("DEVIN_API_KEY")
    repo = os.environ.get("GITHUB_REPOSITORY")
    batch_size = int(os.environ.get("BATCH_SIZE", "3"))
    
    if not all([github_token, devin_api_key, repo]):
        print("Error: Missing required environment variables")
        print("Required: GITHUB_TOKEN, DEVIN_API_KEY, GITHUB_REPOSITORY")
        sys.exit(1)
    
    print(f"🔍 Fetching CodeQL alerts for {repo}...")
    
    github = GitHubClient(github_token, repo)
    devin = DevinClient(devin_api_key)
    
    alerts = github.get_codeql_alerts()
    
    if not alerts:
        print("✅ No open CodeQL alerts found!")
        return
    
    print(f"📋 Found {len(alerts)} open alerts")
    
    batches = batch_alerts(alerts, batch_size)
    print(f"📦 Split into {len(batches)} batches of up to {batch_size} issues each")
    
    sessions = []
    for i, batch in enumerate(batches, 1):
        print(f"\n🚀 Processing batch {i}/{len(batches)}...")
        
        prompt = create_fix_prompt(batch, repo)
        session = devin.create_session(prompt)
        session_id = session["session_id"]
        session_url = session["url"]
        
        print(f"  Created session: {session_url}")
        sessions.append({"batch": i, "url": session_url, "alerts": [a.number for a in batch]})
    
    print("\n" + "="*50)
    print("📊 SESSIONS CREATED")
    print("="*50)
    
    for s in sessions:
        print(f"\nBatch {s['batch']}: {s['url']}")
        print(f"  Alerts: {s['alerts']}")
    
    print("\n✅ Done! Check the Devin sessions for PR creation status.")


if __name__ == "__main__":
    main()