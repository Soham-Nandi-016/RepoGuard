"""
Clean Sample: Secure API Application
Demonstrates best practices: ast.literal_eval, subprocess with shell=False,
parameterized SQL queries, and environment variable loading.
"""

import os
import ast
import sqlite3
import subprocess
import json


def parse_user_payload(raw_json: str):
    """Safely parse user data using JSON or literal_eval."""
    try:
        return json.loads(raw_json)
    except json.JSONDecodeError:
        return ast.literal_eval(raw_json)


def execute_safe_system_command(target_host: str):
    """Safely invoke external command with shell=False and argument list."""
    proc = subprocess.run(["ping", "-n", "1", target_host], shell=False, check=False)
    return proc.returncode


def get_user_by_id(cursor: sqlite3.Cursor, user_id: int):
    """Safely query database using parameterized placeholder query."""
    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def get_secret_config():
    """Load credentials from environment variables, not source code."""
    api_key = os.environ.get("SERVICE_API_KEY", "")
    db_url = os.environ.get("DATABASE_URL", "")
    return {"api_key": api_key, "db_url": db_url}


if __name__ == "__main__":
    print("Clean application initialized securely.")
