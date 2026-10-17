"""
Vulnerable Sample: Main API Application
Demonstrates dangerous AST calls: eval, exec, os.system, shell=True, and verify=False.
"""

import os
import subprocess
import requests
import tempfile


def run_user_code(user_input: str):
    # Flagged: AST-SEC-001 - Dangerous eval()
    result = eval(user_input)
    return result


def execute_script(script_text: str):
    # Flagged: AST-SEC-002 - Dangerous exec()
    exec(script_text)


def ping_host(host: str):
    # Flagged: AST-SEC-003 - Insecure os.system() command execution
    os.system("ping -c 1 " + host)


def run_backup(archive_name: str):
    # Flagged: AST-SEC-005 - subprocess with shell=True
    cmd = f"tar -czf {archive_name}.tar.gz /data"
    proc = subprocess.Popen(cmd, shell=True)
    proc.wait()


def fetch_internal_metrics(url: str):
    # Flagged: AST-NET-001 - Disabled SSL verification
    resp = requests.get(url, verify=False)
    return resp.json()


def create_temp_cache():
    # Flagged: AST-SEC-010 - Insecure tempfile.mktemp()
    temp_path = tempfile.mktemp()
    return temp_path


if __name__ == "__main__":
    print("Vulnerable application running...")
