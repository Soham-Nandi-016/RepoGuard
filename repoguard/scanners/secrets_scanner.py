"""
RepoGuard Module C1: Secrets Scanner
Detects hardcoded secrets, API tokens, database URIs, private keys, and JWTs using regex and entropy validation.
"""

import math
import re
from pathlib import Path
from typing import List, Dict, Pattern, Set, Any
from repoguard.core.models import Issue, Category, Severity


EXCLUDE_EXTS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".pdf", ".pyc", ".db",
    ".sqlite", ".sqlite3", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mov", ".avi", ".weights", ".bin", ".pt", ".pth"
}

EXCLUDE_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "__pycache__", "venv", ".venv",
    "env", ".env", "node_modules", "dist", "build", ".tox",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "site-packages"
}


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy += - p_x * math.log2(p_x)
    return entropy


def mask_secret(secret: str) -> str:
    """Mask confidential tokens for safe reporting."""
    if len(secret) <= 8:
        return "•" * len(secret)
    prefix_len = min(6, len(secret) // 4)
    suffix_len = min(4, len(secret) // 4)
    return f"{secret[:prefix_len]}{'•' * 8}{secret[-suffix_len:]}"


SECRET_RULES: List[Dict[str, Any]] = [
    {
        "id": "SEC-OPENAI-001",
        "title": "Hardcoded OpenAI API Key",
        "severity": Severity.CRITICAL,
        "regex": re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b"),
        "description": "Detected hardcoded OpenAI API key. Exposed keys allow unauthorized API usage, incurring financial costs and data leaks.",
        "recommendation": "Revoke the key immediately from the OpenAI platform dashboard. Store keys in environment variables (e.g. os.environ['OPENAI_API_KEY']) or secrets managers.",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-AWS-001",
        "title": "Hardcoded AWS Access Key ID",
        "severity": Severity.CRITICAL,
        "regex": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "description": "Detected Amazon Web Services (AWS) Access Key ID. Exposed AWS credentials can allow full compromise of cloud infrastructure.",
        "recommendation": "Deactivate this IAM access key immediately in AWS IAM Console. Use AWS IAM Roles, AWS Secrets Manager, or ~/.aws/credentials.",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-AWS-002",
        "title": "Potential AWS Secret Access Key",
        "severity": Severity.CRITICAL,
        "regex": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "description": "Detected an AWS Secret Access Key pattern paired with access credentials.",
        "recommendation": "Rotate your AWS IAM key pair immediately. Use IAM Instance Profiles or federated SSO credentials instead of hardcoded strings.",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-DB-001",
        "title": "Hardcoded Database Connection String with Credentials",
        "severity": Severity.CRITICAL,
        "regex": re.compile(r"\b((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)://[a-zA-Z0-9_\-\.]+:[^@\s'\"<>]+@[a-zA-Z0-9_\-\.:]+(?:/[a-zA-Z0-9_\-\.\?]*)?)\b"),
        "description": "Database connection URL containing plaintext username and password credentials.",
        "recommendation": "Remove plaintext credentials from source code. Load connection strings via environment variables or secret vaults.",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-JWT-001",
        "title": "Exposed JSON Web Token (JWT)",
        "severity": Severity.WARNING,
        "regex": re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "description": "Detected a hardcoded JSON Web Token. Tokens in source code may grant unauthorized session authorization or reveal sensitive claims.",
        "recommendation": "Do not hardcode authentication tokens. Generate tokens dynamically at runtime or inject test tokens during testing through environment config.",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-GH-001",
        "title": "Hardcoded GitHub Personal Access Token",
        "severity": Severity.CRITICAL,
        "regex": re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
        "description": "Detected GitHub Personal Access Token. This grants unauthorized access to private repositories, code, and organization workflows.",
        "recommendation": "Revoke this token immediately on GitHub Settings -> Developer Settings -> Personal Access Tokens. Use GitHub Actions secrets or environment variables.",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-SLACK-001",
        "title": "Exposed Slack Token / Incoming Webhook",
        "severity": Severity.CRITICAL,
        "regex": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48}|https://hooks\.slack\.com/services/T[0-9A-Z_]+/B[0-9A-Z_]+/[0-9A-Za-z_]+)\b"),
        "description": "Detected Slack Bot token, user token, or incoming webhook URL.",
        "recommendation": "Invalidate the Slack token / webhook in the Slack App Management console. Store tokens in environment variables.",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-KEY-001",
        "title": "Private Cryptographic Key",
        "severity": Severity.CRITICAL,
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "description": "Plaintext private cryptographic key block discovered in file.",
        "recommendation": "Never commit private keys to version control. Store keys in a secure key management system (KMS) or local key storage with strict filesystem permissions.",
        "cwe_id": "CWE-312"
    },
    {
        "id": "SEC-STRIPE-001",
        "title": "Live Stripe Secret Key",
        "severity": Severity.CRITICAL,
        "regex": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,32})\b"),
        "description": "Detected live Stripe API secret key. Anyone with this key can charge cards, refund payments, and access customer financial records.",
        "recommendation": "Roll this API key immediately in the Stripe Dashboard. Use environment variables and restricted API keys.",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-GOOGLE-001",
        "title": "Google / Firebase API Key",
        "severity": Severity.WARNING,
        "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "description": "Detected Google Cloud / Firebase API key. Unrestricted keys can lead to unauthorized API quota consumption and cloud charges.",
        "recommendation": "Apply API key restrictions in Google Cloud Console (HTTP referrer, IP address, or API service constraints).",
        "cwe_id": "CWE-798"
    },
    {
        "id": "SEC-GENERIC-001",
        "title": "Hardcoded High-Entropy Secret / Token Assignment",
        "severity": Severity.WARNING,
        "regex": re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]"),
        "description": "Detected variable assignment indicating a high-entropy secret token or password.",
        "recommendation": "Store application secrets in environment variables or configuration files that are excluded from git via .gitignore.",
        "cwe_id": "CWE-798"
    }
]


class SecretsScanner:
    """Scans repository files for committed secrets, credentials, tokens, and cryptographic keys."""

    def scan_file(self, file_path: Path, repo_root: Path) -> List[Issue]:
        issues: List[Issue] = []
        if file_path.suffix.lower() in EXCLUDE_EXTS:
            return issues

        try:
            rel_path = str(file_path.relative_to(repo_root)).replace("\\", "/")
            # Avoid scanning huge files > 2MB
            if file_path.stat().st_size > 2 * 1024 * 1024:
                return issues

            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()

            for line_idx, line in enumerate(lines, start=1):
                # Ignore comment-only lines that are explicit documentation placeholders
                stripped = line.strip()
                if stripped.startswith(("#", "//", "/*", "*")):
                    line_lower = stripped.lower()
                    if "placeholder" in line_lower or "your-key-here" in line_lower or "foo-bar" in line_lower:
                        continue

                for rule in SECRET_RULES:
                    pattern: Pattern = rule["regex"]
                    matches = pattern.finditer(line)
                    for match in matches:
                        # Extract matching secret string
                        secret_val = match.group(1) if match.groups() else match.group(0)

                        # For generic keys, verify Shannon entropy to prevent false positives on simple test words
                        if rule["id"] == "SEC-GENERIC-001":
                            if shannon_entropy(secret_val) < 3.2:
                                continue

                        masked = mask_secret(secret_val)
                        col_idx = match.start() + 1

                        # Form snippet
                        start_line = max(1, line_idx - 1)
                        end_line = min(len(lines), line_idx + 1)
                        snippet_parts = []
                        for idx in range(start_line, end_line + 1):
                            prefix = ">" if idx == line_idx else " "
                            l_text = lines[idx - 1].rstrip("\r\n")
                            # Mask secret inside snippet line
                            if idx == line_idx:
                                l_text = l_text.replace(secret_val, masked)
                            snippet_parts.append(f"{prefix} {idx:4d} | {l_text}")
                        snippet = "\n".join(snippet_parts)

                        issues.append(Issue(
                            id=rule["id"],
                            category=Category.SECRETS_LEAK,
                            severity=rule["severity"],
                            title=rule["title"],
                            description=rule["description"],
                            file_path=rel_path,
                            line_number=line_idx,
                            column_number=col_idx,
                            code_snippet=snippet,
                            recommendation=rule["recommendation"],
                            cwe_id=rule["cwe_id"],
                            masked_value=masked
                        ))
        except Exception:
            pass

        return issues

    def scan_repository(self, repo_path: Path) -> List[Issue]:
        all_issues: List[Issue] = []
        repo_path = Path(repo_path).resolve()

        if not repo_path.exists():
            return all_issues

        for item in repo_path.rglob("*"):
            if not item.is_file():
                continue
            parts = item.relative_to(repo_path).parts
            if any(part in EXCLUDE_DIRS for part in parts):
                continue
            issues = self.scan_file(item, repo_path)
            all_issues.extend(issues)

        return all_issues
