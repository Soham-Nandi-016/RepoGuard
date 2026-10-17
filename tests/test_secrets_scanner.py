"""Unit tests for Module C1: Secrets Scanner."""

from pathlib import Path
from repoguard.scanners.secrets_scanner import SecretsScanner, mask_secret, shannon_entropy
from repoguard.core.models import Severity


def test_mask_secret():
    assert mask_secret("12345") == "•••••"
    masked = mask_secret("sk-proj-1234567890abcdef12345678")
    assert "•" in masked
    assert not masked.startswith("sk-proj-1234567890")


def test_shannon_entropy():
    assert shannon_entropy("aaaaaaa") == 0.0
    high_entropy = shannon_entropy("u9A#kP!82zL0@m$1")
    assert high_entropy > 3.0


def test_secrets_scanner_detects_keys(tmp_path: Path):
    cfg_file = tmp_path / "secrets.py"
    cfg_file.write_text("""
OPENAI = "sk-proj-9182736450192837465019283746"
AWS_ID = "AKIA1234567890ABCDEF"
DB_URI = "postgres://admin:TopSecretPassword123@db.example.com:5432/main"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0"
""", encoding="utf-8")

    scanner = SecretsScanner()
    issues = scanner.scan_repository(tmp_path)

    rule_ids = [i.id for i in issues]
    assert "SEC-OPENAI-001" in rule_ids
    assert "SEC-AWS-001" in rule_ids
    assert "SEC-DB-001" in rule_ids
    assert "SEC-JWT-001" in rule_ids

    for issue in issues:
        assert issue.masked_value is not None
        assert "•" in issue.masked_value
