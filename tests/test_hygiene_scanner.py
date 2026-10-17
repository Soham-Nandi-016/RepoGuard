"""Unit tests for Module C2: Repo Hygiene Scanner."""

from pathlib import Path
from repoguard.scanners.hygiene_scanner import HygieneScanner
from repoguard.core.models import Severity


def test_hygiene_scanner_detects_missing_files(tmp_path: Path):
    scanner = HygieneScanner()
    checks, issues = scanner.scan_hygiene(tmp_path)

    check_names = {c.file_name: c for c in checks}
    assert "README.md" in check_names
    assert check_names["README.md"].exists is False

    assert "LICENSE" in check_names
    assert check_names["LICENSE"].exists is False

    assert ".gitignore" in check_names
    assert check_names[".gitignore"].exists is False


def test_hygiene_scanner_detects_committed_env(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET_KEY=12345\n", encoding="utf-8")

    scanner = HygieneScanner()
    _, issues = scanner.scan_hygiene(tmp_path)

    env_issues = [i for i in issues if i.id == "HYG-ENV-001"]
    assert len(env_issues) == 1
    assert env_issues[0].severity == Severity.CRITICAL


def test_hygiene_scanner_all_intact(tmp_path: Path):
    for name in ["README.md", "LICENSE", ".gitignore", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md"]:
        f = tmp_path / name
        f.write_text(f"# {name}\nDetailed substantive content exceeding minimum length thresholds for test verification.\n", encoding="utf-8")

    scanner = HygieneScanner()
    checks, issues = scanner.scan_hygiene(tmp_path)

    for c in checks:
        assert c.exists is True
        assert c.status == "PASS"

    assert len(issues) == 0
