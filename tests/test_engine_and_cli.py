"""Integration tests for RepoGuard Engine and CLI reporting."""

from pathlib import Path
from repoguard.core.engine import RepoGuardEngine
from repoguard.reporting.html_report import generate_html_report
from repoguard.reporting.json_report import generate_json_report


def test_vulnerable_repo_scan():
    engine = RepoGuardEngine()
    repo_path = Path("samples/vulnerable_repo").resolve()

    report = engine.scan(repo_path, save_to_db=False)

    assert report.summary.health_score < 60
    assert report.summary.grade in ("C", "F")
    assert report.summary.critical_count > 0

    # Ensure AST issues detected
    ast_rule_ids = [i.id for i in report.ast_issues]
    assert "AST-SEC-001" in ast_rule_ids  # eval
    assert "AST-SEC-002" in ast_rule_ids  # exec
    assert "AST-SEC-003" in ast_rule_ids  # os.system
    assert "AST-SEC-005" in ast_rule_ids  # shell=True
    assert "AST-SQL-001" in ast_rule_ids  # SQLi
    assert "AST-DESER-001" in ast_rule_ids  # pickle

    # Ensure Secrets detected
    sec_rule_ids = [i.id for i in report.secret_issues]
    assert "SEC-OPENAI-001" in sec_rule_ids
    assert "SEC-AWS-001" in sec_rule_ids
    assert "SEC-DB-001" in sec_rule_ids

    # Ensure License conflicts detected
    lic_rule_ids = [i.id for i in report.license_issues]
    assert "LIC-CONFLICT-001" in lic_rule_ids

    # Ensure HTML report generates without errors
    html = generate_html_report(report)
    assert "<html" in html
    assert "RepoGuard" in html
    assert "vulnerable_repo" in html

    # Ensure JSON report serializes properly
    json_str = generate_json_report(report)
    assert "health_score" in json_str


def test_clean_repo_scan():
    engine = RepoGuardEngine()
    repo_path = Path("samples/clean_repo").resolve()

    report = engine.scan(repo_path, save_to_db=False)

    assert report.summary.health_score >= 90
    assert report.summary.grade in ("A+", "A")
    assert report.summary.critical_count == 0
    assert len(report.ast_issues) == 0
    assert len(report.secret_issues) == 0
    assert len(report.license_issues) == 0
