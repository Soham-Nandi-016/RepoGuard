"""
RepoGuard Core Engine
Coordinates all scanning modules, aggregates issues, calculates the repository Health Score,
and persists audit reports to the local SQLite database.
"""

import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Set

from repoguard.core.models import (
    ScanReport, ScanSummary, Issue, Severity, Category
)
from repoguard.scanners.ast_scanner import ASTScanner
from repoguard.scanners.license_auditor import LicenseAuditor
from repoguard.scanners.secrets_scanner import SecretsScanner
from repoguard.scanners.hygiene_scanner import HygieneScanner
from repoguard.core.db import db


EXCLUDE_SCAN_DIRS: Set[str] = {
    ".git", ".svn", ".hg", "__pycache__", "venv", ".venv",
    "env", ".env", "node_modules", "dist", "build", ".tox"
}


class RepoGuardEngine:
    def __init__(self):
        self.ast_scanner = ASTScanner()
        self.license_auditor = LicenseAuditor()
        self.secrets_scanner = SecretsScanner()
        self.hygiene_scanner = HygieneScanner()

    def count_scannable_files(self, repo_path: Path) -> int:
        count = 0
        for item in repo_path.rglob("*"):
            if item.is_file():
                parts = item.relative_to(repo_path).parts
                if not any(part in EXCLUDE_SCAN_DIRS for part in parts):
                    count += 1
        return max(1, count)

    def calculate_health_score(
        self,
        ast_issues: list[Issue],
        secret_issues: list[Issue],
        license_issues: list[Issue],
        hygiene_issues: list[Issue],
    ) -> tuple[int, str]:
        score = 100

        # AST Security deductions
        ast_crit = sum(1 for i in ast_issues if i.severity == Severity.CRITICAL)
        ast_warn = sum(1 for i in ast_issues if i.severity == Severity.WARNING)
        score -= min(40, ast_crit * 15)
        score -= min(20, ast_warn * 5)

        # Secrets deductions
        sec_crit = sum(1 for i in secret_issues if i.severity == Severity.CRITICAL)
        sec_warn = sum(1 for i in secret_issues if i.severity == Severity.WARNING)
        score -= min(40, sec_crit * 20)
        score -= min(20, sec_warn * 8)

        # License deductions
        lic_crit = sum(1 for i in license_issues if i.severity == Severity.CRITICAL)
        lic_warn = sum(1 for i in license_issues if i.severity == Severity.WARNING)
        score -= min(40, lic_crit * 20)
        score -= min(18, lic_warn * 6)

        # Hygiene deductions
        for h in hygiene_issues:
            if h.id.startswith("HYG-MISSING-README"):
                score -= 12
            elif h.id.startswith("HYG-MISSING-LICENSE"):
                score -= 12
            elif h.id.startswith("HYG-MISSING-GITIGNORE"):
                score -= 8
            elif h.id.startswith("HYG-MISSING-CONTRIBUTING"):
                score -= 4
            elif h.id.startswith("HYG-MISSING-SECURITY"):
                score -= 4
            elif h.id.startswith("HYG-MISSING-CODEOFCONDUCT"):
                score -= 2
            elif h.id == "HYG-ENV-001":
                score -= 15
            elif h.id in ("HYG-CACHE-001", "HYG-BINARY-001", "HYG-STUB-001"):
                score -= 5

        score = max(0, min(100, score))

        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 55:
            grade = "C"
        else:
            grade = "F"

        return score, grade

    def scan(self, repo_path: str | Path, save_to_db: bool = True) -> ScanReport:
        """Execute a full compliance and security scan on the repository."""
        start_time = time.time()
        path = Path(repo_path).resolve()
        repo_name = path.name or "Repository"

        # 1. Module A: AST Security Scanner
        ast_issues = self.ast_scanner.scan_repository(path)

        # 2. Module B: License & Dependency Auditor
        project_license, dependencies, license_issues = self.license_auditor.audit_dependencies(path)

        # 3. Module C1: Secrets Scanner
        secret_issues = self.secrets_scanner.scan_repository(path)

        # 4. Module C2: Repo Hygiene Scanner
        hygiene_checks, hygiene_issues = self.hygiene_scanner.scan_hygiene(path)

        duration = time.time() - start_time
        files_count = self.count_scannable_files(path)

        # Calculate Score
        score, grade = self.calculate_health_score(
            ast_issues, secret_issues, license_issues, hygiene_issues
        )

        all_issues = ast_issues + secret_issues + license_issues + hygiene_issues
        critical_count = sum(1 for i in all_issues if i.severity == Severity.CRITICAL)
        warning_count = sum(1 for i in all_issues if i.severity == Severity.WARNING)
        info_count = sum(1 for i in all_issues if i.severity == Severity.INFO)

        summary = ScanSummary(
            health_score=score,
            grade=grade,
            total_issues=len(all_issues),
            critical_count=critical_count,
            warning_count=warning_count,
            info_count=info_count,
            files_scanned=files_count,
            scan_duration_seconds=duration,
            project_license=project_license,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        report = ScanReport(
            repo_path=str(path),
            repo_name=repo_name,
            summary=summary,
            ast_issues=ast_issues,
            secret_issues=secret_issues,
            license_issues=license_issues,
            dependencies=dependencies,
            hygiene_checks=hygiene_checks,
            other_hygiene_issues=hygiene_issues
        )

        if save_to_db:
            try:
                db.save_scan(report.to_dict())
            except Exception:
                pass

        return report
