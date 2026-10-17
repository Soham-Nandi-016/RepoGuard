"""
RepoGuard Core Data Models
Definitions for issues, scan results, severity classifications, and summaries.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"
    PASS = "PASS"

    @property
    def color(self) -> str:
        if self == Severity.CRITICAL:
            return "rose"
        elif self == Severity.WARNING:
            return "amber"
        elif self == Severity.PASS:
            return "emerald"
        return "slate"

    @property
    def badge_class(self) -> str:
        if self == Severity.CRITICAL:
            return "bg-rose-50 text-rose-700 border-rose-200"
        elif self == Severity.WARNING:
            return "bg-amber-50 text-amber-700 border-amber-200"
        elif self == Severity.PASS:
            return "bg-emerald-50 text-emerald-700 border-emerald-200"
        return "bg-slate-50 text-slate-700 border-slate-200"


class Category(str, Enum):
    AST_SECURITY = "AST_SECURITY"
    LICENSE_COMPLIANCE = "LICENSE_COMPLIANCE"
    SECRETS_LEAK = "SECRETS_LEAK"
    REPO_HYGIENE = "REPO_HYGIENE"


class LicenseCategory(str, Enum):
    PERMISSIVE = "Permissive"
    WEAK_COPYLEFT = "Weak Copyleft"
    STRONG_COPYLEFT = "Strong Copyleft"
    NETWORK_COPYLEFT = "Network Copyleft"
    PROPRIETARY = "Proprietary"
    UNKNOWN = "Unknown"


@dataclass
class LicenseInfo:
    name: str
    spdx_id: str
    category: LicenseCategory
    is_copyleft: bool = False
    compatibility: str = "COMPATIBLE"  # COMPATIBLE, WARNING, INCOMPATIBLE
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "spdx_id": self.spdx_id,
            "category": self.category.value if isinstance(self.category, LicenseCategory) else self.category,
            "is_copyleft": self.is_copyleft,
            "compatibility": self.compatibility,
            "details": self.details,
        }


@dataclass
class DependencyAudit:
    package_name: str
    specified_version: str
    license: LicenseInfo
    source: str = "PyPI"
    pypi_url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "specified_version": self.specified_version,
            "license": self.license.to_dict(),
            "source": self.source,
            "pypi_url": self.pypi_url or f"https://pypi.org/pypi/{self.package_name}/json",
        }


@dataclass
class Issue:
    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str = ""
    cwe_id: Optional[str] = None
    masked_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value if isinstance(self.category, Category) else self.category,
            "severity": self.severity.value if isinstance(self.severity, Severity) else self.severity,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
            "masked_value": self.masked_value,
        }


@dataclass
class HygieneCheck:
    file_name: str
    required: bool
    exists: bool
    file_size_bytes: int = 0
    status: str = "PASS"  # PASS, FAIL, WARNING
    description: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "required": self.required,
            "exists": self.exists,
            "file_size_bytes": self.file_size_bytes,
            "status": self.status,
            "description": self.description,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanSummary:
    health_score: int = 100
    grade: str = "A+"
    total_issues: int = 0
    critical_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    files_scanned: int = 0
    scan_duration_seconds: float = 0.0
    project_license: Optional[LicenseInfo] = None
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "health_score": self.health_score,
            "grade": self.grade,
            "total_issues": self.total_issues,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "files_scanned": self.files_scanned,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "project_license": self.project_license.to_dict() if self.project_license else None,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanReport:
    repo_path: str
    repo_name: str
    summary: ScanSummary
    ast_issues: List[Issue] = field(default_factory=list)
    secret_issues: List[Issue] = field(default_factory=list)
    license_issues: List[Issue] = field(default_factory=list)
    dependencies: List[DependencyAudit] = field(default_factory=list)
    hygiene_checks: List[HygieneCheck] = field(default_factory=list)
    other_hygiene_issues: List[Issue] = field(default_factory=list)

    @property
    def all_issues(self) -> List[Issue]:
        return self.ast_issues + self.secret_issues + self.license_issues + self.other_hygiene_issues

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_path": self.repo_path,
            "repo_name": self.repo_name,
            "summary": self.summary.to_dict(),
            "ast_issues": [i.to_dict() for i in self.ast_issues],
            "secret_issues": [i.to_dict() for i in self.secret_issues],
            "license_issues": [i.to_dict() for i in self.license_issues],
            "dependencies": [d.to_dict() for d in self.dependencies],
            "hygiene_checks": [h.to_dict() for h in self.hygiene_checks],
            "other_hygiene_issues": [i.to_dict() for i in self.other_hygiene_issues],
            "total_issues_count": len(self.all_issues),
        }
