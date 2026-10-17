"""Unit tests for Module B: License & Dependency Auditor."""

from pathlib import Path
from repoguard.scanners.license_auditor import LicenseAuditor
from repoguard.core.models import LicenseCategory, LicenseInfo, Severity


def test_detect_mit_license(tmp_path: Path):
    lic_file = tmp_path / "LICENSE"
    lic_file.write_text("MIT License\n\nPermission is hereby granted...", encoding="utf-8")

    auditor = LicenseAuditor()
    detected = auditor.detect_project_license(tmp_path)
    assert detected.spdx_id == "MIT"
    assert detected.category == LicenseCategory.PERMISSIVE


def test_detect_gpl_license(tmp_path: Path):
    lic_file = tmp_path / "LICENSE"
    lic_file.write_text("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007...", encoding="utf-8")

    auditor = LicenseAuditor()
    detected = auditor.detect_project_license(tmp_path)
    assert detected.spdx_id == "GPL-3.0"
    assert detected.category == LicenseCategory.STRONG_COPYLEFT


def test_parse_requirements(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("""
# Core deps
fastapi>=0.100.0
uvicorn==0.23.0 # inline comment
rich
-r other.txt
""", encoding="utf-8")

    auditor = LicenseAuditor()
    pkgs = auditor.parse_requirements(tmp_path)
    pkg_names = [p[0] for p in pkgs]
    assert "fastapi" in pkg_names
    assert "uvicorn" in pkg_names
    assert "rich" in pkg_names
    assert "-r" not in pkg_names


def test_copyleft_in_permissive_conflict():
    auditor = LicenseAuditor()
    mit_proj = LicenseInfo("MIT License", "MIT", LicenseCategory.PERMISSIVE, False)
    gpl_dep = LicenseInfo("GPLv3", "GPL-3.0", LicenseCategory.STRONG_COPYLEFT, True)

    compat, issue = auditor.assess_compatibility(mit_proj, gpl_dep, "copyleft-pkg")
    assert compat == "INCOMPATIBLE"
    assert issue is not None
    assert issue.severity == Severity.CRITICAL
    assert "Incompatible Copyleft Dependency" in issue.title


def test_weak_copyleft_warning():
    auditor = LicenseAuditor()
    mit_proj = LicenseInfo("MIT License", "MIT", LicenseCategory.PERMISSIVE, False)
    lgpl_dep = LicenseInfo("LGPLv3", "LGPL-3.0", LicenseCategory.WEAK_COPYLEFT, True)

    compat, issue = auditor.assess_compatibility(mit_proj, lgpl_dep, "weak-copyleft-pkg")
    assert compat == "WARNING"
    assert issue is not None
    assert issue.severity == Severity.WARNING


def test_permissive_compatibility():
    auditor = LicenseAuditor()
    mit_proj = LicenseInfo("MIT License", "MIT", LicenseCategory.PERMISSIVE, False)
    bsd_dep = LicenseInfo("BSD-3-Clause", "BSD-3-Clause", LicenseCategory.PERMISSIVE, False)

    compat, issue = auditor.assess_compatibility(mit_proj, bsd_dep, "clean-pkg")
    assert compat == "COMPATIBLE"
    assert issue is None
