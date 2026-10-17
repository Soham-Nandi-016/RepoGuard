"""
RepoGuard Module B: License & Dependency Auditor
Parses dependencies (requirements.txt), queries PyPI REST API asynchronously,
detects project license, and checks copyleft vs permissive compatibility.
"""

import re
import asyncio
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
import httpx

from repoguard.core.models import (
    Issue, Category, Severity, LicenseInfo,
    LicenseCategory, DependencyAudit
)
from repoguard.core.db import db


# Pre-computed offline knowledge base for standard popular packages
OFFLINE_PACKAGE_LICENSES: Dict[str, Dict[str, Any]] = {
    "requests": {"spdx": "Apache-2.0", "name": "Apache License 2.0", "category": LicenseCategory.PERMISSIVE},
    "fastapi": {"spdx": "MIT", "name": "MIT License", "category": LicenseCategory.PERMISSIVE},
    "uvicorn": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "rich": {"spdx": "MIT", "name": "MIT License", "category": LicenseCategory.PERMISSIVE},
    "jinja2": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "httpx": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "pydantic": {"spdx": "MIT", "name": "MIT License", "category": LicenseCategory.PERMISSIVE},
    "flask": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "django": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "numpy": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "pandas": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "scipy": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "torch": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "pytest": {"spdx": "MIT", "name": "MIT License", "category": LicenseCategory.PERMISSIVE},
    "click": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "typer": {"spdx": "MIT", "name": "MIT License", "category": LicenseCategory.PERMISSIVE},
    "sqlalchemy": {"spdx": "MIT", "name": "MIT License", "category": LicenseCategory.PERMISSIVE},
    "cryptography": {"spdx": "Apache-2.0", "name": "Apache License 2.0 / BSD", "category": LicenseCategory.PERMISSIVE},
    "celery": {"spdx": "BSD-3-Clause", "name": "BSD 3-Clause License", "category": LicenseCategory.PERMISSIVE},
    "redis": {"spdx": "MIT", "name": "MIT License", "category": LicenseCategory.PERMISSIVE},
    # Intentionally copyleft packages for security / license testing
    "ansible": {"spdx": "GPL-3.0", "name": "GNU General Public License v3", "category": LicenseCategory.STRONG_COPYLEFT},
    "mysql-connector-python": {"spdx": "GPL-2.0", "name": "GNU General Public License v2", "category": LicenseCategory.STRONG_COPYLEFT},
    "pygobject": {"spdx": "LGPL-2.1", "name": "GNU Lesser General Public License v2.1", "category": LicenseCategory.WEAK_COPYLEFT},
    "rpy2": {"spdx": "GPL-2.0", "name": "GNU General Public License v2", "category": LicenseCategory.STRONG_COPYLEFT},
    "scapy": {"spdx": "GPL-2.0", "name": "GNU General Public License v2", "category": LicenseCategory.STRONG_COPYLEFT},
    "gpl-sample-lib": {"spdx": "GPL-3.0", "name": "GNU General Public License v3", "category": LicenseCategory.STRONG_COPYLEFT},
    "copyleft-tool": {"spdx": "AGPL-3.0", "name": "GNU Affero General Public License v3", "category": LicenseCategory.NETWORK_COPYLEFT},
}

SPDX_CLASSIFICATIONS: Dict[str, Tuple[LicenseCategory, bool]] = {
    "MIT": (LicenseCategory.PERMISSIVE, False),
    "Apache-2.0": (LicenseCategory.PERMISSIVE, False),
    "BSD-2-Clause": (LicenseCategory.PERMISSIVE, False),
    "BSD-3-Clause": (LicenseCategory.PERMISSIVE, False),
    "ISC": (LicenseCategory.PERMISSIVE, False),
    "Unlicense": (LicenseCategory.PERMISSIVE, False),
    "CC0-1.0": (LicenseCategory.PERMISSIVE, False),
    "Python-2.0": (LicenseCategory.PERMISSIVE, False),
    "Zlib": (LicenseCategory.PERMISSIVE, False),
    "LGPL-2.0": (LicenseCategory.WEAK_COPYLEFT, True),
    "LGPL-2.1": (LicenseCategory.WEAK_COPYLEFT, True),
    "LGPL-3.0": (LicenseCategory.WEAK_COPYLEFT, True),
    "MPL-2.0": (LicenseCategory.WEAK_COPYLEFT, True),
    "EPL-1.0": (LicenseCategory.WEAK_COPYLEFT, True),
    "EPL-2.0": (LicenseCategory.WEAK_COPYLEFT, True),
    "GPL-2.0": (LicenseCategory.STRONG_COPYLEFT, True),
    "GPL-3.0": (LicenseCategory.STRONG_COPYLEFT, True),
    "AGPL-3.0": (LicenseCategory.NETWORK_COPYLEFT, True),
}


class LicenseAuditor:
    def __init__(self):
        self.client_timeout = 3.5

    def detect_project_license(self, repo_path: Path) -> LicenseInfo:
        """Inspect repository files to determine the repository's declared license."""
        license_candidates = [
            "LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.LESSER",
            "LICENCE", "LICENCE.md", "LICENCE.txt"
        ]
        repo_path = Path(repo_path).resolve()
        license_file: Optional[Path] = None

        for name in license_candidates:
            cand = repo_path / name
            if cand.is_file():
                license_file = cand
                break

        if not license_file:
            return LicenseInfo(
                name="No License Detected",
                spdx_id="NOASSERTION",
                category=LicenseCategory.UNKNOWN,
                is_copyleft=False,
                compatibility="WARNING",
                details="Missing LICENSE file. Default copyright laws apply (all rights reserved)."
            )

        try:
            content = license_file.read_text(encoding="utf-8", errors="replace")
            content_lower = content.lower()

            # Detect Apache 2.0
            if "apache license" in content_lower and "version 2.0" in content_lower:
                return LicenseInfo("Apache License 2.0", "Apache-2.0", LicenseCategory.PERMISSIVE, False, "COMPATIBLE", "Permissive license with patent grant.")

            # Detect AGPL v3
            if "affero general public license" in content_lower or "agpl" in content_lower:
                return LicenseInfo("GNU Affero General Public License v3", "AGPL-3.0", LicenseCategory.NETWORK_COPYLEFT, True, "COMPATIBLE", "Strict network copyleft.")

            # Detect LGPL
            if "lesser general public license" in content_lower:
                if "version 3" in content_lower:
                    return LicenseInfo("GNU Lesser General Public License v3", "LGPL-3.0", LicenseCategory.WEAK_COPYLEFT, True, "COMPATIBLE", "Weak copyleft.")
                return LicenseInfo("GNU Lesser General Public License v2.1", "LGPL-2.1", LicenseCategory.WEAK_COPYLEFT, True, "COMPATIBLE", "Weak copyleft.")

            # Detect GPL v3
            if "general public license" in content_lower and ("version 3" in content_lower or "gplv3" in content_lower):
                return LicenseInfo("GNU General Public License v3", "GPL-3.0", LicenseCategory.STRONG_COPYLEFT, True, "COMPATIBLE", "Strong copyleft license.")

            # Detect GPL v2
            if "general public license" in content_lower and ("version 2" in content_lower or "gplv2" in content_lower):
                return LicenseInfo("GNU General Public License v2", "GPL-2.0", LicenseCategory.STRONG_COPYLEFT, True, "COMPATIBLE", "Strong copyleft license.")

            # Detect MIT
            if "mit license" in content_lower or "permission is hereby granted, free of charge" in content_lower:
                return LicenseInfo("MIT License", "MIT", LicenseCategory.PERMISSIVE, False, "COMPATIBLE", "Highly permissive open-source license.")

            # Detect BSD 3-Clause
            if "neither the name of" in content_lower and "redistribution and use in source and binary" in content_lower:
                return LicenseInfo("BSD 3-Clause License", "BSD-3-Clause", LicenseCategory.PERMISSIVE, False, "COMPATIBLE", "Permissive open-source license.")

            # Detect BSD 2-Clause
            if "redistributions of source code must retain" in content_lower and "redistributions in binary form" in content_lower:
                return LicenseInfo("BSD 2-Clause License", "BSD-2-Clause", LicenseCategory.PERMISSIVE, False, "COMPATIBLE", "Permissive open-source license.")

            # Detect MPL 2.0
            if "mozilla public license" in content_lower:
                return LicenseInfo("Mozilla Public License 2.0", "MPL-2.0", LicenseCategory.WEAK_COPYLEFT, True, "COMPATIBLE", "File-level copyleft license.")

            # Detect Unlicense
            if "this is free and unencumbered software released into the public domain" in content_lower:
                return LicenseInfo("The Unlicense", "Unlicense", LicenseCategory.PERMISSIVE, False, "COMPATIBLE", "Public domain dedication.")

            return LicenseInfo("Custom / Unrecognized License", "CUSTOM", LicenseCategory.UNKNOWN, False, "WARNING", "Custom license terms.")
        except Exception:
            return LicenseInfo("Unreadable License File", "UNKNOWN", LicenseCategory.UNKNOWN, False, "WARNING", "Could not parse license file.")

    def parse_requirements(self, repo_path: Path) -> List[Tuple[str, str]]:
        """Parse packages and version specifiers from requirements.txt."""
        req_file = Path(repo_path) / "requirements.txt"
        if not req_file.exists() or not req_file.is_file():
            return []

        packages: List[Tuple[str, str]] = []
        try:
            lines = req_file.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#") or line.startswith("-r") or line.startswith("-i") or line.startswith("--"):
                    continue
                # Strip inline comments
                if "#" in line:
                    line = line.split("#")[0].strip()

                # Match package name and version
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)(.*)$", line)
                if match:
                    pkg_name = match.group(1).strip()
                    ver_spec = match.group(2).strip() or "any"
                    packages.append((pkg_name, ver_spec))
        except Exception:
            pass

        return packages

    def _normalize_license_str(self, license_str: str, classifiers: List[str]) -> Tuple[str, str, LicenseCategory, bool]:
        """Normalize raw PyPI license string or classifiers into standard SPDX and category."""
        # Check classifiers first
        for c in classifiers:
            c_low = c.lower()
            if "gplv3" in c_low or "gpl v3" in c_low or "gnu general public license v3" in c_low:
                return "GNU General Public License v3", "GPL-3.0", LicenseCategory.STRONG_COPYLEFT, True
            if "gplv2" in c_low or "gpl v2" in c_low or "gnu general public license v2" in c_low:
                return "GNU General Public License v2", "GPL-2.0", LicenseCategory.STRONG_COPYLEFT, True
            if "agpl" in c_low or "affero" in c_low:
                return "GNU Affero General Public License v3", "AGPL-3.0", LicenseCategory.NETWORK_COPYLEFT, True
            if "lgpl" in c_low:
                return "GNU Lesser General Public License", "LGPL-3.0", LicenseCategory.WEAK_COPYLEFT, True
            if "mit license" in c_low:
                return "MIT License", "MIT", LicenseCategory.PERMISSIVE, False
            if "apache software license" in c_low or "apache 2" in c_low:
                return "Apache License 2.0", "Apache-2.0", LicenseCategory.PERMISSIVE, False
            if "bsd license" in c_low:
                return "BSD License", "BSD-3-Clause", LicenseCategory.PERMISSIVE, False
            if "mozilla public license" in c_low:
                return "Mozilla Public License 2.0", "MPL-2.0", LicenseCategory.WEAK_COPYLEFT, True

        raw_low = (license_str or "").lower()
        if "mit" in raw_low:
            return "MIT License", "MIT", LicenseCategory.PERMISSIVE, False
        if "apache" in raw_low:
            return "Apache License 2.0", "Apache-2.0", LicenseCategory.PERMISSIVE, False
        if "bsd" in raw_low:
            return "BSD License", "BSD-3-Clause", LicenseCategory.PERMISSIVE, False
        if "agpl" in raw_low:
            return "GNU Affero General Public License v3", "AGPL-3.0", LicenseCategory.NETWORK_COPYLEFT, True
        if "lgpl" in raw_low:
            return "GNU Lesser General Public License", "LGPL-3.0", LicenseCategory.WEAK_COPYLEFT, True
        if "gpl" in raw_low:
            return "GNU General Public License", "GPL-3.0", LicenseCategory.STRONG_COPYLEFT, True
        if "mozilla" in raw_low or "mpl" in raw_low:
            return "Mozilla Public License 2.0", "MPL-2.0", LicenseCategory.WEAK_COPYLEFT, True

        name = license_str.strip() if license_str else "Unknown / Unspecified"
        return name, "UNKNOWN", LicenseCategory.UNKNOWN, False

    async def fetch_package_license_async(self, client: httpx.AsyncClient, pkg_name: str) -> Tuple[LicenseInfo, str]:
        pkg_key = pkg_name.lower()

        # 1. Check local DB cache
        cached = db.get_cached_license(pkg_key)
        if cached:
            spdx = cached["spdx_id"]
            cat_enum = LicenseCategory(cached["category"]) if cached["category"] in LicenseCategory._value2member_map_ else LicenseCategory.UNKNOWN
            return LicenseInfo(
                name=cached["license_name"],
                spdx_id=spdx,
                category=cat_enum,
                is_copyleft=cached["is_copyleft"],
                compatibility="COMPATIBLE",
                details="Loaded from RepoGuard SQLite cache"
            ), "Local Cache"

        # 2. Check offline pre-computed DB
        if pkg_key in OFFLINE_PACKAGE_LICENSES:
            info = OFFLINE_PACKAGE_LICENSES[pkg_key]
            cat_enum = info["category"]
            is_copyleft = cat_enum in (LicenseCategory.STRONG_COPYLEFT, LicenseCategory.NETWORK_COPYLEFT, LicenseCategory.WEAK_COPYLEFT)
            db.cache_license(pkg_key, info["name"], info["spdx"], cat_enum.value, is_copyleft)
            return LicenseInfo(
                name=info["name"],
                spdx_id=info["spdx"],
                category=cat_enum,
                is_copyleft=is_copyleft,
                compatibility="COMPATIBLE",
                details="Loaded from built-in package license database"
            ), "Offline Database"

        # 3. Query PyPI asynchronously
        url = f"https://pypi.org/pypi/{pkg_name}/json"
        try:
            resp = await client.get(url, timeout=self.client_timeout)
            if resp.status_code == 200:
                data = resp.json()
                info_data = data.get("info", {})
                raw_license = info_data.get("license") or ""
                classifiers = info_data.get("classifiers") or []
                name, spdx, category, is_copyleft = self._normalize_license_str(raw_license, classifiers)
                db.cache_license(pkg_key, name, spdx, category.value, is_copyleft)
                return LicenseInfo(
                    name=name,
                    spdx_id=spdx,
                    category=category,
                    is_copyleft=is_copyleft,
                    compatibility="COMPATIBLE",
                    details=f"Retrieved live from PyPI REST API"
                ), "PyPI REST API"
        except Exception:
            pass

        # Fallback if PyPI fails or network is offline
        return LicenseInfo(
            name="Unknown License",
            spdx_id="UNKNOWN",
            category=LicenseCategory.UNKNOWN,
            is_copyleft=False,
            compatibility="WARNING",
            details="PyPI query timed out or package license not declared"
        ), "Offline Fallback"

    def assess_compatibility(self, project_license: LicenseInfo, dep_license: LicenseInfo, pkg_name: str) -> Tuple[str, Optional[Issue]]:
        """
        Cross-reference project license with dependency license.
        Flag restrictive copyleft packages included in permissive projects.
        """
        proj_cat = project_license.category
        dep_cat = dep_license.category

        # Case 1: Permissive Project (e.g. MIT, Apache, BSD) + Strong Copyleft Dependency (GPL, AGPL)
        if proj_cat == LicenseCategory.PERMISSIVE and dep_cat in (LicenseCategory.STRONG_COPYLEFT, LicenseCategory.NETWORK_COPYLEFT):
            dep_license.compatibility = "INCOMPATIBLE"
            issue = Issue(
                id="LIC-CONFLICT-001",
                category=Category.LICENSE_COMPLIANCE,
                severity=Severity.CRITICAL,
                title=f"Incompatible Copyleft Dependency: {pkg_name} ({dep_license.spdx_id})",
                description=(
                    f"Dependency '{pkg_name}' is licensed under {dep_license.name} ({dep_license.spdx_id}, Strong Copyleft). "
                    f"Distributing this dependency within a permissive {project_license.spdx_id} project violates open-source license terms "
                    f"unless the entire project is relicensed under {dep_license.spdx_id}."
                ),
                file_path="requirements.txt",
                recommendation=f"Replace '{pkg_name}' with a permissively licensed alternative (MIT, Apache-2.0, or BSD), or relicense project under {dep_license.spdx_id}.",
                cwe_id="CWE-1059"
            )
            return "INCOMPATIBLE", issue

        # Case 2: Permissive Project + Weak Copyleft Dependency (LGPL, MPL)
        if proj_cat == LicenseCategory.PERMISSIVE and dep_cat == LicenseCategory.WEAK_COPYLEFT:
            dep_license.compatibility = "WARNING"
            issue = Issue(
                id="LIC-WARN-001",
                category=Category.LICENSE_COMPLIANCE,
                severity=Severity.WARNING,
                title=f"Weak Copyleft Dependency Notice: {pkg_name} ({dep_license.spdx_id})",
                description=(
                    f"Dependency '{pkg_name}' is licensed under {dep_license.name} ({dep_license.spdx_id}, Weak Copyleft). "
                    f"Permitted in a {project_license.spdx_id} project provided the library is dynamically linked without modifications. "
                    f"Any source code modifications to '{pkg_name}' must be published under {dep_license.spdx_id}."
                ),
                file_path="requirements.txt",
                recommendation=f"Verify that '{pkg_name}' is imported as an unmodified dynamic dependency and not statically linked into your codebase.",
                cwe_id="CWE-1059"
            )
            return "WARNING", issue

        # Case 3: Missing Project License + Any Dependency
        if proj_cat == LicenseCategory.UNKNOWN:
            dep_license.compatibility = "WARNING"
            issue = Issue(
                id="LIC-WARN-002",
                category=Category.LICENSE_COMPLIANCE,
                severity=Severity.WARNING,
                title=f"Unspecified Project License with Dependency '{pkg_name}'",
                description=f"Project lacks an explicit LICENSE file, which may create legal ambiguities when distributing alongside third-party dependency '{pkg_name}'.",
                file_path="requirements.txt",
                recommendation="Add a standard open-source LICENSE file (e.g. MIT, Apache-2.0) to your repository root.",
                cwe_id="CWE-1059"
            )
            return "WARNING", issue

        # Default: Compatible
        dep_license.compatibility = "COMPATIBLE"
        return "COMPATIBLE", None

    async def audit_dependencies_async(self, repo_path: Path) -> Tuple[LicenseInfo, List[DependencyAudit], List[Issue]]:
        repo_path = Path(repo_path).resolve()
        proj_license = self.detect_project_license(repo_path)
        packages = self.parse_requirements(repo_path)

        audits: List[DependencyAudit] = []
        issues: List[Issue] = []

        if not packages:
            return proj_license, audits, issues

        async with httpx.AsyncClient(headers={"User-Agent": "RepoGuard/1.0 (University of Mumbai ITL709)"}) as client:
            tasks = [self.fetch_package_license_async(client, pkg_name) for pkg_name, _ in packages]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for (pkg_name, ver_spec), result in zip(packages, results):
                if isinstance(result, Exception):
                    lic_info = LicenseInfo(
                        name="Unknown License",
                        spdx_id="UNKNOWN",
                        category=LicenseCategory.UNKNOWN,
                        is_copyleft=False,
                        compatibility="WARNING",
                        details="Error looking up license"
                    )
                    source = "Lookup Error"
                else:
                    lic_info, source = result

                # Assess compatibility
                _, issue = self.assess_compatibility(proj_license, lic_info, pkg_name)
                if issue:
                    issues.append(issue)

                audits.append(DependencyAudit(
                    package_name=pkg_name,
                    specified_version=ver_spec,
                    license=lic_info,
                    source=source,
                    pypi_url=f"https://pypi.org/pypi/{pkg_name}/json"
                ))

        return proj_license, audits, issues

    def audit_dependencies(self, repo_path: Path) -> Tuple[LicenseInfo, List[DependencyAudit], List[Issue]]:
        """Synchronous runner for audit_dependencies_async, safe in both CLI and FastAPI async contexts."""
        import concurrent.futures

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # If running inside an existing event loop (e.g. FastAPI / AnyIO), execute in dedicated thread
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(asyncio.run, self.audit_dependencies_async(repo_path))
                return future.result()
        else:
            return asyncio.run(self.audit_dependencies_async(repo_path))
