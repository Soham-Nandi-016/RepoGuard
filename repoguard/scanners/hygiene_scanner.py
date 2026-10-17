"""
RepoGuard Module C2: Repo Hygiene Scanner
Verifies essential open-source baseline files (README, LICENSE, .gitignore, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT),
identifies checked-in environment files, oversized binaries, and stray caches.
"""

from pathlib import Path
from typing import List, Tuple, Dict
from repoguard.core.models import HygieneCheck, Issue, Category, Severity


ESSENTIAL_FILES_SPEC = [
    {
        "file_name": "README.md",
        "alt_names": ["README", "readme.md", "README.rst", "README.txt"],
        "required": True,
        "description": "Primary documentation providing project overview, installation, and usage instructions.",
        "deduction": 12
    },
    {
        "file_name": "LICENSE",
        "alt_names": ["LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"],
        "required": True,
        "description": "Defines software distribution rights, permissions, and copyright limitations.",
        "deduction": 12
    },
    {
        "file_name": ".gitignore",
        "alt_names": [],
        "required": True,
        "description": "Prevents accidental tracking of secrets, virtual environments, build artifacts, and caches.",
        "deduction": 8
    },
    {
        "file_name": "CONTRIBUTING.md",
        "alt_names": ["CONTRIBUTING", "contributing.md", ".github/CONTRIBUTING.md"],
        "required": False,
        "description": "Provides contribution workflow, testing requirements, and Pull Request guidelines.",
        "deduction": 5
    },
    {
        "file_name": "SECURITY.md",
        "alt_names": ["SECURITY", "security.md", ".github/SECURITY.md"],
        "required": False,
        "description": "Outlines vulnerability reporting procedures and coordinated security disclosures.",
        "deduction": 5
    },
    {
        "file_name": "CODE_OF_CONDUCT.md",
        "alt_names": ["CODE_OF_CONDUCT", "code_of_conduct.md", ".github/CODE_OF_CONDUCT.md"],
        "required": False,
        "description": "Establishes community standards, inclusivity expectations, and reporting channels.",
        "deduction": 3
    }
]

TEMPLATES: Dict[str, str] = {
    "SECURITY.md": """# Security Policy

## Supported Versions
Please ensure you are running the latest version before submitting a vulnerability report.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability
We take the security of this repository seriously. If you believe you have discovered a vulnerability, please **DO NOT** open a public issue.

Instead, please send an encrypted or direct email to security@example.com with:
- Detailed steps to reproduce
- Affected files or endpoints
- Proof of concept (PoC)

We will acknowledge receipt within 48 hours and work with you on a coordinated disclosure.
""",
    "CONTRIBUTING.md": """# Contributing to RepoGuard

Thank you for your interest in contributing!

## Code of Conduct
All contributors are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Setup
1. Fork the repository and clone your fork locally.
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   pip install -r requirements.txt
   ```
3. Run test suite:
   ```bash
   pytest
   ```

## Pull Request Guidelines
- Follow PEP 8 style conventions.
- Ensure all automated tests pass before submitting.
- Provide a clear PR description detailing your changes.
""",
    "CODE_OF_CONDUCT.md": """# Contributor Covenant Code of Conduct

## Our Pledge
We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone, regardless of age, body size, visible or invisible disability, ethnicity, sex characteristics, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, caste, color, religion, or sexual identity and orientation.

## Our Standards
Examples of behavior that contributes to a positive environment include:
* Demonstrating empathy and kindness toward other people
* Being respectful of differing opinions, viewpoints, and experiences
* Giving and gracefully accepting constructive feedback
* Accepting responsibility and apologizing to those affected by our mistakes

## Enforcement
Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the project team at conduct@example.com.
""",
    ".gitignore": """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual Environments
venv/
.venv/
ENV/
env/

# Environment Variables & Secrets
.env
.env.*
!.env.example

# IDEs
.vscode/
.idea/
*.swp
*.swo

# Testing & Coverage
.pytest_cache/
.coverage
htmlcov/
.mypy_cache/
.ruff_cache/
"""
}


class HygieneScanner:
    """Evaluates repository structure and baseline open source health standards."""

    def scan_hygiene(self, repo_path: Path) -> Tuple[List[HygieneCheck], List[Issue]]:
        repo_path = Path(repo_path).resolve()
        checks: List[HygieneCheck] = []
        issues: List[Issue] = []

        if not repo_path.exists():
            return checks, issues

        # 1. Evaluate Essential Health Files
        for spec in ESSENTIAL_FILES_SPEC:
            target_name = spec["file_name"]
            candidates = [target_name] + spec["alt_names"]

            found_file: Path | None = None
            for cand in candidates:
                p = repo_path / cand
                if p.is_file():
                    found_file = p
                    break

            if found_file:
                size_bytes = found_file.stat().st_size
                # Check for empty / trivial files
                if size_bytes < 30 and spec["required"]:
                    status = "WARNING"
                    desc = f"{target_name} exists but appears to be empty or a stub ({size_bytes} bytes)."
                    rec = f"Populate {target_name} with comprehensive project content."
                    issues.append(Issue(
                        id="HYG-STUB-001",
                        category=Category.REPO_HYGIENE,
                        severity=Severity.WARNING,
                        title=f"Trivial or Empty Baseline File: {target_name}",
                        description=desc,
                        file_path=str(found_file.relative_to(repo_path)).replace("\\", "/"),
                        recommendation=rec,
                        cwe_id="CWE-1059"
                    ))
                else:
                    status = "PASS"
                    desc = f"{target_name} is present ({size_bytes} bytes)."
                    rec = "File is properly established."

                checks.append(HygieneCheck(
                    file_name=target_name,
                    required=spec["required"],
                    exists=True,
                    file_size_bytes=size_bytes,
                    status=status,
                    description=desc,
                    recommendation=rec
                ))
            else:
                # File is missing
                severity = Severity.CRITICAL if spec["required"] else Severity.WARNING
                status = "FAIL" if spec["required"] else "WARNING"
                rec = f"Create a standard {target_name} file in repository root."

                checks.append(HygieneCheck(
                    file_name=target_name,
                    required=spec["required"],
                    exists=False,
                    file_size_bytes=0,
                    status=status,
                    description=f"Missing essential file: {target_name}. {spec['description']}",
                    recommendation=rec
                ))

                issues.append(Issue(
                    id=f"HYG-MISSING-{target_name.replace('.', '').replace('-', '').upper()}",
                    category=Category.REPO_HYGIENE,
                    severity=severity,
                    title=f"Missing Baseline Health File: {target_name}",
                    description=f"The repository is missing {target_name}. {spec['description']}",
                    file_path=target_name,
                    recommendation=rec,
                    cwe_id="CWE-1059"
                ))

        # 2. Check for checked-in .env files
        env_files = list(repo_path.glob(".env*"))
        for env_file in env_files:
            if env_file.is_file() and env_file.name != ".env.example":
                rel = str(env_file.relative_to(repo_path)).replace("\\", "/")
                issues.append(Issue(
                    id="HYG-ENV-001",
                    category=Category.REPO_HYGIENE,
                    severity=Severity.CRITICAL,
                    title="Committed Environment File (.env)",
                    description=f"Detected committed environment file '{rel}'. Environment files often contain API keys, database passwords, and secrets that should never be pushed to version control.",
                    file_path=rel,
                    recommendation="Add '.env*' to .gitignore, remove from git tracking (git rm --cached .env), and provide a non-sensitive '.env.example' instead.",
                    cwe_id="CWE-552"
                ))

        # 3. Check for committed __pycache__ or .pyc files
        pyc_files = list(repo_path.rglob("*.pyc"))[:5]
        if pyc_files:
            rel = str(pyc_files[0].relative_to(repo_path)).replace("\\", "/")
            issues.append(Issue(
                id="HYG-CACHE-001",
                category=Category.REPO_HYGIENE,
                severity=Severity.WARNING,
                title="Committed Compiled Python Bytecode (*.pyc)",
                description=f"Detected committed bytecode artifacts (e.g. '{rel}'). Compiled files clutter git history and can cause runtime synchronization conflicts across environments.",
                file_path=rel,
                recommendation="Add '__pycache__/' and '*.pyc' to your .gitignore and clean git cache.",
                cwe_id="CWE-1059"
            ))

        # 4. Check for oversized committed binaries (> 5 MB)
        oversized_exts = {".zip", ".tar.gz", ".tar", ".exe", ".bin", ".weights", ".pt", ".iso"}
        for item in repo_path.rglob("*"):
            if item.is_file() and not any(p in item.parts for p in [".git", "venv", ".venv", "node_modules"]):
                if item.suffix.lower() in oversized_exts or item.stat().st_size > 5 * 1024 * 1024:
                    size_mb = item.stat().st_size / (1024 * 1024)
                    if size_mb > 5.0:
                        rel = str(item.relative_to(repo_path)).replace("\\", "/")
                        issues.append(Issue(
                            id="HYG-BINARY-001",
                            category=Category.REPO_HYGIENE,
                            severity=Severity.WARNING,
                            title=f"Oversized Committed Binary Asset ({size_mb:.1f} MB)",
                            description=f"Large binary asset '{rel}' ({size_mb:.1f} MB) is committed directly to the git tree.",
                            file_path=rel,
                            recommendation="Store large binaries using Git LFS (Large File Storage) or external object storage (S3, HuggingFace Hub, or GitHub Releases).",
                            cwe_id="CWE-1059"
                        ))
                        break  # Report once to avoid spam

        return checks, issues

    @staticmethod
    def get_template(file_name: str) -> str:
        return TEMPLATES.get(file_name, f"# {file_name}\n\nDocument details here.")
