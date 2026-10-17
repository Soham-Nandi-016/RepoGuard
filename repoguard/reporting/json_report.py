"""
RepoGuard Module D: JSON Report Generator
Generates structured JSON representations of audit findings for CI/CD pipelines.
"""

import json
from repoguard.core.models import ScanReport


def generate_json_report(report: ScanReport, indent: int = 2) -> str:
    """Format the scan report as a JSON string."""
    return json.dumps(report.to_dict(), indent=indent)
