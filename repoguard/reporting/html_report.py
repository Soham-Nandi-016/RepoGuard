"""
RepoGuard Module D: Standalone HTML Report Generator
Generates self-contained, light-theme HTML audit reports ready for distribution or offline viewing.
Strict Light Theme: Clean white backgrounds, slate typography, emerald/amber/rose alerts.
"""

import html as html_escape
from repoguard.core.models import ScanReport, Severity, Issue, DependencyAudit, HygieneCheck


def escape(s: str) -> str:
    return html_escape.escape(str(s or ""))


def render_ast_card(issue: Issue) -> str:
    is_crit = issue.severity == Severity.CRITICAL
    sev_class = "bg-rose-50 text-rose-700 border-rose-200" if is_crit else "bg-amber-50 text-amber-700 border-amber-200"
    cwe_tag = f'<span class="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-mono">{escape(issue.cwe_id)}</span>' if issue.cwe_id else ''

    snippet_block = ""
    if issue.code_snippet:
        snippet_block = f"""
        <div class="mt-3 bg-slate-900 text-slate-100 rounded-lg p-3 text-xs font-mono overflow-x-auto">
          <pre>{escape(issue.code_snippet)}</pre>
        </div>
        """

    return f"""
    <div class="bg-white rounded-xl border border-slate-200 p-5 shadow-xs transition hover:border-slate-300">
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
        <div class="flex items-center space-x-2.5">
          <span class="px-2.5 py-0.5 rounded-md text-xs font-bold border {sev_class}">
            {issue.severity.value}
          </span>
          <span class="font-mono text-xs font-semibold text-slate-500">{escape(issue.id)}</span>
          {cwe_tag}
        </div>
        <div class="font-mono text-xs text-slate-500 truncate">
          {escape(issue.file_path)}:{issue.line_number or 0}
        </div>
      </div>

      <h3 class="text-base font-bold text-slate-900 mt-2">{escape(issue.title)}</h3>
      <p class="text-sm text-slate-600 mt-1">{escape(issue.description)}</p>

      {snippet_block}

      <div class="mt-3 p-3 rounded-lg bg-emerald-50/70 border border-emerald-100 text-xs text-emerald-900 flex items-start space-x-2">
        <span class="font-bold text-emerald-800 shrink-0">💡 Fix Recommendation:</span>
        <span>{escape(issue.recommendation)}</span>
      </div>
    </div>
    """


def render_secret_card(sec: Issue) -> str:
    is_crit = sec.severity == Severity.CRITICAL
    sev_class = "bg-rose-50 text-rose-700 border-rose-200" if is_crit else "bg-amber-50 text-amber-700 border-amber-200"

    snippet_block = ""
    if sec.code_snippet:
        snippet_block = f"""
        <div class="mt-3 bg-slate-900 text-slate-100 rounded-lg p-3 text-xs font-mono overflow-x-auto">
          <pre>{escape(sec.code_snippet)}</pre>
        </div>
        """

    return f"""
    <div class="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
      <div class="flex items-center justify-between">
        <div class="flex items-center space-x-2.5">
          <span class="px-2.5 py-0.5 rounded-md text-xs font-bold border {sev_class}">
            {sec.severity.value}
          </span>
          <span class="font-mono text-xs text-slate-500">{escape(sec.id)}</span>
        </div>
        <div class="font-mono text-xs text-slate-500">{escape(sec.file_path)}:{sec.line_number or 0}</div>
      </div>
      <h3 class="font-bold text-slate-900 mt-2">{escape(sec.title)}</h3>
      <div class="mt-2 p-2.5 rounded bg-rose-50/70 border border-rose-100 flex items-center space-x-2 text-xs">
        <span class="font-semibold text-rose-800">Masked Token:</span>
        <code class="text-rose-900 font-bold">{escape(sec.masked_value or '')}</code>
      </div>
      {snippet_block}
      <div class="mt-3 p-3 rounded-lg bg-amber-50/70 border border-amber-100 text-xs text-amber-900">
        <strong>Remediation:</strong> {escape(sec.recommendation)}
      </div>
    </div>
    """


def render_dep_row(dep: DependencyAudit) -> str:
    comp = dep.license.compatibility
    if comp == "INCOMPATIBLE":
        badge = "bg-rose-50 text-rose-700 border-rose-200"
    elif comp == "WARNING":
        badge = "bg-amber-50 text-amber-700 border-amber-200"
    else:
        badge = "bg-emerald-50 text-emerald-700 border-emerald-200"

    cat_str = dep.license.category.value if hasattr(dep.license.category, "value") else str(dep.license.category)

    return f"""
    <tr class="hover:bg-slate-50/70">
      <td class="py-3 px-4 font-bold text-slate-800">
        <a href="{dep.pypi_url}" target="_blank" class="hover:text-indigo-600 transition flex items-center space-x-1">
          <span>{escape(dep.package_name)}</span>
          <span class="text-slate-400 text-xs">↗</span>
        </a>
      </td>
      <td class="py-3 px-4 font-mono text-slate-600">{escape(dep.specified_version)}</td>
      <td class="py-3 px-4 font-semibold text-slate-800">{escape(dep.license.spdx_id)}</td>
      <td class="py-3 px-4 text-slate-600">{escape(cat_str)}</td>
      <td class="py-3 px-4 text-slate-500">{escape(dep.source)}</td>
      <td class="py-3 px-4 text-center">
        <span class="px-2.5 py-0.5 rounded-full text-xs font-bold border {badge}">
          {escape(comp)}
        </span>
      </td>
    </tr>
    """


def render_hygiene_row(chk: HygieneCheck) -> str:
    if chk.status == "PASS":
        badge = "bg-emerald-50 text-emerald-700 border-emerald-200"
    elif chk.status == "WARNING":
        badge = "bg-amber-50 text-amber-700 border-amber-200"
    else:
        badge = "bg-rose-50 text-rose-700 border-rose-200"

    req_str = "Mandatory" if chk.required else "Recommended"
    size_str = f"{chk.file_size_bytes} B" if chk.exists else "-"
    tip_str = f'<div class="text-indigo-600 font-medium mt-0.5">Tip: {escape(chk.recommendation)}</div>' if (not chk.exists or chk.status != "PASS") else ""

    return f"""
    <tr class="hover:bg-slate-50/70">
      <td class="py-3 px-4 font-bold text-slate-800 flex items-center space-x-2">
        <span>📄</span>
        <span>{escape(chk.file_name)}</span>
      </td>
      <td class="py-3 px-4 text-center font-medium text-slate-500">{req_str}</td>
      <td class="py-3 px-4 text-center">
        <span class="px-2.5 py-0.5 rounded-full text-xs font-bold border {badge}">
          {escape(chk.status)}
        </span>
      </td>
      <td class="py-3 px-4 text-right font-mono text-slate-600">{size_str}</td>
      <td class="py-3 px-4 text-slate-600">
        <div>{escape(chk.description)}</div>
        {tip_str}
      </td>
    </tr>
    """


def generate_html_report(report: ScanReport) -> str:
    summary = report.summary
    score = summary.health_score

    if score >= 90:
        score_color = "text-emerald-600"
        score_bg = "bg-emerald-50"
        score_border = "border-emerald-200"
        badge_text = "PASSED AUDIT"
    elif score >= 70:
        score_color = "text-indigo-600"
        score_bg = "bg-indigo-50"
        score_border = "border-indigo-200"
        badge_text = "MODERATE RISK"
    elif score >= 55:
        score_color = "text-amber-600"
        score_bg = "bg-amber-50"
        score_border = "border-amber-200"
        badge_text = "ELEVATED RISK"
    else:
        score_color = "text-rose-600"
        score_bg = "bg-rose-50"
        score_border = "border-rose-200"
        badge_text = "CRITICAL FAILURES"

    ast_cards_html = "".join(render_ast_card(i) for i in report.ast_issues) if report.ast_issues else """
    <div class="bg-white rounded-xl border border-slate-200 p-8 text-center">
      <div class="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto text-xl font-bold mb-2">✓</div>
      <h3 class="font-bold text-slate-800">No AST Security Vulnerabilities Detected</h3>
      <p class="text-xs text-slate-500 mt-1">Python source code parsed successfully without dangerous calls or SQL injection.</p>
    </div>
    """

    secret_cards_html = "".join(render_secret_card(s) for s in report.secret_issues) if report.secret_issues else """
    <div class="bg-white rounded-xl border border-slate-200 p-8 text-center">
      <div class="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto text-xl font-bold mb-2">✓</div>
      <h3 class="font-bold text-slate-800">No Hardcoded Secrets Detected</h3>
      <p class="text-xs text-slate-500 mt-1">No API keys, credentials, or private cryptographic keys discovered in repository files.</p>
    </div>
    """

    dep_rows_html = "".join(render_dep_row(d) for d in report.dependencies) if report.dependencies else """
    <tr><td colspan="6" class="py-6 text-center text-slate-400">No dependencies declared in requirements.txt</td></tr>
    """

    hygiene_rows_html = "".join(render_hygiene_row(h) for h in report.hygiene_checks)

    license_conflicts_html = ""
    if report.license_issues:
        for iss in report.license_issues:
            license_conflicts_html += f"""
            <div class="bg-rose-50 border border-rose-200 rounded-xl p-4 text-xs mb-3">
              <div class="flex items-center space-x-2 font-bold text-rose-800 text-sm">
                <span>⚠️ {escape(iss.title)}</span>
              </div>
              <p class="text-rose-700 mt-1">{escape(iss.description)}</p>
              <div class="mt-2 text-rose-900 font-semibold">Fix: {escape(iss.recommendation)}</div>
            </div>
            """
    else:
        license_conflicts_html = """
        <div class="bg-emerald-50/60 border border-emerald-200 rounded-xl p-4 text-xs text-emerald-800 flex items-center space-x-2 mb-3">
          <span class="text-base font-bold">✓</span>
          <span>All audited package licenses are compatible with repository license. No copyleft conflicts detected.</span>
        </div>
        """

    proj_lic_name = escape(summary.project_license.name if summary.project_license else "None")
    proj_lic_spdx = escape(summary.project_license.spdx_id if summary.project_license else "None")
    proj_lic_details = escape(summary.project_license.details if summary.project_license else "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RepoGuard Audit Report - {escape(report.repo_name)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    body {{
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: #F8FAFC;
      color: #0F172A;
    }}
    code, pre, .font-mono {{
      font-family: 'JetBrains Mono', monospace;
    }}
  </style>
</head>
<body class="min-h-screen bg-slate-50 text-slate-900 antialiased">

  <header class="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-xs">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center text-white shadow-sm font-bold text-lg">
          🛡️
        </div>
        <div>
          <div class="flex items-center space-x-2">
            <span class="font-extrabold text-slate-900 tracking-tight text-lg">RepoGuard</span>
            <span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">Standalone Report</span>
          </div>
          <p class="text-xs text-slate-500">RepoGuard | Protect Every Repository</p>
        </div>
      </div>
      <div class="flex items-center space-x-3 text-xs">
        <span class="text-slate-500">Generated: <strong class="text-slate-700">{escape(summary.timestamp)}</strong></span>
        <button onclick="window.print()" class="px-3 py-1.5 rounded-lg border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium transition shadow-xs">
          🖨️ Print / Save PDF
        </button>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">

    <div class="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
      <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
        <div>
          <div class="flex items-center space-x-2 text-xs font-medium text-slate-500 uppercase tracking-wider mb-1">
            <span>Repository Compliance Inspection</span>
            <span>•</span>
            <span>Static Analysis Mode</span>
          </div>
          <h1 class="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight flex items-center space-x-3">
            <span>{escape(report.repo_name)}</span>
            <span class="text-xs font-semibold px-2.5 py-1 rounded-full {score_bg} {score_color} border {score_border}">
              Grade {escape(summary.grade)} ({badge_text})
            </span>
          </h1>
          <p class="text-sm text-slate-500 mt-1 font-mono truncate max-w-2xl">{escape(report.repo_path)}</p>
        </div>

        <div class="flex items-center space-x-6 self-start lg:self-center">
          <div class="text-right">
            <div class="text-xs uppercase font-semibold text-slate-400">Compliance Score</div>
            <div class="text-4xl font-extrabold {score_color} tracking-tight">{score}<span class="text-xl text-slate-400 font-normal">/100</span></div>
            <div class="text-xs text-slate-500 mt-0.5">{summary.total_issues} issues identified</div>
          </div>
          <div class="w-16 h-16 rounded-2xl {score_bg} border {score_border} flex items-center justify-center font-black text-2xl {score_color}">
            {escape(summary.grade)}
          </div>
        </div>
      </div>

      <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mt-6 pt-6 border-t border-slate-100">
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
          <div class="text-xs font-medium text-slate-500">Critical Alerts</div>
          <div class="text-xl font-bold text-rose-600 mt-0.5">{summary.critical_count}</div>
        </div>
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
          <div class="text-xs font-medium text-slate-500">Warnings</div>
          <div class="text-xl font-bold text-amber-600 mt-0.5">{summary.warning_count}</div>
        </div>
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
          <div class="text-xs font-medium text-slate-500">Project License</div>
          <div class="text-sm font-bold text-slate-800 mt-1 truncate">{proj_lic_spdx}</div>
        </div>
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
          <div class="text-xs font-medium text-slate-500">Dependencies</div>
          <div class="text-xl font-bold text-indigo-600 mt-0.5">{len(report.dependencies)}</div>
        </div>
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
          <div class="text-xs font-medium text-slate-500">Files Scanned</div>
          <div class="text-xl font-bold text-slate-800 mt-0.5">{summary.files_scanned}</div>
        </div>
        <div class="p-3 rounded-xl bg-slate-50 border border-slate-200/60">
          <div class="text-xs font-medium text-slate-500">Scan Duration</div>
          <div class="text-xl font-bold text-slate-800 mt-0.5">{summary.scan_duration_seconds:.2f}s</div>
        </div>
      </div>
    </div>

    <div class="border-b border-slate-200 flex space-x-6 text-sm font-semibold">
      <button onclick="switchTab('ast')" id="tab-btn-ast" class="pb-3 text-indigo-600 border-b-2 border-indigo-600 flex items-center space-x-2">
        <span>🛡️ AST Security</span>
        <span class="px-2 py-0.5 rounded-full text-xs bg-indigo-50 text-indigo-700">{len(report.ast_issues)}</span>
      </button>
      <button onclick="switchTab('license')" id="tab-btn-license" class="pb-3 text-slate-500 hover:text-slate-800 border-b-2 border-transparent flex items-center space-x-2">
        <span>📜 License & Dependencies</span>
        <span class="px-2 py-0.5 rounded-full text-xs bg-slate-100 text-slate-700">{len(report.dependencies)}</span>
      </button>
      <button onclick="switchTab('secrets')" id="tab-btn-secrets" class="pb-3 text-slate-500 hover:text-slate-800 border-b-2 border-transparent flex items-center space-x-2">
        <span>🔑 Secrets & Leaks</span>
        <span class="px-2 py-0.5 rounded-full text-xs bg-slate-100 text-slate-700">{len(report.secret_issues)}</span>
      </button>
      <button onclick="switchTab('hygiene')" id="tab-btn-hygiene" class="pb-3 text-slate-500 hover:text-slate-800 border-b-2 border-transparent flex items-center space-x-2">
        <span>📋 Repo Hygiene</span>
        <span class="px-2 py-0.5 rounded-full text-xs bg-slate-100 text-slate-700">{len(report.hygiene_checks)}</span>
      </button>
    </div>

    <div id="tab-ast" class="tab-content space-y-4">
      <div>
        <h2 class="text-lg font-bold text-slate-900">AST Security Findings</h2>
        <p class="text-xs text-slate-500">Abstract Syntax Tree analysis flagging dangerous calls, deserialization, and SQL injection.</p>
      </div>
      <div class="space-y-4">
        {ast_cards_html}
      </div>
    </div>

    <div id="tab-license" class="tab-content hidden space-y-6">
      <div class="bg-white rounded-xl border border-slate-200 p-5 shadow-xs">
        <h2 class="text-base font-bold text-slate-900">Project License Analysis</h2>
        <div class="mt-3 flex items-center space-x-4">
          <div class="px-3 py-1.5 rounded-lg bg-indigo-50 border border-indigo-200 text-indigo-700 font-bold text-sm">
            Declared: {proj_lic_name} ({proj_lic_spdx})
          </div>
          <div class="text-xs text-slate-600">
            {proj_lic_details}
          </div>
        </div>
      </div>

      {license_conflicts_html}

      <div class="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
          <h3 class="font-bold text-slate-900 text-sm">Audited Dependencies ({len(report.dependencies)})</h3>
          <span class="text-xs text-slate-500">Cross-referenced via PyPI REST API</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
              <tr>
                <th class="py-3 px-4">Package</th>
                <th class="py-3 px-4">Version</th>
                <th class="py-3 px-4">Declared License</th>
                <th class="py-3 px-4">License Type</th>
                <th class="py-3 px-4">Source</th>
                <th class="py-3 px-4 text-center">Compatibility</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              {dep_rows_html}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div id="tab-secrets" class="tab-content hidden space-y-4">
      <div>
        <h2 class="text-lg font-bold text-slate-900">Secrets & Hardcoded Credentials</h2>
        <p class="text-xs text-slate-500">Regex and entropy matching for API keys, cloud tokens, database URIs, and private keys.</p>
      </div>
      <div class="space-y-4">
        {secret_cards_html}
      </div>
    </div>

    <div id="tab-hygiene" class="tab-content hidden space-y-6">
      <div class="bg-white rounded-xl border border-slate-200 shadow-xs overflow-hidden">
        <div class="px-5 py-4 border-b border-slate-100">
          <h3 class="font-bold text-slate-900 text-sm">Essential Open Source Health Files</h3>
          <p class="text-xs text-slate-500">Repository governance, licensing, and security contact points.</p>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
              <tr>
                <th class="py-3 px-4">Baseline Health File</th>
                <th class="py-3 px-4 text-center">Requirement</th>
                <th class="py-3 px-4 text-center">Status</th>
                <th class="py-3 px-4 text-right">File Size</th>
                <th class="py-3 px-4">Assessment & Recommendations</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              {hygiene_rows_html}
            </tbody>
          </table>
        </div>
      </div>
    </div>

  </main>

  <script>
    function switchTab(tabId) {{
      const tabs = ['ast', 'license', 'secrets', 'hygiene'];
      tabs.forEach(t => {{
        const el = document.getElementById('tab-' + t);
        const btn = document.getElementById('tab-btn-' + t);
        if (t === tabId) {{
          el.classList.remove('hidden');
          btn.classList.add('text-indigo-600', 'border-indigo-600');
          btn.classList.remove('text-slate-500', 'border-transparent');
        }} else {{
          el.classList.add('hidden');
          btn.classList.remove('text-indigo-600', 'border-indigo-600');
          btn.classList.add('text-slate-500', 'border-transparent');
        }}
      }});
    }}
  </script>

  <footer class="mt-16 border-t border-slate-200 bg-white py-6 text-center text-xs text-slate-500">
    <p>RepoGuard v1.0.0 — Open Source Static Analysis Engine (GPLv3 License)</p>
    <p class="mt-1 text-slate-400">Zero Cloud Uploads • 100% Local CPU Execution</p>
  </footer>
</body>
</html>"""
