"""
RepoGuard Module D2: FastAPI Web Application & Dashboard
Light-theme-only responsive web UI, REST API endpoints, live repository scanner,
and standalone report exporter.
"""

from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from repoguard.core.engine import RepoGuardEngine
from repoguard.core.db import db
from repoguard.reporting.html_report import generate_html_report
from repoguard.reporting.json_report import generate_json_report
from repoguard.scanners.hygiene_scanner import HygieneScanner


app = FastAPI(
    title="RepoGuard API",
    description="Automated repository compliance, AST security, secrets detection, and license auditor.",
    version="1.0.0"
)

# Template setup
TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
engine = RepoGuardEngine()


class ScanRequest(BaseModel):
    path: str
    save_to_db: bool = True


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Render the modern light-theme RepoGuard dashboard."""
    recent_scans = db.get_recent_scans(limit=10)
    current_workspace = str(Path.cwd().resolve()).replace("\\", "/")
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "recent_scans": recent_scans,
            "current_workspace": current_workspace,
        }
    )


@app.post("/api/scan")
async def execute_scan(scan_req: ScanRequest):
    """Execute static analysis on target repository path."""
    target_path = Path(scan_req.path).resolve()
    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"Target path does not exist: {target_path}")
    if not target_path.is_dir():
        raise HTTPException(status_code=400, detail=f"Target path is not a directory: {target_path}")

    try:
        report = engine.scan(target_path, save_to_db=scan_req.save_to_db)
        return JSONResponse(content=report.to_dict())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")


@app.get("/api/history")
async def get_history(limit: int = 15):
    """Retrieve recent scan history from SQLite database."""
    return JSONResponse(content=db.get_recent_scans(limit=limit))


@app.get("/api/scan/{scan_id}")
async def get_scan_report(scan_id: int):
    """Retrieve full audit report by historical ID."""
    report_dict = db.get_scan_by_id(scan_id)
    if not report_dict:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(content=report_dict)


@app.get("/api/export/html")
async def export_html(path: Optional[str] = None, scan_id: Optional[int] = None):
    """Generate and download standalone self-contained repoguard_report.html."""
    if scan_id is not None:
        report_dict = db.get_scan_by_id(scan_id)
        if not report_dict:
            raise HTTPException(status_code=404, detail="Historical scan not found")
        # Re-run or construct
        target_path = Path(report_dict.get("repo_path", "."))
    elif path:
        target_path = Path(path).resolve()
    else:
        raise HTTPException(status_code=400, detail="Must provide 'path' or 'scan_id'")

    if not target_path.exists():
        raise HTTPException(status_code=400, detail="Target path does not exist")

    report = engine.scan(target_path, save_to_db=False)
    html_content = generate_html_report(report)

    filename = f"repoguard_report_{report.repo_name}.html"
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/export/json")
async def export_json(path: Optional[str] = None, scan_id: Optional[int] = None):
    """Export machine-readable JSON report."""
    if scan_id is not None:
        report_dict = db.get_scan_by_id(scan_id)
        if not report_dict:
            raise HTTPException(status_code=404, detail="Scan not found")
        return JSONResponse(content=report_dict)

    if not path:
        raise HTTPException(status_code=400, detail="Must provide 'path' or 'scan_id'")

    target_path = Path(path).resolve()
    if not target_path.exists():
        raise HTTPException(status_code=400, detail="Target path does not exist")

    report = engine.scan(target_path, save_to_db=False)
    filename = f"repoguard_report_{report.repo_name}.json"
    return Response(
        content=generate_json_report(report),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/file-content")
async def get_file_content(repo_path: str, file_path: str, line: Optional[int] = None):
    """Retrieve file lines around flagged line for code viewer."""
    try:
        base = Path(repo_path).resolve()
        target = (base / file_path).resolve()
        # Security check: must reside inside base
        if not str(target).startswith(str(base)):
            raise HTTPException(status_code=403, detail="Access denied: path traversal attempt")

        if not target.is_file():
            raise HTTPException(status_code=404, detail="File not found")

        content = target.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        return JSONResponse(content={
            "file_path": file_path,
            "total_lines": len(lines),
            "flagged_line": line,
            "lines": lines
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/template/{file_name}")
async def get_hygiene_template(file_name: str):
    """Retrieve standard starter boilerplate for missing hygiene files."""
    template_content = HygieneScanner.get_template(file_name)
    return JSONResponse(content={"file_name": file_name, "content": template_content})
