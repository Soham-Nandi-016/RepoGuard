"""
RepoGuard Module D2: FastAPI Web Application & Dashboard
Light-theme-only responsive web UI, REST API endpoints, live repository scanner,
and standalone report exporter.
"""

import io
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Optional, Dict, List
from fastapi import FastAPI, Request, HTTPException, Query, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from repoguard.core.engine import RepoGuardEngine
from repoguard.core.db import db
from repoguard.reporting.html_report import generate_html_report
from repoguard.reporting.json_report import generate_json_report
from repoguard.scanners.hygiene_scanner import HygieneScanner

# In-memory store for uploaded scan file contents so the code viewer modal can display flagged lines
UPLOADED_FILES_STORE: Dict[str, Dict[str, List[str]]] = {}


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


@app.post("/api/scan-upload")
async def scan_upload(
    file: UploadFile = File(...),
    save_to_db: bool = Query(True)
):
    """
    Handle uploaded .py files or .zip repository archives in memory,
    extract to a temporary folder, run engine.run_scan(), cache file contents
    in memory for the code inspector, and auto-clean temporary files.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    filename = file.filename
    lower_name = filename.lower()
    is_zip = lower_name.endswith(".zip")
    is_py = lower_name.endswith(".py")

    if not is_zip and not is_py:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format. Please upload a single .py file or a .zip repository archive."
        )

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    temp_dir_obj = tempfile.TemporaryDirectory(prefix="repoguard_upload_")
    try:
        temp_dir = Path(temp_dir_obj.name).resolve()
        scan_target = temp_dir

        if is_zip:
            try:
                zip_buffer = io.BytesIO(contents)
                if not zipfile.is_zipfile(zip_buffer):
                    raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive.")
                with zipfile.ZipFile(zip_buffer, "r") as zf:
                    # Guard against Zip Slip / path traversal
                    for member in zf.infolist():
                        extracted_path = (temp_dir / member.filename).resolve()
                        if not str(extracted_path).startswith(str(temp_dir)):
                            raise HTTPException(status_code=400, detail="ZIP archive contains unsafe path traversal.")
                    zf.extractall(temp_dir)
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Failed to extract ZIP archive: {str(e)}")

            # Check if archive has a single top-level directory (e.g. GitHub repo-main)
            child_items = [p for p in temp_dir.iterdir() if p.name not in ("__MACOSX", ".DS_Store")]
            if len(child_items) == 1 and child_items[0].is_dir():
                scan_target = child_items[0]

        elif is_py:
            safe_name = Path(filename).name or "script.py"
            py_target = temp_dir / safe_name
            py_target.write_bytes(contents)
            scan_target = temp_dir

        # Cache file lines in memory for code viewer modal
        cached_files: Dict[str, List[str]] = {}
        for f in scan_target.rglob("*"):
            if f.is_file():
                try:
                    rel = str(f.relative_to(scan_target)).replace("\\", "/")
                    cached_files[rel] = f.read_text(encoding="utf-8", errors="replace").splitlines()
                except Exception:
                    pass

        # Execute scan via engine.run_scan
        report = engine.run_scan(scan_target, save_to_db=save_to_db)

        # Enhance report metadata with upload branding
        display_name = Path(filename).name
        upload_identifier = f"[Upload] {display_name}"
        report.repo_name = display_name
        report.repo_path = upload_identifier
        report_dict = report.to_dict()
        report_dict["repo_name"] = display_name
        report_dict["repo_path"] = upload_identifier

        # Store in in-memory file cache keyed by upload_identifier
        UPLOADED_FILES_STORE[upload_identifier] = cached_files
        if len(UPLOADED_FILES_STORE) > 30:
            oldest_key = next(iter(UPLOADED_FILES_STORE))
            del UPLOADED_FILES_STORE[oldest_key]

        return JSONResponse(content=report_dict)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")
    finally:
        # Guarantee auto-clean of temporary files
        temp_dir_obj.cleanup()


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
        # Check in-memory store for uploaded scans
        if repo_path in UPLOADED_FILES_STORE:
            norm_file = file_path.replace("\\", "/")
            lines = None
            if norm_file in UPLOADED_FILES_STORE[repo_path]:
                lines = UPLOADED_FILES_STORE[repo_path][norm_file]
            else:
                base_name = Path(file_path).name
                for k, v in UPLOADED_FILES_STORE[repo_path].items():
                    if k.endswith(base_name) or base_name in k:
                        lines = v
                        break

            if lines is not None:
                return JSONResponse(content={
                    "file_path": file_path,
                    "total_lines": len(lines),
                    "flagged_line": line,
                    "lines": lines
                })

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
