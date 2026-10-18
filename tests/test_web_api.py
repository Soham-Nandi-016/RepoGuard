"""Unit tests for Module D2: FastAPI Web API Endpoints."""

import io
import zipfile
import pytest
from fastapi.testclient import TestClient
from repoguard.web.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_dashboard_endpoint(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    assert "RepoGuard" in response.text
    assert "Protect Every Repository" in response.text
    assert "GPLv3 License" in response.text
    assert "University of Mumbai" not in response.text
    assert "ITL709" not in response.text


def test_api_scan_endpoint(client: TestClient):
    response = client.post(
        "/api/scan",
        json={"path": "samples/vulnerable_repo", "save_to_db": True}
    )
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert data["summary"]["critical_count"] > 0
    assert "ast_issues" in data


def test_api_scan_invalid_path(client: TestClient):
    response = client.post(
        "/api/scan",
        json={"path": "invalid/non_existent_folder", "save_to_db": False}
    )
    assert response.status_code == 400


def test_api_scan_upload_single_py(client: TestClient):
    py_code = b"import os\nos.system('rm -rf /')\neval('1+1')\n"
    response = client.post(
        "/api/scan-upload",
        files={"file": ("vulnerable_script.py", py_code, "text/x-python")},
        params={"save_to_db": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["repo_name"] == "vulnerable_script.py"
    assert data["summary"]["critical_count"] > 0
    assert len(data["ast_issues"]) >= 2


def test_api_scan_upload_zip_archive(client: TestClient):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("test_repo/main.py", "eval('2+2')\n")
        zf.writestr("test_repo/README.md", "# Test Repo\n")
        zf.writestr("test_repo/LICENSE", "MIT License\n")
    zip_buffer.seek(0)

    response = client.post(
        "/api/scan-upload",
        files={"file": ("test_repo.zip", zip_buffer.getvalue(), "application/zip")},
        params={"save_to_db": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["repo_name"] == "test_repo.zip"
    assert "summary" in data
    assert any(i["id"] == "AST-SEC-001" for i in data["ast_issues"])


def test_api_scan_upload_invalid_extension(client: TestClient):
    response = client.post(
        "/api/scan-upload",
        files={"file": ("unsupported.txt", b"hello world", "text/plain")}
    )
    assert response.status_code == 400
    assert "Unsupported file format" in response.json()["detail"]


def test_api_file_content_uploaded(client: TestClient):
    py_code = b"x = 1\neval('x')\n"
    upload_res = client.post(
        "/api/scan-upload",
        files={"file": ("temp_sample.py", py_code, "text/x-python")},
        params={"save_to_db": False}
    )
    assert upload_res.status_code == 200
    upload_data = upload_res.json()
    repo_path = upload_data["repo_path"]

    res = client.get(f"/api/file-content?repo_path={repo_path}&file_path=temp_sample.py&line=2")
    assert res.status_code == 200
    content = res.json()
    assert content["total_lines"] == 2
    assert "eval('x')" in content["lines"][1]


def test_api_history_endpoint(client: TestClient):
    response = client.get("/api/history")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_api_template_endpoint(client: TestClient):
    response = client.get("/api/template/SECURITY.md")
    assert response.status_code == 200
    data = response.json()
    assert "Security Policy" in data["content"]


def test_api_export_html_endpoint(client: TestClient):
    response = client.get("/api/export/html?path=samples/clean_repo")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "RepoGuard" in response.text
