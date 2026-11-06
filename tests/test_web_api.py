"""Unit tests for Module D2: FastAPI Web API Endpoints."""

from unittest.mock import patch
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
    assert "https://cdn.tailwindcss.com" in response.text
    assert "/static/css/styles.css" in response.text
    assert "github-scan-btn" in response.text
    assert "University of Mumbai" not in response.text
    assert "ITL709" not in response.text


def test_index_html_endpoint(client: TestClient):
    response = client.get("/index.html")
    assert response.status_code == 200
    assert "RepoGuard" in response.text
    assert "https://cdn.tailwindcss.com" in response.text


def test_static_css_endpoint(client: TestClient):
    response = client.get("/static/css/styles.css")
    assert response.status_code == 200
    assert "text/css" in response.headers.get("content-type", "")
    assert "--color-brand" in response.text
    # Verify local compiled utility classes and responsive breakpoints are present
    assert ".flex {" in response.text
    assert ".grid {" in response.text
    assert ".bg-white {" in response.text
    assert ".max-w-7xl {" in response.text
    assert "@media (min-width: 640px)" in response.text


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


@patch("repoguard.web.app.download_github_repo_zip")
def test_api_scan_github_endpoint(mock_download, client: TestClient):
    """Test full in-memory GitHub scan via POST /api/scan-github."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("test-repo-main/main.py", "eval('1+1')\nos.system('ls')\n")
        zf.writestr("test-repo-main/README.md", "# Test GitHub Repo\n")
        zf.writestr("test-repo-main/LICENSE", "MIT License\n")
    zip_buffer.seek(0)
    mock_download.return_value = zip_buffer

    response = client.post(
        "/api/scan-github",
        data={"repo_url": "https://github.com/test-org/test-repo"},
        params={"save_to_db": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["repo_name"] == "test-org/test-repo"
    assert data["repo_path"] == "[GitHub] test-org/test-repo"
    assert "summary" in data
    assert data["summary"]["critical_count"] > 0
    assert any(i["id"] == "AST-SEC-001" for i in data["ast_issues"])


def test_api_scan_github_invalid_url(client: TestClient):
    """Test HTTP 400 rejection on invalid repository URLs."""
    response = client.post(
        "/api/scan-github",
        data={"repo_url": "https://gitlab.com/invalid/repo"}
    )
    assert response.status_code == 400
    assert "Invalid GitHub repository URL" in response.json()["detail"]


def test_api_scan_github_missing_url(client: TestClient):
    """Test HTTP 400 rejection when repo_url parameter is empty."""
    response = client.post(
        "/api/scan-github",
        data={"repo_url": ""}
    )
    assert response.status_code == 400
    assert "Missing required 'repo_url' parameter" in response.json()["detail"]


@patch("repoguard.web.app.download_github_repo_zip")
def test_api_scan_github_unreachable_repository(mock_download, client: TestClient):
    """Test HTTP 400 error return when repository is private or unreachable."""
    mock_download.side_effect = ValueError("Could not access public repository 'secret/repo'. HTTP status 404.")

    response = client.post(
        "/api/scan-github",
        data={"repo_url": "https://github.com/secret/repo"}
    )
    assert response.status_code == 400
    assert "Could not access public repository" in response.json()["detail"]


@patch("repoguard.web.app.download_github_repo_zip")
def test_api_file_content_github_scan(mock_download, client: TestClient):
    """Test that code inspector modal can view files from in-memory GitHub scan."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("sample-repo-main/app.py", "x = 1\neval('x + 1')\n")
        zf.writestr("sample-repo-main/README.md", "# Sample\n")
        zf.writestr("sample-repo-main/LICENSE", "MIT License\n")
    zip_buffer.seek(0)
    mock_download.return_value = zip_buffer

    scan_res = client.post(
        "/api/scan-github",
        data={"repo_url": "https://github.com/sample/repo"},
        params={"save_to_db": False}
    )
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    repo_path = scan_data["repo_path"]

    res = client.get(f"/api/file-content?repo_path={repo_path}&file_path=app.py&line=2")
    assert res.status_code == 200
    content = res.json()
    assert content["total_lines"] == 2
    assert "eval('x + 1')" in content["lines"][1]

