"""Unit tests for Module D2: FastAPI Web API Endpoints."""

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
    assert "ITL709" in response.text


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
