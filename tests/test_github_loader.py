"""Unit tests for GitHub Repository Archive Loader and in-memory download pipeline."""

import io
import zipfile
import pytest
from unittest.mock import patch, MagicMock
import httpx

from repoguard.scanner.github_loader import parse_github_url, download_github_repo_zip


def _create_mock_zip(file_content: str = "print('hello world')\n") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("test-repo-main/main.py", file_content)
        zf.writestr("test-repo-main/README.md", "# Test Repo\n")
        zf.writestr("test-repo-main/LICENSE", "MIT License\n")
    return buffer.getvalue()


def test_parse_github_url_valid_formats():
    """Verify standard, trailing slash, .git suffix, and variant URL normalization."""
    test_cases = [
        ("https://github.com/torvalds/linux", ("torvalds", "linux")),
        ("https://github.com/torvalds/linux/", ("torvalds", "linux")),
        ("https://github.com/torvalds/linux.git", ("torvalds", "linux")),
        ("https://github.com/torvalds/linux.git/", ("torvalds", "linux")),
        ("http://github.com/pallets/flask", ("pallets", "flask")),
        ("github.com/psf/requests", ("psf", "requests")),
        ("https://github.com/owner-name/repo.name", ("owner-name", "repo.name")),
        ("https://github.com/owner/repo?branch=main#readme", ("owner", "repo")),
    ]
    for url, expected in test_cases:
        assert parse_github_url(url) == expected


def test_parse_github_url_invalid_formats():
    """Verify invalid or non-GitHub URLs raise descriptive ValueError."""
    invalid_urls = [
        "",
        "   ",
        None,
        123,
        "https://gitlab.com/owner/repo",
        "https://bitbucket.org/owner/repo",
        "https://github.com/",
        "https://github.com/onlyowner",
        "https://example.com/owner/repo",
        "not-a-valid-url",
    ]
    for url in invalid_urls:
        with pytest.raises(ValueError):
            parse_github_url(url)


@patch("httpx.Client.get")
def test_download_github_repo_zip_main_success(mock_get):
    """Verify archive download succeeds directly via 'main' branch."""
    zip_bytes = _create_mock_zip("x = eval('1+1')\n")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = zip_bytes
    mock_get.return_value = mock_resp

    result = download_github_repo_zip("https://github.com/owner/myrepo")

    assert isinstance(result, io.BytesIO)
    assert zipfile.is_zipfile(result)
    with zipfile.ZipFile(result, "r") as zf:
        namelist = zf.namelist()
        assert "test-repo-main/main.py" in namelist
        assert "test-repo-main/README.md" in namelist


@patch("httpx.Client.get")
def test_download_github_repo_zip_fallback_to_master(mock_get):
    """Verify fallback to 'master.zip' when 'main.zip' returns non-200 (e.g. 404)."""
    zip_bytes = _create_mock_zip("import os\n")

    resp_404 = MagicMock()
    resp_404.status_code = 404
    resp_404.content = b"Not Found"

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.content = zip_bytes

    # First request for main.zip returns 404; second request for master.zip returns 200
    mock_get.side_effect = [resp_404, resp_200]

    result = download_github_repo_zip("https://github.com/owner/legacy-repo")

    assert isinstance(result, io.BytesIO)
    assert zipfile.is_zipfile(result)
    assert mock_get.call_count == 2
    first_url = mock_get.call_args_list[0][0][0]
    second_url = mock_get.call_args_list[1][0][0]
    assert "refs/heads/main.zip" in first_url
    assert "refs/heads/master.zip" in second_url


@patch("httpx.Client.get")
def test_download_github_repo_zip_both_branches_fail(mock_get):
    """Verify descriptive ValueError when neither branch returns 200 (private or missing repo)."""
    resp_404 = MagicMock()
    resp_404.status_code = 404
    resp_404.content = b"Not Found"
    mock_get.return_value = resp_404

    with pytest.raises(ValueError) as excinfo:
        download_github_repo_zip("https://github.com/private-org/hidden-repo")

    assert "Could not access public repository" in str(excinfo.value)
    assert "HTTP status 404" in str(excinfo.value)


@patch("httpx.Client.get")
def test_download_github_repo_zip_timeout(mock_get):
    """Verify clean exception handling on network timeout."""
    mock_get.side_effect = httpx.TimeoutException("Timed out connecting")

    with pytest.raises(ValueError) as excinfo:
        download_github_repo_zip("https://github.com/slow-org/slow-repo")

    assert "timed out" in str(excinfo.value).lower()


@patch("httpx.Client.get")
def test_download_github_repo_zip_network_error(mock_get):
    """Verify clean exception handling on connection / DNS failure."""
    mock_get.side_effect = httpx.RequestError("DNS lookup failed")

    with pytest.raises(ValueError) as excinfo:
        download_github_repo_zip("https://github.com/broken-dns/broken-repo")

    assert "network error" in str(excinfo.value).lower()

