"""
RepoGuard GitHub Repository Archive Loader
Downloads public GitHub repository archives in-memory for security and compliance audits.
Zero cloud disk persistence: keeps archives strictly in-memory (io.BytesIO).
"""

import io
import re
from typing import Tuple
import httpx


GITHUB_URL_REGEX = re.compile(r"github\.com/([^/]+)/([^/]+)")


def parse_github_url(repo_url: str) -> Tuple[str, str]:
    """
    Normalize a GitHub repository URL and extract the owner and repository names.
    Strips leading/trailing whitespace, trailing slashes, and '.git' suffixes.

    Returns:
        Tuple[str, str]: (owner, repo)

    Raises:
        ValueError: If the URL format is invalid or cannot be parsed.
    """
    if not repo_url or not isinstance(repo_url, str):
        raise ValueError("Repository URL must be a non-empty string.")

    normalized = repo_url.strip()

    # Strip trailing slashes
    normalized = normalized.rstrip("/")

    # Strip .git suffix
    if normalized.endswith(".git"):
        normalized = normalized[:-4]

    match = GITHUB_URL_REGEX.search(normalized)
    if not match:
        raise ValueError(
            f"Invalid GitHub repository URL: '{repo_url}'. "
            "Expected format: https://github.com/{owner}/{repo}"
        )

    owner = match.group(1).strip()
    repo = match.group(2).strip()

    # Remove query parameters or fragments if present
    if "?" in repo:
        repo = repo.split("?")[0].strip()
    if "#" in repo:
        repo = repo.split("#")[0].strip()

    if not owner or not repo:
        raise ValueError(
            f"Invalid GitHub repository URL: '{repo_url}'. "
            "Could not parse valid owner and repository names."
        )

    return owner, repo


def download_github_repo_zip(repo_url: str) -> io.BytesIO:
    """
    Download a public GitHub repository ZIP archive directly into an in-memory BytesIO buffer.
    
    1. Normalizes the URL and parses owner/repo.
    2. Attempts download from 'main' branch (archive/refs/heads/main.zip).
    3. Falls back to 'master' branch (archive/refs/heads/master.zip) if main is not 200.
    4. Enforces a 15.0s timeout and cleanly handles network / URL errors.

    Returns:
        io.BytesIO: In-memory buffer containing the downloaded ZIP archive.

    Raises:
        ValueError: On invalid URL, non-200 responses (e.g. 404 private/non-existent),
                    network failures, or timeouts.
    """
    owner, repo = parse_github_url(repo_url)

    branches = ["main", "master"]
    headers = {
        "User-Agent": "RepoGuard/1.0 (Automated Security Auditor; GitHub In-Memory Scanner)",
        "Accept": "application/vnd.github.v3+json, application/zip, */*"
    }

    last_status = None

    try:
        with httpx.Client(timeout=15.0, follow_redirects=True, headers=headers) as client:
            for branch in branches:
                archive_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
                try:
                    response = client.get(archive_url)
                    last_status = response.status_code
                    if response.status_code == 200:
                        content = response.content
                        if not content:
                            raise ValueError(
                                f"Downloaded archive from GitHub for '{owner}/{repo}' ({branch}) is empty."
                            )
                        buffer = io.BytesIO(content)
                        buffer.seek(0)
                        return buffer
                except httpx.TimeoutException:
                    raise ValueError(
                        f"Connection to GitHub timed out (15.0s limit) while requesting {archive_url}."
                    )
                except httpx.RequestError as exc:
                    raise ValueError(
                        f"Network error while connecting to GitHub ({archive_url}): {str(exc)}"
                    )

        # Neither main nor master returned 200
        raise ValueError(
            f"Could not access public repository '{owner}/{repo}'. "
            f"GitHub returned HTTP status {last_status}. "
            "Please check that the repository exists, is public, and contains a 'main' or 'master' branch."
        )

    except ValueError:
        raise
    except httpx.TimeoutException:
        raise ValueError(
            f"Connection to GitHub timed out (15.0s limit) for repository '{owner}/{repo}'."
        )
    except httpx.RequestError as exc:
        raise ValueError(
            f"Network error while fetching repository '{owner}/{repo}': {str(exc)}"
        )
    except Exception as exc:
        raise ValueError(f"Unexpected error while downloading repository '{owner}/{repo}': {str(exc)}")

