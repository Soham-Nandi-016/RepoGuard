"""Re-export GitHub loader from repoguard.scanner.github_loader."""
from repoguard.scanner.github_loader import download_github_repo_zip, parse_github_url

__all__ = ["download_github_repo_zip", "parse_github_url"]

