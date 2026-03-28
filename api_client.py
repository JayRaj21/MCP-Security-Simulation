"""GitHub REST API client — the open-source data backend for v2.

Why GitHub API?
  * Truly open-source and free for public repositories.
  * Provides realistic "file" semantics (list, read, SHA integrity).
  * No separate server to run — the data layer is already hosted.
  * Rate limit: 60 req/hr unauthenticated, 5 000 req/hr with a personal token.

Set ``GITHUB_TOKEN`` in the environment to raise the rate limit.
Set ``GITHUB_REPO`` to point at any public repository (default: public-apis/public-apis).
"""
import base64
from typing import Tuple

import requests


class GitHubAPIClient:
    """Read-only client wrapping the GitHub REST API v3.

    All write paths are intentionally absent — the data layer is immutable
    from this server's perspective, which satisfies the *unalterable* requirement.
    """

    _BASE = "https://api.github.com"

    def __init__(self, repo: str, branch: str = "master", token: str = "") -> None:
        self._repo = repo
        self._branch = branch
        self._headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "MCP-Security-Simulation-v2",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def list_contents(self, path: str = "") -> list:
        """List files (and directories) at *path* in the repository.

        Returns a list of dicts, each with keys:
            name, path, type (``"file"`` or ``"dir"``), size, sha
        """
        url = f"{self._BASE}/repos/{self._repo}/contents/{path.lstrip('/')}"
        resp = requests.get(
            url,
            headers=self._headers,
            params={"ref": self._branch},
            timeout=10,
        )
        resp.raise_for_status()
        items = resp.json()
        if isinstance(items, dict):
            # GitHub returns a single object when the path is a file
            return [self._summarise(items)]
        return [self._summarise(i) for i in items]

    def read_file(self, path: str) -> Tuple[str, str]:
        """Fetch and decode a file's content.

        Returns:
            (content_str, sha) — the decoded UTF-8 content and the Git blob SHA.

        The SHA can be used for additional integrity cross-checking against the
        HMAC signature provided by :class:`~v2.crypto.CryptoManager`.
        """
        url = f"{self._BASE}/repos/{self._repo}/contents/{path.lstrip('/')}"
        resp = requests.get(
            url,
            headers=self._headers,
            params={"ref": self._branch},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list) or data.get("type") != "file":
            raise ValueError(f"'{path}' is not a file (got type={data.get('type')})")
        encoding = data.get("encoding", "")
        raw = data.get("content", "")
        if encoding == "base64":
            content = base64.b64decode(raw).decode("utf-8", errors="replace")
        else:
            content = raw
        return content, data.get("sha", "")

    def repo_info(self) -> dict:
        """Return basic metadata about the configured repository."""
        url = f"{self._BASE}/repos/{self._repo}"
        resp = requests.get(url, headers=self._headers, timeout=10)
        resp.raise_for_status()
        d = resp.json()
        return {
            "full_name": d.get("full_name"),
            "description": d.get("description"),
            "default_branch": d.get("default_branch"),
            "html_url": d.get("html_url"),
            "stargazers_count": d.get("stargazers_count"),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _summarise(item: dict) -> dict:
        return {
            "name": item.get("name", ""),
            "path": item.get("path", ""),
            "type": item.get("type", ""),
            "size": item.get("size", 0),
            "sha": item.get("sha", ""),
        }
