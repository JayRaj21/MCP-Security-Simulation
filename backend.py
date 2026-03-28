"""JSONPlaceholder REST API client — backend for the MCP gateway.

JSONPlaceholder (https://jsonplaceholder.typicode.com) is a free, open-source
fake REST API that provides realistic user, post, and todo data with no
authentication required — making it an ideal open-source data backend for
a security gateway demo.

Resources:
  users   — 10 users with contact details, addresses, and company info
  posts   — 100 blog posts (10 per user)
  todos   — 200 tasks (20 per user)
"""
import requests
from typing import Optional

_BASE    = "https://jsonplaceholder.typicode.com"
_TIMEOUT = 10


class BackendAPI:
    """Thin HTTP wrapper around the JSONPlaceholder REST API."""

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def list_users(self) -> list:
        r = requests.get(f"{_BASE}/users", timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def get_user(self, user_id: int) -> dict:
        r = requests.get(f"{_BASE}/users/{user_id}", timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Posts
    # ------------------------------------------------------------------

    def list_posts(self, user_id: Optional[int] = None) -> list:
        params = {"userId": user_id} if user_id else {}
        r = requests.get(f"{_BASE}/posts", params=params, timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def get_post(self, post_id: int) -> dict:
        r = requests.get(f"{_BASE}/posts/{post_id}", timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Todos
    # ------------------------------------------------------------------

    def list_todos(self, user_id: Optional[int] = None) -> list:
        params = {"userId": user_id} if user_id else {}
        r = requests.get(f"{_BASE}/todos", params=params, timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def get_todo(self, todo_id: int) -> dict:
        r = requests.get(f"{_BASE}/todos/{todo_id}", timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()
