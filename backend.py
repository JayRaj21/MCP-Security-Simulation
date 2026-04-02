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
    """Thin HTTP wrapper around the JSONPlaceholder REST API.

    Soft-delete state is held in memory and reset to empty on every
    instantiation (i.e. every server startup), so all resources are
    automatically restored to their original state when the server starts.
    """

    def __init__(self) -> None:
        # In-memory soft-delete sets — cleared on every startup (restore on init)
        self._deleted: dict[str, set] = {"users": set(), "posts": set(), "todos": set()}
        print("[gateway] BackendAPI initialised — all resources restored to original state")

    # ------------------------------------------------------------------
    # Soft-delete management
    # ------------------------------------------------------------------

    def delete_user(self, user_id: int) -> None:
        self._deleted["users"].add(user_id)

    def delete_post(self, post_id: int) -> None:
        self._deleted["posts"].add(post_id)

    def delete_todo(self, todo_id: int) -> None:
        self._deleted["todos"].add(todo_id)

    def restore_all(self) -> dict:
        """Clear all soft-deletes. Returns counts of what was restored."""
        counts = {k: len(v) for k, v in self._deleted.items()}
        for s in self._deleted.values():
            s.clear()
        return counts

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def list_users(self) -> list:
        r = requests.get(f"{_BASE}/users", timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if self._deleted["users"]:
            data = [u for u in data if u["id"] not in self._deleted["users"]]
        return data

    def get_user(self, user_id: int) -> dict:
        if user_id in self._deleted["users"]:
            raise ValueError(f"User {user_id} not found (deleted)")
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
        data = r.json()
        if self._deleted["posts"]:
            data = [p for p in data if p["id"] not in self._deleted["posts"]]
        return data

    def get_post(self, post_id: int) -> dict:
        if post_id in self._deleted["posts"]:
            raise ValueError(f"Post {post_id} not found (deleted)")
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
        data = r.json()
        if self._deleted["todos"]:
            data = [t for t in data if t["id"] not in self._deleted["todos"]]
        return data

    def get_todo(self, todo_id: int) -> dict:
        if todo_id in self._deleted["todos"]:
            raise ValueError(f"Todo {todo_id} not found (deleted)")
        r = requests.get(f"{_BASE}/todos/{todo_id}", timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json()
