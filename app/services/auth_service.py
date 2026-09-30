"""Authentication service with vulnerable and secure login flows."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import text
from werkzeug.security import check_password_hash

from ..database import db
from ..models import User

USERNAME_WHITELIST = re.compile(r"^[A-Za-z0-9_]{3,30}$")


@dataclass
class LoginResult:
    success: bool
    message: str
    user: dict | None
    query_preview: str
    blocked: bool = False


class AuthService:
    """Contains intentionally vulnerable and secure authentication code."""

    @staticmethod
    def vulnerable_login(username: str, password: str) -> LoginResult:
        """Intentionally unsafe raw SQL query for demonstration only.

        This method concatenates user input into SQL. It exists so the final
        project can clearly show why SQL injection is dangerous. Do not copy it
        into any real application.
        """
        query = (
            "SELECT id, username, full_name, role FROM users "
            f"WHERE username = '{username}' AND password_plain = '{password}'"
        )
        row = db.session.execute(text(query)).mappings().first()
        if row:
            return LoginResult(
                success=True,
                message="Logged in through the vulnerable query. This may be a SQL injection bypass.",
                user=dict(row),
                query_preview=query,
            )
        return LoginResult(False, "Invalid credentials in vulnerable mode.", None, query)

    @staticmethod
    def secure_login(username: str, password: str) -> LoginResult:
        """Secure authentication with whitelist validation and bound parameters."""
        if not USERNAME_WHITELIST.fullmatch(username or ""):
            return LoginResult(
                success=False,
                message="Blocked by input validation: username must be 3-30 letters, numbers, or underscores.",
                user=None,
                query_preview="No database query executed because validation failed.",
                blocked=True,
            )

        # Parameterized query: username is treated as data, not executable SQL.
        stmt = text(
            "SELECT id, username, full_name, role, password_hash FROM users WHERE username = :username"
        )
        row = db.session.execute(stmt, {"username": username}).mappings().first()
        query_preview = "SELECT ... FROM users WHERE username = :username  -- parameterized"

        if row and check_password_hash(row["password_hash"], password):
            return LoginResult(
                success=True,
                message="Logged in securely using validation + prepared statement + password hash.",
                user={
                    "id": row["id"],
                    "username": row["username"],
                    "full_name": row["full_name"],
                    "role": row["role"],
                },
                query_preview=query_preview,
            )
        return LoginResult(False, "Invalid credentials in secure mode.", None, query_preview)

    @staticmethod
    def parameterized_only_demo(username: str, password: str) -> LoginResult:
        """Show that prepared statements prevent bypass even if WAF is disabled."""
        stmt = text(
            "SELECT id, username, full_name, role FROM users "
            "WHERE username = :username AND password_plain = :password"
        )
        row = db.session.execute(stmt, {"username": username, "password": password}).mappings().first()
        preview = (
            "SELECT id, username, full_name, role FROM users "
            "WHERE username = :username AND password_plain = :password"
        )
        if row:
            return LoginResult(True, "Matched only when parameters exactly equal stored data.", dict(row), preview)
        return LoginResult(False, "No bypass: malicious text was treated as a literal username.", None, preview)
