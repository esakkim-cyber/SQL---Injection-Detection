"""Database setup and seed data."""

from __future__ import annotations

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash


db = SQLAlchemy()


def init_database(app: Flask) -> None:
    """Create tables and insert demo users if the database is empty."""
    from .models import User

    db.create_all()

    # Seed only once. The plaintext column is present only for the intentionally
    # vulnerable route; the secure route verifies the password hash.
    if User.query.count() == 0:
        users = [
            User(
                username="admin",
                full_name="Administrator",
                role="admin",
                password_plain="password123",
                password_hash=generate_password_hash("password123"),
            ),
            User(
                username="alice",
                full_name="Alice Khan",
                role="student",
                password_plain="alice123",
                password_hash=generate_password_hash("alice123"),
            ),
            User(
                username="bob",
                full_name="Bob Ahmed",
                role="student",
                password_plain="bob123",
                password_hash=generate_password_hash("bob123"),
            ),
        ]
        db.session.add_all(users)
        db.session.commit()

    # This tiny ping catches broken database URLs early and gives a clear error.
    db.session.execute(text("SELECT 1"))
