import hashlib
import hmac
import os
import secrets
import time

from fastapi import Depends, Header, HTTPException

from .db import tx

ROLES = {"sender", "recipient", "moderator", "admin"}
SESSION_TTL = 60 * 60  # 1 hour


def hash_pw(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}${key.hex()}"


def check_pw(password: str, stored: str) -> bool:
    salt = bytes.fromhex(stored.split("$")[0])
    return hmac.compare_digest(hash_pw(password, salt), stored)


DUMMY_HASH = hash_pw("dummy")  # compared against for unknown users so timing doesn't leak usernames


def validate_roles(roles: set[str]):
    if not roles or not roles <= ROLES:
        raise HTTPException(400, f"Roles must be a non-empty subset of {sorted(ROLES)}")
    if {"admin", "moderator"} <= roles:
        raise HTTPException(400, "Separation of duties: a user cannot be both admin and moderator")


def set_roles(db, username: str, roles: set[str]):
    db.execute("DELETE FROM user_roles WHERE username = ?", (username,))
    db.executemany("INSERT INTO user_roles VALUES (?, ?)", [(username, r) for r in roles])


def new_session(db, username: str) -> str:
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions VALUES (?, ?, ?)",
        (hashlib.sha256(token.encode()).hexdigest(), username, time.time() + SESSION_TTL),
    )
    return token


def current_user(authorization: str = Header()) -> dict:
    token_hash = hashlib.sha256(authorization.removeprefix("Bearer ").encode()).hexdigest()
    with tx() as db:
        row = db.execute(
            """SELECT u.username FROM sessions s JOIN users u USING (username)
               WHERE s.token_hash = ? AND s.expires_at > ? AND u.status = 'active'""",
            (token_hash, time.time()),
        ).fetchone()
        if not row:
            raise HTTPException(401, "Invalid or expired session")
        roles = {r["role"] for r in db.execute("SELECT role FROM user_roles WHERE username = ?", (row["username"],))}
    return {"username": row["username"], "roles": roles}


def require(*allowed: str):
    """RBAC dependency: deny unless the user holds at least one allowed role."""
    def dep(user: dict = Depends(current_user)) -> dict:
        if not user["roles"] & set(allowed):
            raise HTTPException(403, "Forbidden for your role")
        return user
    return dep
