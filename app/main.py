import sqlite3

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from .audit import audit
from .auth import DUMMY_HASH, check_pw, current_user, hash_pw, new_session, require, set_roles, validate_roles
from .db import init_db, tx
from .messages import router as messages_router
from .tokens import router as tokens_router

init_db()
app = FastAPI(title="WhisperChain+")
app.include_router(tokens_router)
app.include_router(messages_router)


class RegisterIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,32}$")
    password: str = Field(min_length=8, max_length=128)
    roles: set[str]
    public_key: str | None = None  # PEM, generated client-side (Week 3)


class LoginIn(BaseModel):
    username: str
    password: str


class RolesIn(BaseModel):
    roles: set[str]


@app.post("/register", status_code=201)
def register(body: RegisterIn):
    """Anyone can request an account; it stays 'pending' until an admin approves it."""
    validate_roles(body.roles)
    if "admin" in body.roles:
        raise HTTPException(403, "Admin accounts cannot be self-requested")
    with tx() as db:
        try:
            db.execute(
                "INSERT INTO users (username, pw_hash, public_key) VALUES (?, ?, ?)",
                (body.username, hash_pw(body.password), body.public_key),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username taken")
        set_roles(db, body.username, body.roles)
        audit(db, "registration_requested", ",".join(sorted(body.roles)))
    return {"username": body.username, "status": "pending"}


@app.post("/login")
def login(body: LoginIn):
    with tx() as db:
        row = db.execute("SELECT pw_hash, status FROM users WHERE username = ?", (body.username,)).fetchone()
        if not check_pw(body.password, row["pw_hash"] if row else DUMMY_HASH) or row["status"] != "active":
            raise HTTPException(401, "Invalid credentials or account not active")
        return {"token": new_session(db, body.username)}


@app.get("/me")
def me(user: dict = Depends(current_user)):
    return {"username": user["username"], "roles": sorted(user["roles"])}


# ---------- Admin: manages registration and roles (cannot see messages) ----------

@app.get("/admin/pending")
def pending(_: dict = Depends(require("admin"))):
    with tx() as db:
        rows = db.execute(
            """SELECT u.username, group_concat(r.role) AS roles FROM users u
               LEFT JOIN user_roles r USING (username) WHERE u.status = 'pending' GROUP BY u.username"""
        ).fetchall()
    return [{"username": r["username"], "requested_roles": (r["roles"] or "").split(",")} for r in rows]


def _get_user(db, username: str):
    row = db.execute("SELECT status FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        raise HTTPException(404, "No such user")
    return row


@app.post("/admin/users/{username}/approve")
def approve(username: str, body: RolesIn | None = None, _: dict = Depends(require("admin"))):
    """Activate a pending account, optionally overriding the requested roles."""
    with tx() as db:
        if _get_user(db, username)["status"] != "pending":
            raise HTTPException(409, "User is not pending")
        if body:
            validate_roles(body.roles)
            set_roles(db, username, body.roles)
        db.execute("UPDATE users SET status = 'active' WHERE username = ?", (username,))
        audit(db, "user_approved", "admin")
    return {"username": username, "status": "active"}


@app.put("/admin/users/{username}/roles")
def assign_roles(username: str, body: RolesIn, _: dict = Depends(require("admin"))):
    validate_roles(body.roles)
    with tx() as db:
        _get_user(db, username)
        set_roles(db, username, body.roles)
        audit(db, "roles_changed", "admin")
    return {"username": username, "roles": sorted(body.roles)}


@app.post("/admin/users/{username}/revoke")
def revoke(username: str, _: dict = Depends(require("admin"))):
    with tx() as db:
        _get_user(db, username)
        db.execute("UPDATE users SET status = 'revoked' WHERE username = ?", (username,))
        db.execute("DELETE FROM sessions WHERE username = ?", (username,))
        audit(db, "user_revoked", "admin")
    return {"username": username, "status": "revoked"}
