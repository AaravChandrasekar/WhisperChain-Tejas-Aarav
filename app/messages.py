"""Message submission, inbox, flagging, moderation view and audit log access (RBAC checks)."""
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .audit import audit, verify_chain
from .auth import require
from .db import tx
from .tokens import TokenIn, redeem_token

router = APIRouter()


class MessageIn(BaseModel):
    token: TokenIn
    recipient: str
    ciphertext: str = Field(min_length=1, max_length=4096)  # opaque to the server; encrypted client-side in Week 3


@router.post("/messages", status_code=201)
def send_message(body: MessageIn):
    """No login on purpose: a valid token proves the caller is a Sender without revealing which one."""
    with tx() as db:
        if not db.execute(
            """SELECT 1 FROM users JOIN user_roles USING (username)
               WHERE username = ? AND role = 'recipient' AND status = 'active'""",
            (body.recipient,),
        ).fetchone():
            raise HTTPException(404, "No such recipient")
    try:
        with tx() as db:
            redeem_token(db, body.token)
            msg_id = secrets.token_urlsafe(16)
            db.execute("INSERT INTO messages (id, recipient, ciphertext) VALUES (?, ?, ?)",
                       (msg_id, body.recipient, body.ciphertext))
            audit(db, "message_sent", "sender")
    except HTTPException:
        with tx() as db:  # separate transaction: the failed one above was rolled back
            audit(db, "token_rejected", "sender")
        raise
    return {"id": msg_id}


@router.get("/inbox")
def inbox(user: dict = Depends(require("recipient"))):
    """Own messages only."""
    with tx() as db:
        rows = db.execute("SELECT id, ciphertext, flagged FROM messages WHERE recipient = ?",
                          (user["username"],)).fetchall()
    return [dict(r) for r in rows]


@router.post("/messages/{msg_id}/flag")
def flag(msg_id: str, user: dict = Depends(require("recipient"))):
    with tx() as db:
        updated = db.execute("UPDATE messages SET flagged = 1 WHERE id = ? AND recipient = ?",
                             (msg_id, user["username"])).rowcount
        if not updated:  # same response for "doesn't exist" and "not yours"
            raise HTTPException(404, "No such message in your inbox")
        audit(db, "message_flagged", "recipient")
    return {"id": msg_id, "flagged": True}


@router.get("/moderation/flagged")
def flagged(_: dict = Depends(require("moderator"))):
    """Moderators only, and only flagged messages. No sender info exists to return."""
    with tx() as db:
        rows = db.execute("SELECT id, ciphertext FROM messages WHERE flagged = 1").fetchall()
    return [dict(r) for r in rows]


@router.get("/audit")
def audit_log(_: dict = Depends(require("moderator", "admin"))):
    """Read-only view of role-level events (no identities, no message content)."""
    with tx() as db:
        rows = db.execute("SELECT id, ts, action, role FROM audit_log ORDER BY id").fetchall()
        return {"chain_valid": verify_chain(db), "entries": [dict(r) for r in rows]}
