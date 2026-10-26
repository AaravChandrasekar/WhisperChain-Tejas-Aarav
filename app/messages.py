"""Message submission, inbox, flagging and moderation view (RBAC checks)."""
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

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
    with tx() as db:
        redeem_token(db, body.token)
        msg_id = secrets.token_urlsafe(16)
        db.execute("INSERT INTO messages (id, recipient, ciphertext) VALUES (?, ?, ?)",
                   (msg_id, body.recipient, body.ciphertext))
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
    return {"id": msg_id, "flagged": True}


@router.get("/moderation/flagged")
def flagged(_: dict = Depends(require("moderator"))):
    """Moderators only, and only flagged messages. No sender info exists to return."""
    with tx() as db:
        rows = db.execute("SELECT id, ciphertext FROM messages WHERE flagged = 1").fetchall()
    return [dict(r) for r in rows]
