"""Key directory, message submission, inbox and audit log access (RBAC checks)."""
import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import whisper_crypto as wc

from .audit import audit, verify_chain
from .auth import require
from .db import tx
from .tokens import TokenIn, redeem_token

router = APIRouter()


class MessageIn(BaseModel):
    token: TokenIn
    recipient: str
    ciphertext: str = Field(min_length=1, max_length=8192)  # whisper_crypto envelope

# Returns the full list of recipient public keys so anyone can start an encrypted chat
@router.get("/directory")
def directory():
    with tx() as db:
        rows = db.execute(
            """SELECT username, public_key FROM users JOIN user_roles USING (username)
               WHERE role = 'recipient' AND status = 'active' AND public_key IS NOT NULL
               ORDER BY username"""
        ).fetchall()
    return [{"username": r["username"], "public_key": r["public_key"], "fingerprint": wc.fingerprint(r["public_key"])}
            for r in rows]

# Sends an encrypted message into a recipient's queue without requiring sender login
@router.post("/messages", status_code=201)
def send_message(body: MessageIn):
    try:
        wc.parse_envelope(body.ciphertext)  # shape only, and before the token so a bad envelope doesn't spend it
    except wc.InvalidMessage as exc:
        raise HTTPException(400, str(exc))
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
            msg_id = secrets.token_hex(16)  # hex, so an id never starts with "-" and looks like a CLI flag
            db.execute("INSERT INTO messages (id, recipient, ciphertext) VALUES (?, ?, ?)",
                       (msg_id, body.recipient, body.ciphertext))
            audit(db, "message_sent", "sender")
    except HTTPException:
        with tx() as db:  # separate transaction: the failed one above was rolled back
            audit(db, "token_rejected", "sender")
        raise
    return {"id": msg_id}

# Pulls incoming messages for the logged-in recipient while keeping them encrypted
@router.get("/inbox")
def inbox(user: dict = Depends(require("recipient"))):
    with tx() as db:
        rows = db.execute("SELECT id, ciphertext, delivered, id IN (SELECT message_id FROM flags) AS flagged "
                          "FROM messages WHERE recipient = ?", (user["username"],)).fetchall()
        new = [r["id"] for r in rows if not r["delivered"]]
        db.executemany("UPDATE messages SET delivered = 1 WHERE id = ?", [(i,) for i in new])
        for _ in new:
            audit(db, "message_delivered", "recipient")
    return [{"id": r["id"], "ciphertext": r["ciphertext"], "flagged": bool(r["flagged"])} for r in rows]

# Read-only view of role-level events with no identities and no message content)
@router.get("/audit")
def audit_log(user: dict = Depends(require("moderator", "admin"))):
    with tx() as db:
        audit(db, "audit_viewed", ",".join(sorted(user["roles"] & {"moderator", "admin"})))
        rows = db.execute("SELECT id, ts, action, role FROM audit_log ORDER BY id").fetchall()
        return {"chain_valid": verify_chain(db), "entries": [dict(r) for r in rows]}