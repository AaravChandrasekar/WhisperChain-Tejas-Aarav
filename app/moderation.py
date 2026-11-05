"""Flagging and moderation. A recipient flags a message by re-encrypting what they decrypted for
every moderator, so flagged content stays unreadable at rest to everyone else (admins included)."""
import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

import whisper_crypto as wc

from .audit import audit
from .auth import require
from .db import tx

router = APIRouter()


class FlagIn(BaseModel):
    reports: dict[str, str]  # moderator username -> the decrypted message re-sealed for them


def active_moderators(db) -> dict[str, str]:
    rows = db.execute(
        """SELECT username, public_key FROM users JOIN user_roles USING (username)
           WHERE role = 'moderator' AND status = 'active' AND public_key IS NOT NULL ORDER BY username"""
    )
    return {r["username"]: r["public_key"] for r in rows}


@router.get("/moderation/keys")
def moderator_keys(_: dict = Depends(require("recipient"))):
    """The public keys a recipient encrypts a flag report for."""
    with tx() as db:
        return [{"username": u, "public_key": k} for u, k in active_moderators(db).items()]


@router.post("/messages/{msg_id}/flag")
def flag(msg_id: str, body: FlagIn, user: dict = Depends(require("recipient"))):
    for envelope in body.reports.values():
        try:
            wc.parse_envelope(envelope)
        except wc.InvalidMessage as exc:
            raise HTTPException(400, str(exc))
    with tx() as db:
        if not db.execute("SELECT 1 FROM messages WHERE id = ? AND recipient = ?",
                          (msg_id, user["username"])).fetchone():
            raise HTTPException(404, "No such message in your inbox")  # same for "doesn't exist" and "not yours"
        moderators = active_moderators(db)
        if not moderators:
            raise HTTPException(409, "No moderators to review flags")
        if set(body.reports) != set(moderators):
            raise HTTPException(400, "Report must be encrypted for every active moderator")
        try:
            db.execute("INSERT INTO flags (message_id, reports) VALUES (?, ?)", (msg_id, json.dumps(body.reports)))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Already flagged")
        audit(db, "message_flagged", "recipient")
    return {"id": msg_id, "flagged": True}


@router.get("/moderation/flagged")
def flagged(user: dict = Depends(require("moderator"))):
    """Moderators only, and only flagged messages, each as the report sealed for this moderator.
    `recipient` is who flagged it: their name is bound into the encryption and the sender's signature."""
    with tx() as db:
        rows = db.execute("SELECT f.message_id, m.recipient, f.reports FROM flags f "
                          "JOIN messages m ON m.id = f.message_id").fetchall()
    return [{"id": r["message_id"], "recipient": r["recipient"],
             "report": json.loads(r["reports"]).get(user["username"])} for r in rows]
