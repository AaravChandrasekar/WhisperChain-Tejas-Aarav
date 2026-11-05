"""Flagging and moderation. A recipient flags a message by re-encrypting what they decrypted for
every moderator, so flagged content stays unreadable at rest to everyone else (admins included).
Moderators dismiss a flag or freeze the anonymous sender's pseudonym, and alerting rules watch for
floods of flags and for unusually many freezes (possible moderator abuse, visible to admins)."""
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

import whisper_crypto as wc

from .audit import audit
from .auth import require
from .db import tx
from .tokens import now

router = APIRouter()

FLAG_ALERT = 5    # open flags waiting for review
FREEZE_ALERT = 3  # freezes within 24 hours


class FlagIn(BaseModel):
    reports: dict[str, str]  # moderator username -> the decrypted message re-sealed for them


class FreezeIn(BaseModel):
    pseudonym: str = Field(pattern=r"^[0-9a-f]{64}$")  # read from the decrypted, verified report


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
        if db.execute("SELECT COUNT(*) FROM flags WHERE status = 'open'").fetchone()[0] == FLAG_ALERT:
            audit(db, "alert_flag_threshold", "system")
    return {"id": msg_id, "flagged": True}


@router.get("/moderation/flagged")
def flagged(user: dict = Depends(require("moderator"))):
    """The moderator queue: open flags only, each as the report sealed for this moderator.
    `recipient` is who flagged it: their name is bound into the encryption and the sender's signature."""
    with tx() as db:
        audit(db, "flags_reviewed", "moderator")
        rows = db.execute("SELECT f.message_id, m.recipient, f.reports FROM flags f "
                          "JOIN messages m ON m.id = f.message_id WHERE f.status = 'open'").fetchall()
    return [{"id": r["message_id"], "recipient": r["recipient"],
             "report": json.loads(r["reports"]).get(user["username"])} for r in rows]


def resolve(db, msg_id: str, status: str):
    if not db.execute("UPDATE flags SET status = ? WHERE message_id = ? AND status = 'open'",
                      (status, msg_id)).rowcount:
        raise HTTPException(404, "No such open flag")


@router.post("/moderation/flags/{msg_id}/dismiss")
def dismiss(msg_id: str, _: dict = Depends(require("moderator"))):
    with tx() as db:
        resolve(db, msg_id, "dismissed")
        audit(db, "flag_dismissed", "moderator")
    return {"id": msg_id, "status": "dismissed"}


@router.post("/moderation/flags/{msg_id}/freeze")
def freeze(msg_id: str, body: FreezeIn, _: dict = Depends(require("moderator"))):
    """Refuse all future tokens from the flagged message's pseudonym. Nobody learns who it belongs to."""
    with tx() as db:
        resolve(db, msg_id, "frozen")
        db.execute("INSERT OR IGNORE INTO frozen_pseudonyms VALUES (?, ?)",
                   (hashlib.sha256(bytes.fromhex(body.pseudonym)).hexdigest(), now()))
        audit(db, "token_frozen", "moderator")
        since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        recent = db.execute("SELECT COUNT(*) FROM frozen_pseudonyms WHERE frozen_at > ?", (since,)).fetchone()[0]
        if recent == FREEZE_ALERT:
            audit(db, "alert_freeze_threshold", "system")
    return {"id": msg_id, "status": "frozen"}
