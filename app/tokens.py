"""Rounds and anonymous sender tokens"""
import hashlib
import sqlite3
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .audit import audit
from .auth import require
from .blind import load_server_key, sign_blinded, verify
from .db import tx

router = APIRouter()

_key = load_server_key()
N, E = _key.public_key().public_numbers().n, _key.public_key().public_numbers().e
D = _key.private_numbers().d

HEX = r"^[0-9a-f]+$"


class BlindIn(BaseModel):
    blinded: str = Field(pattern=HEX)


class TokenIn(BaseModel):
    pseudonym: str = Field(pattern=HEX)   # Ed25519 public key (raw bytes, hex)
    credential: str = Field(pattern=HEX)  # unblinded server signature on the pseudonym
    round_sig: str = Field(pattern=HEX)   # pseudonym's signature over b"round:<id>"


def now():
    return datetime.now(timezone.utc).isoformat()


def open_round(db) -> int:
    row = db.execute("SELECT id FROM rounds WHERE closed_at IS NULL").fetchone()
    if not row:
        raise HTTPException(409, "No open round")
    return row["id"]


# Ends whatever round is currently active and starts a fresh one
@router.post("/admin/rounds/open")
def start_round(_: dict = Depends(require("admin"))):
    with tx() as db:
        if db.execute("UPDATE rounds SET closed_at = ? WHERE closed_at IS NULL", (now(),)).rowcount:
            audit(db, "round_closed", "admin")  # same event as an explicit close, so every round's end is logged
        rid = db.execute("INSERT INTO rounds (opened_at) VALUES (?)", (now(),)).lastrowid
        audit(db, "round_opened", "admin")
    return {"round": rid}

# Ends the current round
@router.post("/admin/rounds/close")
def end_round(_: dict = Depends(require("admin"))):
    with tx() as db:
        rid = open_round(db)
        db.execute("UPDATE rounds SET closed_at = ? WHERE id = ?", (now(), rid))
        audit(db, "round_closed", "admin")
    return {"round": rid, "status": "closed"}

# Tells clients which round is currently active so they know what payload to sign in their token
@router.get("/rounds/current")
def current_round():
    with tx() as db:
        return {"round": open_round(db)}


# Exposes the server's public RSA modulus and exponent
# Senders need these to blind their pseudonym keys locally before asking for a credential
@router.get("/tokens/public-key")
def public_key():
    return {"n": format(N, "x"), "e": E}

# Issues a blind RSA signature over a sender's pseudonym
@router.post("/tokens/credential")
def issue_credential(body: BlindIn, user: dict = Depends(require("sender"))):
    blinded = int(body.blinded, 16)
    if not 1 < blinded < N:
        raise HTTPException(400, "Invalid blinded value")
    with tx() as db:
        try:
            db.execute("INSERT INTO credentials_issued VALUES (?)", (user["username"],))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Credential already issued")
        audit(db, "credential_issued", "sender")
    return {"blind_signature": format(sign_blinded(blinded, D, N), "x")}

# Accept a token once per pseudonym per round, unless frozen
def redeem_token(db, t: TokenIn):
    rid = open_round(db)
    pub = bytes.fromhex(t.pseudonym)
    if not verify(pub, int(t.credential, 16), N, E):
        raise HTTPException(403, "Invalid credential")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(t.round_sig), f"round:{rid}".encode())
    except (InvalidSignature, ValueError):
        raise HTTPException(403, "Invalid round signature")
    pseudonym_hash = hashlib.sha256(pub).hexdigest()
    if db.execute("SELECT 1 FROM frozen_pseudonyms WHERE pseudonym_hash = ?", (pseudonym_hash,)).fetchone():
        raise HTTPException(403, "Token frozen by a moderator")
    try:
        db.execute("INSERT INTO spent_tokens VALUES (?, ?)", (pseudonym_hash, rid))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Token already used this round")
    audit(db, "token_used", "sender")
