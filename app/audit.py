"""Append-only, hash-chained and signed audit log. Logs role-level metadata only, never usernames.

Each entry's hash covers the previous entry's hash, and the system's Ed25519 audit key signs it, so
even someone who can write to the database can't rewrite history without the key file."""
import hashlib
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .blind import load_key

_key = load_key(os.environ.get("WC_AUDIT_KEY", "audit_key.pem"), Ed25519PrivateKey.generate)


def _hash(prev: str, ts: str, action: str, role: str) -> str:
    return hashlib.sha256(f"{prev}|{ts}|{action}|{role}".encode()).hexdigest()


def audit(db, action: str, role: str):
    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else "0" * 64
    ts = datetime.now(timezone.utc).isoformat()
    h = _hash(prev, ts, action, role)
    db.execute(
        "INSERT INTO audit_log (ts, action, role, prev_hash, hash, sig) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, action, role, prev, h, _key.sign(h.encode()).hex()),
    )


def verify_chain(db) -> bool:
    """True if every entry links to the one before it and carries a valid signature."""
    prev, pub = "0" * 64, _key.public_key()
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        if r["prev_hash"] != prev or r["hash"] != _hash(prev, r["ts"], r["action"], r["role"]):
            return False
        try:
            pub.verify(bytes.fromhex(r["sig"]), r["hash"].encode())
        except InvalidSignature:
            return False
        prev = r["hash"]
    return True
