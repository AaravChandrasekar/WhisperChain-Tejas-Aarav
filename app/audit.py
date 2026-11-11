"""Append-only, hash-chained and signed audit log. Logs role-level metadata only, never usernames.

Each entry's hash covers the previous entry's hash, and the system's Ed25519 audit key signs it, so
even someone who can write to the database can't rewrite history without the key file. The newest
entry's id and hash are also kept outside the database (`audit_head.json`, or `WC_AUDIT_HEAD`, protected
like the key), so deleting the newest entries, which leaves a valid shorter chain, is caught too."""
import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .blind import load_key

_key = load_key(os.environ.get("WC_AUDIT_KEY", "audit_key.pem"), Ed25519PrivateKey.generate)
_head_lock = threading.Lock()


def _hash(prev: str, ts: str, action: str, role: str) -> str:
    return hashlib.sha256(f"{prev}|{ts}|{action}|{role}".encode()).hexdigest()


def _head_path() -> str:
    return os.environ.get("WC_AUDIT_HEAD", "audit_head.json")


def _read_head():
    try:
        with open(_head_path()) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def _write_head(entry_id: int, h: str):
    tmp = _head_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"id": entry_id, "hash": h}, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, _head_path())  # atomic, so a crash never leaves a half-written head


def _advance_head(entry_id: int, h: str):
    """Runs after commit. Only moves forward, and never recreates a missing head for an existing log:
    deleting the head file must not be a way to make a truncated log look valid again."""
    with _head_lock:
        head = _read_head()
        if (head is None and entry_id == 1) or (head is not None and entry_id > head["id"]):
            _write_head(entry_id, h)


def audit(db, action: str, role: str):
    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else "0" * 64
    ts = datetime.now(timezone.utc).isoformat()
    h = _hash(prev, ts, action, role)
    entry_id = db.execute(
        "INSERT INTO audit_log (ts, action, role, prev_hash, hash, sig) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, action, role, prev, h, _key.sign(h.encode()).hex()),
    ).lastrowid
    db.after_commit.append(lambda: _advance_head(entry_id, h))


def verify_chain(db) -> bool:
    """True if every entry links to the one before it, carries a valid signature, and the log still
    reaches the newest entry recorded in the head file (so nothing was cut off the end)."""
    prev, pub = "0" * 64, _key.public_key()
    hashes = {}
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        if r["prev_hash"] != prev or r["hash"] != _hash(prev, r["ts"], r["action"], r["role"]):
            return False
        try:
            pub.verify(bytes.fromhex(r["sig"]), r["hash"].encode())
        except InvalidSignature:
            return False
        prev = hashes[r["id"]] = r["hash"]
    head = _read_head()
    if head is None:
        return not hashes  # an empty log needs no head; a non-empty one without its head can't be trusted
    return hashes.get(head["id"]) == head["hash"]


if __name__ == "__main__":
    # `python -m app.audit`: one-time anchor for a log written before head files existed.
    # It accepts the log as it is now, so only run it on a log you trust.
    from .db import tx
    with tx() as db:
        last = db.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        if not last or _read_head():
            sys.exit("Nothing to do: the log is empty or already anchored.")
        _write_head(last["id"], last["hash"])
        print(f"Anchored at entry {last['id']}. Chain valid: {verify_chain(db)}")
