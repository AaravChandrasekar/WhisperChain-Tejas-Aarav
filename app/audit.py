import hashlib
from datetime import datetime, timezone


def audit(db, action: str, role: str):
    """Append a hash-chained entry. Logs role-level metadata only, never usernames."""
    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else "0" * 64
    ts = datetime.now(timezone.utc).isoformat()
    h = hashlib.sha256(f"{prev}|{ts}|{action}|{role}".encode()).hexdigest()
    db.execute(
        "INSERT INTO audit_log (ts, action, role, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
        (ts, action, role, prev, h),
    )


def verify_chain(db) -> bool:
    prev = "0" * 64
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        expected = hashlib.sha256(f"{prev}|{r['ts']}|{r['action']}|{r['role']}".encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != expected:
            return False
        prev = r["hash"]
    return True
