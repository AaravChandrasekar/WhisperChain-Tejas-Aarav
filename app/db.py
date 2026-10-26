import os
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,
    pw_hash    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
    public_key TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS user_roles (
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    role     TEXT NOT NULL CHECK (role IN ('sender', 'recipient', 'moderator', 'admin')),
    PRIMARY KEY (username, role)
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS rounds (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    opened_at TEXT NOT NULL,
    closed_at TEXT
);
-- Records only THAT a user got a credential, never the (blinded) pseudonym itself.
CREATE TABLE IF NOT EXISTS credentials_issued (
    username TEXT PRIMARY KEY REFERENCES users(username)
);
-- One row per pseudonym per round. Identity-free: pseudonyms can't be linked to users.
CREATE TABLE IF NOT EXISTS spent_tokens (
    pseudonym_hash TEXT NOT NULL,
    round_id       INTEGER NOT NULL REFERENCES rounds(id),
    PRIMARY KEY (pseudonym_hash, round_id)
);
-- No sender, no timestamp, random id: nothing here points back to who sent it.
CREATE TABLE IF NOT EXISTS messages (
    id         TEXT PRIMARY KEY,
    recipient  TEXT NOT NULL REFERENCES users(username),
    ciphertext TEXT NOT NULL,
    flagged    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    action    TEXT NOT NULL,
    role      TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
-- Append-only: the database itself rejects edits/deletes to the audit log.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


@contextmanager
def tx():
    """Open a connection, run everything inside one transaction, then close."""
    conn = sqlite3.connect(os.environ.get("WC_DB", "whisperchain.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db():
    with tx() as db:
        db.executescript(SCHEMA)
