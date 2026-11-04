"""Drive the command-line client end to end against the app, with a throwaway key folder."""
import io
import json
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import client as cli
import whisper_crypto as wc
from app.db import tx
from app.main import app

REQUESTS = []  # (method, path, headers) of every request the client makes


class RecordingClient(TestClient):
    def request(self, method, url, **kwargs):
        REQUESTS.append((method, str(url), kwargs.get("headers") or {}))
        return super().request(method, url, **kwargs)


cli._http = lambda: RecordingClient(app)
cli.HOME = Path(tempfile.mkdtemp())
TEXT = "thanks for staying late to help with the lab"


def run(user, *args, password="password1"):
    """Run one client command, answering every password prompt. Returns (exit code, output)."""
    out = io.StringIO()
    with patch("getpass.getpass", return_value=password), redirect_stdout(out), redirect_stderr(out):
        code = cli.main(["-u", user, *args])
    return code, out.getvalue()


def ok(user, *args, **kwargs):
    code, out = run(user, *args, **kwargs)
    assert code == 0, out
    return out


# Set up the way the README demo does: register, admin approves, open a round, log in.
ok("cara", "register", "--roles", "recipient")
ok("cole", "register", "--roles", "sender")
ok("root", "login", password="rootpass1")
assert "cara: recipient" in ok("root", "pending") and "cole: sender" in ok("root", "pending")
ok("root", "approve", "cara")
ok("root", "approve", "cole")
ok("root", "open-round")
ok("cara", "login")
ok("cole", "login")
ok("cole", "credential")


def test_send_is_anonymous_and_recipient_decrypts():
    REQUESTS.clear()
    assert "Sent anonymously to cara" in ok("cole", "send", "cara", TEXT)
    assert REQUESTS and all("Authorization" not in headers for _, _, headers in REQUESTS)
    out = ok("cara", "inbox")
    assert TEXT in out and "verified anonymous sender" in out


def test_one_message_per_round():
    code, out = run("cole", "send", "cara", "a second one")
    assert code == 1 and "already used this round" in out


def test_swapped_recipient_key_is_refused():
    pins = cli.HOME / "cole" / "pinned_keys.json"
    real = pins.read_text()
    pins.write_text(json.dumps({"cara": "0" * 64}))  # as if cara's key changed on the server
    REQUESTS.clear()
    code, out = run("cole", "send", "cara", "hello")
    assert code == 1 and "has changed" in out
    assert not any(path.endswith("/messages") for _, path, _ in REQUESTS)  # refused before sending
    pins.write_text(real)


def test_unverifiable_messages_are_hidden():
    rogue = Ed25519PrivateKey.generate()  # a pseudonym with no real credential
    cara_key = wc.load_public_key(next(u for u in cli.call("GET", "/directory") if u["username"] == "cara")["public_key"])
    with tx() as db:  # planted straight into the database, e.g. by a malicious server
        db.execute("INSERT INTO messages (id, recipient, ciphertext) VALUES ('planted', 'cara', ?)",
                   (wc.seal(wc.build_inner("fake compliment", "cara", 1, rogue, 12345), cara_key),))
    out = ok("cara", "inbox")
    assert "[planted] hidden, failed verification" in out and "fake compliment" not in out


def test_flag_and_audit():
    msg_id = next(line.split("]")[0][1:] for line in ok("cara", "inbox").splitlines()
                  if "verified anonymous sender" in line)
    assert "Flagged" in ok("cara", "flag", msg_id)
    out = ok("root", "audit")
    assert "Hash chain valid: True" in out and "message_flagged" in out
    assert "cara" not in out and "cole" not in out


def test_wrong_password_and_missing_setup():
    assert run("cara", "inbox", password="wrong")[1].strip() == "error: Wrong password"
    assert "No keys" in run("nobody", "inbox")[1]
    assert "already has keys" in run("cara", "register", "--roles", "recipient")[1]
    assert "already have a credential" in run("cole", "credential")[1]
    assert "not an active recipient" in run("cole", "send", "root", "hi")[1]


def test_local_files_are_private_and_encrypted():
    for name in ["rsa.pem", "pseudonym.pem", "credential.json", "session.json"]:
        assert (cli.HOME / "cole" / name).stat().st_mode & 0o777 == 0o600
    assert b"ENCRYPTED" in (cli.HOME / "cole" / "rsa.pem").read_bytes()
    assert b"ENCRYPTED" in (cli.HOME / "cole" / "pseudonym.pem").read_bytes()