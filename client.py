"""WhisperChain+ command-line client. Keys are made and used only on this machine: the server
only ever sees public keys, blinded values and ciphertext.

    python client.py -u ria register --roles recipient
    python client.py -u ria login
    python client.py -u sol credential
    python client.py -u sol send ria "you explained recursion so well!"
    python client.py -u ria inbox

Each user's files live in $WC_HOME/<user>/ (default ~/.whisperchain), readable only by you,
with private keys encrypted under the account password.
"""
import argparse
import getpass
import json
import os
import sys
from collections import Counter
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import whisper_crypto as wc

SERVER = os.environ.get("WC_SERVER", "http://127.0.0.1:8000")
HOME = Path(os.environ.get("WC_HOME", Path.home() / ".whisperchain"))


class ClientError(Exception):
    """Something the user should see as a one-line error."""


# ---------- Server and local files ----------

def _http() -> httpx.Client:
    return httpx.Client(base_url=SERVER, timeout=30)


def call(method: str, path: str, user: str | None = None, **kwargs):
    """One request. With `user`, sends their saved session; without, nothing that identifies anyone."""
    headers = {"Authorization": f"Bearer {session(user)}"} if user else {}
    http = _http()
    try:
        r = http.request(method, path, headers=headers, **kwargs)
    finally:
        http.close()
    if r.is_error:
        try:
            detail = r.json()["detail"]
        except (ValueError, KeyError):
            detail = r.text
        raise ClientError(f"{r.status_code}: {detail}")
    return r.json()


def home(user: str) -> Path:
    d = HOME / user
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def write_private(path: Path, data: bytes):
    """Write a file only this OS user can read."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def session(user: str) -> str:
    path = home(user) / "session.json"
    if not path.exists():
        raise ClientError(f"Not logged in; run: python client.py -u {user} login")
    return json.loads(path.read_text())["token"]


def unlock(user: str):
    """Ask for the password and check it against the local private key. Returns (password, rsa_key)."""
    path = home(user) / "rsa.pem"
    if not path.exists():
        raise ClientError(f"No keys for {user} on this machine; run register first")
    password = getpass.getpass(f"Password for {user}: ")
    try:
        return password, wc.import_private_key(path.read_bytes(), password)
    except ValueError:
        raise ClientError("Wrong password") from None


def check_pin(user: str, name: str, pem: str):
    """Trust on first use: remember each recipient's key fingerprint and refuse if it later
    changes (e.g. a compromised admin swapping in a key they control)."""
    path = home(user) / "pinned_keys.json"
    pins = json.loads(path.read_text()) if path.exists() else {}
    fp = wc.fingerprint(pem)
    if pins.setdefault(name, fp) != fp:
        raise ClientError(f"{name}'s public key has changed since you last wrote to them "
                          f"(was {pins[name][:16]}, now {fp[:16]}). Not sending.")
    write_private(path, json.dumps(pins, indent=2).encode())


# ---------- Commands ----------

def cmd_register(user: str, roles: str):
    path = home(user) / "rsa.pem"
    if path.exists():
        raise ClientError(f"{user} already has keys on this machine ({path})")
    password = getpass.getpass("Choose a password (8+ characters): ")
    if getpass.getpass("Repeat it: ") != password:
        raise ClientError("Passwords don't match")
    key = wc.generate_keys()
    write_private(path, wc.export_private_key(key, password))
    try:
        call("POST", "/register", json={"username": user, "password": password,
                                        "roles": sorted(roles.split(",")), "public_key": wc.public_pem(key)})
    except Exception:
        path.unlink()  # registration failed, so this key belongs to no one
        raise
    print(f"Registered {user}; waiting for an admin to approve.")
    print(f"Your key fingerprint: {wc.fingerprint(wc.public_pem(key))[:16]}")


def cmd_login(user: str):
    password = getpass.getpass(f"Password for {user}: ")
    token = call("POST", "/login", json={"username": user, "password": password})["token"]
    write_private(home(user) / "session.json", json.dumps({"token": token}).encode())
    print(f"Logged in as {user} ({', '.join(call('GET', '/me', user=user)['roles'])}).")


def cmd_credential(user: str):
    """Get the one anonymous sender credential: the server signs a pseudonym key it never sees."""
    d = home(user)
    if (d / "credential.json").exists():
        raise ClientError("You already have a credential")
    password, _ = unlock(user)
    pk = call("GET", "/tokens/public-key")
    n, e = int(pk["n"], 16), pk["e"]
    pseudonym = Ed25519PrivateKey.generate()
    pub = pseudonym.public_key().public_bytes_raw()
    blinded, r = wc.blind(pub, n, e)
    # Saved before asking: the server only ever issues one credential per user.
    write_private(d / "pseudonym.pem", wc.export_private_key(pseudonym, password))
    blind_sig = call("POST", "/tokens/credential", user=user, json={"blinded": format(blinded, "x")})
    credential = wc.unblind(int(blind_sig["blind_signature"], 16), r, n)
    if not wc.verify(pub, credential, n, e):
        raise ClientError("The server's signature doesn't verify")
    write_private(d / "credential.json", json.dumps({"credential": format(credential, "x")}).encode())
    print("Got your anonymous sender credential. The server can't link it to you.")


def cmd_send(user: str, to: str, text: str):
    d = home(user)
    if not (d / "credential.json").exists():
        raise ClientError(f"No credential yet; run: python client.py -u {user} credential")
    password, _ = unlock(user)
    pseudonym = wc.import_private_key((d / "pseudonym.pem").read_bytes(), password)
    credential = json.loads((d / "credential.json").read_text())["credential"]

    # From here on, nothing sent names the sender: no session, just the anonymous token.
    round_id = call("GET", "/rounds/current")["round"]
    entry = next((u for u in call("GET", "/directory") if u["username"] == to), None)
    if not entry:
        raise ClientError(f"{to} is not an active recipient")
    check_pin(user, to, entry["public_key"])
    try:
        inner = wc.build_inner(text, to, round_id, pseudonym, int(credential, 16))
    except ValueError as exc:
        raise ClientError(str(exc)) from None
    token = {"pseudonym": pseudonym.public_key().public_bytes_raw().hex(), "credential": credential,
             "round_sig": pseudonym.sign(f"round:{round_id}".encode()).hex()}
    call("POST", "/messages", json={"token": token, "recipient": to,
                                    "ciphertext": wc.seal(inner, wc.load_public_key(entry["public_key"]))})
    print(f"Sent anonymously to {to} (round {round_id}).")


def cmd_inbox(user: str):
    _, key = unlock(user)
    messages = call("GET", "/inbox", user=user)
    if not messages:
        print("Inbox is empty.")
        return
    pk = call("GET", "/tokens/public-key")
    for m in messages:
        flagged = " [flagged]" if m["flagged"] else ""
        try:
            inner = wc.unseal(m["ciphertext"], key, user)
            wc.verify_inner(inner, user, int(pk["n"], 16), pk["e"])
        except wc.InvalidMessage as exc:
            # Never show text we can't verify: it could have been planted by the server itself.
            print(f"[{m['id']}]{flagged} hidden, failed verification: {exc}")
            continue
        print(f"[{m['id']}]{flagged} round {inner['round']}, from a verified anonymous sender:")
        print(f"    {inner['text']}")


def cmd_flag(user: str, message_id: str):
    """Decrypt the message and re-seal it for every moderator, so only they can read the report."""
    _, key = unlock(user)
    msg = next((m for m in call("GET", "/inbox", user=user) if m["id"] == message_id), None)
    if not msg:
        raise ClientError(f"No message {message_id} in your inbox")
    try:
        inner = wc.unseal(msg["ciphertext"], key, user)
    except wc.InvalidMessage as exc:
        raise ClientError(str(exc)) from None
    reports = {m["username"]: wc.seal(inner, wc.load_public_key(m["public_key"]))
               for m in call("GET", "/moderation/keys", user=user)}
    call("POST", f"/messages/{message_id}/flag", user=user, json={"reports": reports})
    print(f"Flagged {message_id} for moderators.")


def open_report(flag: dict, key, pk: dict) -> dict:
    """Moderators: decrypt a flag report and check it's a genuine message to whoever flagged it."""
    if not flag["report"]:
        raise wc.InvalidMessage("not sealed for you (flagged before you became a moderator)")
    inner = wc.unseal(flag["report"], key, flag["recipient"])
    wc.verify_inner(inner, flag["recipient"], int(pk["n"], 16), pk["e"])
    return inner


def cmd_dashboard(user: str):
    """Moderators: the open flag queue, decrypted and verified locally, then any alerts."""
    _, key = unlock(user)
    pk = call("GET", "/tokens/public-key")
    reports = {}
    for f in call("GET", "/moderation/flagged", user=user):
        try:
            reports[f["id"]] = open_report(f, key, pk)
        except wc.InvalidMessage as exc:
            reports[f["id"]] = exc
    per_sender = Counter(r["pseudonym"] for r in reports.values() if isinstance(r, dict))
    print(f"Open flags: {len(reports)}")
    for msg_id, r in reports.items():
        if isinstance(r, wc.InvalidMessage):
            print(f"[{msg_id}] unverifiable, consider dismissing: {r}")
            continue
        count = per_sender[r["pseudonym"]]  # many flags on one pseudonym suggests a repeat abuser
        print(f"[{msg_id}] round {r['round']}, anonymous sender {r['pseudonym'][:16]} ({count} open flags):")
        print(f"    {r['text']}")
    alerts = [e for e in call("GET", "/audit", user=user)["entries"] if e["action"].startswith("alert_")]
    print(f"Alerts: {len(alerts)}")
    for e in alerts:
        print(f"  {e['ts']}  {e['action']}")


def cmd_dismiss(user: str, message_id: str):
    call("POST", f"/moderation/flags/{message_id}/dismiss", user=user)
    print(f"Dismissed the flag on {message_id}.")


def cmd_freeze(user: str, message_id: str):
    """Freeze the sender of a flagged message. Only a verified report gives up its pseudonym."""
    _, key = unlock(user)
    flag = next((f for f in call("GET", "/moderation/flagged", user=user) if f["id"] == message_id), None)
    if not flag:
        raise ClientError(f"No open flag on {message_id}")
    try:
        inner = open_report(flag, key, call("GET", "/tokens/public-key"))
    except wc.InvalidMessage as exc:
        raise ClientError(f"Report failed verification ({exc}); dismiss it instead") from None
    call("POST", f"/moderation/flags/{message_id}/freeze", user=user, json={"pseudonym": inner["pseudonym"]})
    print(f"Froze the anonymous sender of {message_id}; their future tokens will be refused.")


def cmd_pending(user: str):
    rows = call("GET", "/admin/pending", user=user)
    for p in rows:
        print(f"{p['username']}: {', '.join(p['requested_roles'])}")
    if not rows:
        print("No pending accounts.")


def cmd_approve(user: str, username: str):
    call("POST", f"/admin/users/{username}/approve", user=user)
    print(f"Approved {username}.")


def cmd_open_round(user: str):
    print(f"Round {call('POST', '/admin/rounds/open', user=user)['round']} is open.")


def cmd_audit(user: str):
    log = call("GET", "/audit", user=user)
    print(f"Hash chain and signatures valid: {log['chain_valid']}")
    for e in log["entries"]:
        print(f"{e['id']:>4}  {e['ts']}  {e['action']:<22} {e['role']}")


# ---------- Command line ----------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="WhisperChain+ client")
    p.add_argument("-u", "--user", default=os.environ.get("WC_USER"), help="your username (or set WC_USER)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("register", help="make your keys and request an account").add_argument(
        "--roles", required=True, help="comma-separated: sender, recipient, moderator")
    sub.add_parser("login", help="start a session (lasts an hour)")
    sub.add_parser("credential", help="senders: get your anonymous credential (once)")
    s = sub.add_parser("send", help="senders: send an anonymous compliment (one per round)")
    s.add_argument("recipient")
    s.add_argument("text")
    sub.add_parser("inbox", help="recipients: decrypt and show your messages")
    sub.add_parser("flag", help="recipients: flag an abusive message").add_argument("message_id")
    sub.add_parser("dashboard", help="moderators: review open flags and alerts")
    sub.add_parser("dismiss", help="moderators: dismiss a flag").add_argument("message_id")
    sub.add_parser("freeze", help="moderators: freeze a flagged message's sender").add_argument("message_id")
    sub.add_parser("pending", help="admin: list accounts waiting for approval")
    sub.add_parser("approve", help="admin: approve an account").add_argument("username")
    sub.add_parser("open-round", help="admin: close the current round and open a new one")
    sub.add_parser("audit", help="admin/moderator: show the audit log")
    args = p.parse_args(argv)
    if not args.user:
        p.error("pass -u USERNAME or set WC_USER")

    commands = {
        "register": lambda: cmd_register(args.user, args.roles),
        "login": lambda: cmd_login(args.user),
        "credential": lambda: cmd_credential(args.user),
        "send": lambda: cmd_send(args.user, args.recipient, args.text),
        "inbox": lambda: cmd_inbox(args.user),
        "flag": lambda: cmd_flag(args.user, args.message_id),
        "dashboard": lambda: cmd_dashboard(args.user),
        "dismiss": lambda: cmd_dismiss(args.user, args.message_id),
        "freeze": lambda: cmd_freeze(args.user, args.message_id),
        "pending": lambda: cmd_pending(args.user),
        "approve": lambda: cmd_approve(args.user, args.username),
        "open-round": lambda: cmd_open_round(args.user),
        "audit": lambda: cmd_audit(args.user),
    }
    try:
        commands[args.command]()
    except ClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"error: can't reach the server at {SERVER} ({exc})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())