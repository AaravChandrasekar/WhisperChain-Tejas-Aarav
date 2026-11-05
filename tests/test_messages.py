import os

import pytest
from helpers import ADMIN, KEYS, client, get_credential, make_token, new_user

import whisper_crypto as wc
from app.db import tx

RECIPIENT = new_user("ria", ["recipient"])
OTHER = new_user("omar", ["recipient"])
MODERATOR = new_user("moe", ["moderator"])
SENDER = new_user("sol", ["sender", "recipient"])
CRED = get_credential(SENDER)
TEXT = "you explained recursion so well!"


def envelope(round_id, to="ria", text=TEXT):
    """What a sender's client does: find the recipient's key in the directory and encrypt for it."""
    keys = {u["username"]: u["public_key"] for u in client.get("/directory").json()}
    priv, _, cred = CRED
    return wc.seal(wc.build_inner(text, to, round_id, priv, cred), wc.load_public_key(keys[to]))


def send(token, ciphertext, recipient="ria"):
    return client.post("/messages", json={"token": token, "recipient": recipient, "ciphertext": ciphertext})


def test_directory_is_public_and_lists_only_active_recipients():
    new_user("pat", ["recipient"])
    client.post("/admin/users/pat/revoke", headers=ADMIN)
    directory = client.get("/directory").json()  # no login needed
    names = [u["username"] for u in directory]
    assert "ria" in names and "sol" in names
    assert not {"moe", "pat", "root"} & set(names)  # not a recipient / revoked / admin
    ria = next(u for u in directory if u["username"] == "ria")
    assert ria["fingerprint"] == wc.fingerprint(wc.public_pem(KEYS["ria"]))


def test_only_token_holders_can_send():
    rid = client.post("/admin/rounds/open", headers=ADMIN).json()["round"]
    env = envelope(rid)
    assert send(make_token(*CRED, rid), env, recipient="moe").status_code == 404  # not a recipient
    assert send(make_token(*CRED, rid), "not an envelope").status_code == 400  # refused before the token is spent
    assert send(make_token(*CRED, rid), env).status_code == 201
    assert send(make_token(*CRED, rid), env).status_code == 409  # one per round
    assert send({"pseudonym": "ab", "credential": "cd", "round_sig": "ef"}, env).status_code == 403  # no valid token


def test_inbox_is_own_only():
    assert len(client.get("/inbox", headers=RECIPIENT).json()) == 1
    assert client.get("/inbox", headers=OTHER).json() == []
    assert client.get("/inbox", headers=MODERATOR).status_code == 403
    assert client.get("/inbox", headers=ADMIN).status_code == 403


def test_recipient_decrypts_and_verifies_locally():
    pk = client.get("/tokens/public-key").json()
    [msg] = client.get("/inbox", headers=RECIPIENT).json()
    inner = wc.unseal(msg["ciphertext"], KEYS["ria"], "ria")
    wc.verify_inner(inner, "ria", int(pk["n"], 16), pk["e"])
    assert inner["text"] == TEXT
    with pytest.raises(wc.InvalidMessage):
        wc.unseal(msg["ciphertext"], KEYS["omar"], "omar")


def report_for_moderators(msg):
    """What a recipient's client does: decrypt the message and re-seal it for every moderator."""
    inner = wc.unseal(msg["ciphertext"], KEYS["ria"], "ria")
    return {"reports": {m["username"]: wc.seal(inner, wc.load_public_key(m["public_key"]))
                        for m in client.get("/moderation/keys", headers=RECIPIENT).json()}}


def test_flagging_and_moderation():
    def flagged():
        return {f["id"]: f for f in client.get("/moderation/flagged", headers=MODERATOR).json()}

    msg = client.get("/inbox", headers=RECIPIENT).json()[0]
    body = report_for_moderators(msg)
    assert msg["id"] not in flagged()  # unflagged is invisible
    assert client.post(f"/messages/{msg['id']}/flag", headers=OTHER, json=body).status_code == 404  # not theirs
    assert client.post(f"/messages/{msg['id']}/flag", headers=RECIPIENT,
                       json={"reports": {}}).status_code == 400  # not sealed for every moderator
    assert client.post(f"/messages/{msg['id']}/flag", headers=RECIPIENT, json=body).status_code == 200
    assert client.post(f"/messages/{msg['id']}/flag", headers=RECIPIENT, json=body).status_code == 409
    assert client.get("/inbox", headers=RECIPIENT).json()[0]["flagged"]

    # The moderator decrypts the report and verifies a real pseudonym sent it to ria.
    report = flagged()[msg["id"]]
    pk = client.get("/tokens/public-key").json()
    inner = wc.unseal(report["report"], KEYS["moe"], report["recipient"])
    wc.verify_inner(inner, "ria", int(pk["n"], 16), pk["e"])
    assert inner["text"] == TEXT and inner["pseudonym"] == CRED[1].hex()
    for who in (ADMIN, SENDER, RECIPIENT):
        assert client.get("/moderation/flagged", headers=who).status_code == 403
    assert client.get("/moderation/keys", headers=ADMIN).status_code == 403


def test_no_sender_info_stored():
    with tx() as db:
        assert db.execute("SELECT * FROM messages").fetchone().keys() == \
            ["id", "recipient", "ciphertext", "delivered"]
        tables = {r["name"]: r["sql"] for r in db.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table'")}
    assert "WITHOUT ROWID" in tables["messages"] and "WITHOUT ROWID" in tables["spent_tokens"]
    with open(os.environ["WC_DB"], "rb") as f:
        raw = f.read()
    assert b'"ct"' in raw  # the envelope is on disk...
    assert TEXT.encode() not in raw and CRED[1].hex().encode() not in raw  # no plaintext, no pseudonym


def test_audit_log_access_and_events():
    assert client.get("/audit", headers=SENDER).status_code == 403
    assert client.get("/audit", headers=ADMIN).status_code == 200
    log = client.get("/audit", headers=MODERATOR).json()
    assert log["chain_valid"]
    actions = [e["action"] for e in log["entries"]]
    assert {"key_registered", "credential_issued", "token_used", "message_sent", "token_rejected",
            "message_flagged"} <= set(actions)
    with tx() as db:
        delivered = db.execute("SELECT COUNT(*) FROM messages WHERE delivered = 1").fetchone()[0]
    assert actions.count("message_delivered") == delivered  # each logged once, however often inboxes are fetched
    assert "ria" not in str(log) and "sol" not in str(log)  # no identities