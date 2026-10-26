from helpers import ADMIN, client, get_credential, make_token, new_user

from app.db import tx

RECIPIENT = new_user("ria", ["recipient"])
OTHER = new_user("omar", ["recipient"])
MODERATOR = new_user("moe", ["moderator"])
SENDER = new_user("sol", ["sender", "recipient"])
CRED = get_credential(SENDER)


def send(token, recipient="ria", text="you explained recursion so well!"):
    return client.post("/messages", json={"token": token, "recipient": recipient, "ciphertext": text})


def test_only_token_holders_can_send():
    rid = client.post("/admin/rounds/open", headers=ADMIN).json()["round"]
    assert send(make_token(*CRED, rid), recipient="moe").status_code == 404  # not a recipient
    assert send(make_token(*CRED, rid)).status_code == 201
    assert send(make_token(*CRED, rid)).status_code == 409  # one per round
    assert send({"pseudonym": "ab", "credential": "cd", "round_sig": "ef"}).status_code == 403  # no valid token


def test_inbox_is_own_only():
    assert len(client.get("/inbox", headers=RECIPIENT).json()) == 1
    assert client.get("/inbox", headers=OTHER).json() == []
    assert client.get("/inbox", headers=MODERATOR).status_code == 403
    assert client.get("/inbox", headers=ADMIN).status_code == 403


def test_flagging_and_moderation():
    msg_id = client.get("/inbox", headers=RECIPIENT).json()[0]["id"]
    assert client.get("/moderation/flagged", headers=MODERATOR).json() == []  # unflagged is invisible
    assert client.post(f"/messages/{msg_id}/flag", headers=OTHER).status_code == 404  # not their message
    assert client.post(f"/messages/{msg_id}/flag", headers=RECIPIENT).status_code == 200
    assert client.get("/moderation/flagged", headers=MODERATOR).json()[0]["id"] == msg_id
    for who in (ADMIN, SENDER, RECIPIENT):
        assert client.get("/moderation/flagged", headers=who).status_code == 403


def test_no_sender_info_stored():
    with tx() as db:
        assert db.execute("SELECT * FROM messages").fetchone().keys() == ["id", "recipient", "ciphertext", "flagged"]


def test_audit_log_access_and_events():
    assert client.get("/audit", headers=SENDER).status_code == 403
    assert client.get("/audit", headers=ADMIN).status_code == 200
    log = client.get("/audit", headers=MODERATOR).json()
    assert log["chain_valid"]
    actions = {e["action"] for e in log["entries"]}
    assert {"credential_issued", "token_used", "message_sent", "token_rejected", "message_flagged"} <= actions
    assert "ria" not in str(log) and "sol" not in str(log)  # no identities
