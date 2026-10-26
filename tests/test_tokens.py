from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from helpers import ADMIN, client, get_credential, make_token, new_user

from app.db import tx
from app.tokens import TokenIn, redeem_token


def redeem_status(token):
    try:
        with tx() as db:
            redeem_token(db, TokenIn(**token))
        return 200
    except HTTPException as e:
        return e.status_code


def test_only_admin_opens_rounds():
    sender = new_user("tara", ["sender"])
    assert client.post("/admin/rounds/open", headers=sender).status_code == 403


def test_only_senders_get_one_credential():
    recipient = new_user("rita", ["recipient"])
    assert client.post("/tokens/credential", headers=recipient, json={"blinded": "abc"}).status_code == 403
    sender = new_user("sid", ["sender"])
    get_credential(sender)
    assert client.post("/tokens/credential", headers=sender, json={"blinded": "abc"}).status_code == 409


def test_one_token_per_round():
    priv, pub, cred = get_credential(new_user("tess", ["sender"]))

    r1 = client.post("/admin/rounds/open", headers=ADMIN).json()["round"]
    assert client.get("/rounds/current").json()["round"] == r1
    assert redeem_status(make_token(priv, pub, cred, r1)) == 200
    assert redeem_status(make_token(priv, pub, cred, r1)) == 409  # second message same round

    r2 = client.post("/admin/rounds/open", headers=ADMIN).json()["round"]
    assert redeem_status(make_token(priv, pub, cred, r1)) == 403  # stale round signature
    assert redeem_status(make_token(priv, pub, cred, r2)) == 200  # fresh round, fresh token

    client.post("/admin/rounds/close", headers=ADMIN)
    assert redeem_status(make_token(priv, pub, cred, r2)) == 409  # no open round


def test_forged_credential_rejected():
    rid = client.post("/admin/rounds/open", headers=ADMIN).json()["round"]
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    assert redeem_status(make_token(priv, pub, 12345, rid)) == 403


def test_server_cannot_link_token_to_user():
    with tx() as db:
        assert db.execute("SELECT * FROM credentials_issued").fetchone().keys() == ["username"]  # no pseudonym stored
        assert db.execute("SELECT * FROM spent_tokens").fetchone().keys() == ["pseudonym_hash", "round_id"]  # no user
