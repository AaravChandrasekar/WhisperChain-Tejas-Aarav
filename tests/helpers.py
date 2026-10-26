"""Shared test helpers, including the client side of the blind-signature flow."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.blind import blind, unblind
from app.main import app

client = TestClient(app)


def login(username, password="password1"):
    token = client.post("/login", json={"username": username, "password": password}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


ADMIN = login("root", "rootpass1")


def new_user(username, roles):
    client.post("/register", json={"username": username, "password": "password1", "roles": roles})
    client.post(f"/admin/users/{username}/approve", headers=ADMIN)
    return login(username)


def get_credential(headers):
    """Make a pseudonym key, blind it, get it signed, unblind."""
    pk = client.get("/tokens/public-key").json()
    n, e = int(pk["n"], 16), pk["e"]
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    blinded, r = blind(pub, n, e)
    resp = client.post("/tokens/credential", headers=headers, json={"blinded": format(blinded, "x")})
    assert resp.status_code == 200
    return priv, pub, unblind(int(resp.json()["blind_signature"], 16), r, n)


def make_token(priv, pub, cred, round_id):
    return {"pseudonym": pub.hex(), "credential": format(cred, "x"),
            "round_sig": priv.sign(f"round:{round_id}".encode()).hex()}
