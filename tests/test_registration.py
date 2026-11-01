from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import whisper_crypto as wc
from app.audit import verify_chain
from app.db import tx
from app.main import app

client = TestClient(app)
PEM = wc.public_pem(wc.generate_keys())


def login(username, password):
    r = client.post("/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {r.json()['token']}"} if r.status_code == 200 else r


def test_registration_flow():
    assert client.post("/register", json={"username": "alex", "password": "password1", "roles": ["sender", "recipient"], "public_key": PEM}).status_code == 201
    assert client.post("/register", json={"username": "alex", "password": "password1", "roles": ["sender"], "public_key": PEM}).status_code == 409
    assert login("alex", "password1").status_code == 401  # pending users can't log in

    admin = login("root", "rootpass1")
    assert client.get("/admin/pending", headers=admin).json()[0]["username"] == "alex"
    assert client.post("/admin/users/alex/approve", headers=admin).status_code == 200

    alex = login("alex", "password1")
    assert client.get("/me", headers=alex).json()["roles"] == ["recipient", "sender"]
    assert client.get("/admin/pending", headers=alex).status_code == 403  # RBAC


def test_role_rules():
    bad = [["admin"], ["admin", "moderator"], ["wizard"], []]
    for roles in bad:
        assert client.post("/register", json={"username": "eve", "password": "password1", "roles": roles, "public_key": PEM}).status_code in (400, 403)
    admin = login("root", "rootpass1")
    client.post("/register", json={"username": "mod", "password": "password1", "roles": ["moderator"], "public_key": PEM})
    assert client.post("/admin/users/mod/approve", headers=admin, json={"roles": ["moderator", "admin"]}).status_code == 400


def test_revoke_kills_sessions():
    admin = login("root", "rootpass1")
    client.post("/register", json={"username": "sam", "password": "password1", "roles": ["sender"], "public_key": PEM})
    client.post("/admin/users/sam/approve", headers=admin)
    sam = login("sam", "password1")
    client.post("/admin/users/sam/revoke", headers=admin)
    assert client.get("/me", headers=sam).status_code == 401


def test_public_key_required_and_checked():
    base = {"username": "kim", "password": "password1", "roles": ["recipient"]}
    assert client.post("/register", json=base).status_code == 422  # missing
    weak = wc.public_pem(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    for pem in ["not a key", weak]:
        assert client.post("/register", json={**base, "public_key": pem}).status_code == 400


def test_audit_log_is_append_only_and_chained():
    with tx() as db:
        assert verify_chain(db)
        rows = db.execute("SELECT action, role FROM audit_log").fetchall()
        assert all("alex" not in tuple(r) for r in rows)  # no identities logged
        try:
            db.execute("DELETE FROM audit_log")
            assert False
        except Exception as e:
            assert "append-only" in str(e)