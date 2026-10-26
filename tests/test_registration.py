from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def login(username, password):
    r = client.post("/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {r.json()['token']}"} if r.status_code == 200 else r


def test_registration_flow():
    assert client.post("/register", json={"username": "alex", "password": "password1", "roles": ["sender", "recipient"]}).status_code == 201
    assert client.post("/register", json={"username": "alex", "password": "password1", "roles": ["sender"]}).status_code == 409
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
        assert client.post("/register", json={"username": "eve", "password": "password1", "roles": roles}).status_code in (400, 403)
    admin = login("root", "rootpass1")
    client.post("/register", json={"username": "mod", "password": "password1", "roles": ["moderator"]})
    assert client.post("/admin/users/mod/approve", headers=admin, json={"roles": ["moderator", "admin"]}).status_code == 400


def test_revoke_kills_sessions():
    admin = login("root", "rootpass1")
    client.post("/register", json={"username": "sam", "password": "password1", "roles": ["sender"]})
    client.post("/admin/users/sam/approve", headers=admin)
    sam = login("sam", "password1")
    client.post("/admin/users/sam/revoke", headers=admin)
    assert client.get("/me", headers=sam).status_code == 401

