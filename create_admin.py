"""Bootstrap the first admin: python create_admin.py <username>"""
import sys
from getpass import getpass

from app.auth import hash_pw, set_roles
from app.db import init_db, tx

username = sys.argv[1]
password = getpass("Admin password (min 8 chars): ")
assert len(password) >= 8, "Password too short"

init_db()
with tx() as db:
    db.execute("INSERT INTO users (username, pw_hash, status) VALUES (?, ?, 'active')", (username, hash_pw(password)))
    set_roles(db, username, {"admin"})
print(f"Admin '{username}' created.")
