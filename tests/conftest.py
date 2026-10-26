import os
import tempfile

# Point the app at a throwaway DB and signing key before it is imported.
_tmp = tempfile.mkdtemp()
os.environ["WC_DB"] = os.path.join(_tmp, "test.db")
os.environ["WC_KEY"] = os.path.join(_tmp, "server_key.pem")

from app.auth import hash_pw, set_roles  # noqa: E402
from app.db import init_db, tx  # noqa: E402

init_db()
with tx() as db:
    db.execute("INSERT INTO users (username, pw_hash, status) VALUES ('root', ?, 'active')", (hash_pw("rootpass1"),))
    set_roles(db, "root", {"admin"})
