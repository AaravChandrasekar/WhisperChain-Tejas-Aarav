"""Regenerates the audit log samples in this folder.
Run from anywhere: python generate_samples.py <repo> <scratch_workdir> <output_dir>
The server, database, keys and client homes all live in <scratch_workdir>; nothing in the repo is touched.
"""
import contextlib, getpass, io, json, os, re, shutil, sqlite3, subprocess, sys, time

REPO, WORK, OUT = map(os.path.abspath, sys.argv[1:4])
shutil.rmtree(WORK, ignore_errors=True); os.makedirs(WORK); os.makedirs(OUT, exist_ok=True)
PORT = "8765"
env = dict(os.environ, WC_DB=f"{WORK}/demo.db", WC_KEY=f"{WORK}/server_key.pem",
           WC_AUDIT_KEY=f"{WORK}/audit_key.pem", WC_AUDIT_HEAD=f"{WORK}/audit_head.json", WC_HOME=f"{WORK}/clients",
           WC_SERVER=f"http://127.0.0.1:{PORT}", PYTHONPATH=REPO)
os.environ.update(env)
sys.path.insert(0, REPO)

PW = {u: f"{u}-password-123" for u in ["root", "ria", "kai", "moe", "sol", "ana", "ben", "eve", "zed"]}
next_pw = []  # override queue for the next getpass prompts
getpass.getpass = lambda prompt="": next_pw.pop(0) if next_pw else PW[current[0]]
current = [None]

# bootstrap admin
subprocess.run([sys.executable, "-c", f"import getpass; getpass.getpass=lambda p='': {PW['root']!r}; "
                "import sys; sys.argv=['create_admin.py','root']; exec(open('create_admin.py').read())"],
               cwd=REPO, env=env, check=True)
server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", PORT],
                          cwd=REPO, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
import httpx, client  # noqa: E402
for _ in range(50):
    try: httpx.get(f"http://127.0.0.1:{PORT}/rounds/current"); break
    except httpx.HTTPError: time.sleep(0.2)

transcript = []
def run(user, *args, pw=None):
    current[0] = user
    if pw: next_pw.append(pw)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = client.main(["-u", user, *args])
    shown = " ".join(f'"{a}"' if " " in a else a for a in args)
    transcript.append(f"$ python client.py -u {user} {shown}\n{buf.getvalue().rstrip()}" + ("" if rc == 0 else f"\n[exit {rc}]"))
    return buf.getvalue()
def note(text): transcript.append(f"# --- {text} ---")
def api(user, method, path, **kw):
    r = client.call(method, path, user=user, **kw)
    transcript.append(f"# API {method} {path} as {user} -> {json.dumps(r)}")
    return r
def msg_id(out): return re.search(r"[0-9a-f]{32}", out).group(0)

try:
    note("Phase 1: registration and account administration")
    run("root", "login")
    for u, roles in [("ria", "recipient"), ("kai", "recipient"), ("moe", "moderator"),
                     ("sol", "sender"), ("ana", "sender"), ("ben", "sender"),
                     ("eve", "sender"), ("zed", "sender")]:
        next_pw.extend([PW[u], PW[u]])  # choose + repeat
        run(u, "register", "--roles", roles)
    run("root", "pending")
    for u in ["ria", "kai", "moe", "sol", "ana", "ben", "eve", "zed"]:
        run("root", "approve", u)
    api("root", "PUT", "/admin/users/zed/roles", json={"roles": ["sender", "recipient"]})
    api("root", "POST", "/admin/users/eve/revoke")
    note("Failed login attempts: wrong password, then the revoked account")
    run("sol", "login", pw="wrong-password")
    run("eve", "login")

    note("Phase 2: round 1 - anonymous credentials and messages")
    run("root", "open-round")
    SENT = {}
    for u in ["sol", "ana", "ben"]:
        run(u, "login"); run(u, "credential")
    SENT["sol1"] = "You are a worthless idiot"; run("sol", "send", "ria", "You are a worthless idiot")
    SENT["ana1"] = "Nobody wants you here"; run("ana", "send", "ria", "Nobody wants you here")
    SENT["ben1"] = "Your presentation was terrible and so are you"; run("ben", "send", "ria", "Your presentation was terrible and so are you")
    note("Replay: sol tries a second message in the same round")
    run("sol", "send", "kai", "Great job today!")

    note("Phase 3: round 2 (opening it closes round 1)")
    run("root", "open-round")
    SENT["sol2"] = "Still a loser"; run("sol", "send", "ria", "Still a loser")
    SENT["ana2"] = "Thanks for helping me with the lab!"; run("ana", "send", "ria", "Thanks for helping me with the lab!")
    SENT["ben2"] = "Your talk was really inspiring"; run("ben", "send", "kai", "Your talk was really inspiring")

    note("Phase 4: recipients read and flag")
    run("ria", "login"); inbox = run("ria", "inbox")
    by_text = {t: i for i, t in re.findall(r"\[([0-9a-f]{32})\][^\n]*\n    ([^\n]*)", inbox)}
    ids = {k: by_text[t] for k, t in SENT.items() if t in by_text}
    run("kai", "login"); run("kai", "inbox")
    for k in ["sol1", "ana1", "ben1", "sol2", "ana2"]:  # 5th open flag trips alert_flag_threshold
        run("ria", "flag", ids[k])

    note("Phase 5: moderator review")
    run("moe", "login"); run("moe", "dashboard")
    for k in ["sol1", "ana1", "ben1"]:  # 3rd freeze in 24h trips alert_freeze_threshold
        run("moe", "freeze", ids[k])
    run("moe", "dismiss", ids["ana2"])  # the genuine compliment ria flagged by mistake
    run("moe", "dismiss", ids["sol2"])  # sender already frozen

    note("Phase 6: round 3 - frozen sender is blocked")
    run("root", "open-round")
    run("sol", "send", "ria", "You can't stop me")
    api("root", "POST", "/admin/rounds/close")

    note("Phase 7: audit review")
    run("moe", "audit")
    audit_out = run("root", "audit")
finally:
    server.terminate(); server.wait()

with open(f"{OUT}/demo_transcript.txt", "w") as f:
    f.write("\n\n".join(transcript) + "\n")
with open(f"{OUT}/audit_log_admin_view.txt", "w") as f:
    f.write("$ python client.py -u root audit\n" + audit_out)

# Raw table (what the server stores) + independent verification
from app import audit as A  # uses WC_AUDIT_KEY from env
db = sqlite3.connect(env["WC_DB"]); db.row_factory = sqlite3.Row
rows = [dict(r) for r in db.execute("SELECT * FROM audit_log ORDER BY id")]
with open(f"{OUT}/audit_log_raw.json", "w") as f:
    json.dump(rows, f, indent=2)

# Tamper tests
def conn(path):
    c = sqlite3.connect(path); c.row_factory = sqlite3.Row; return c
lines = ["Tamper-resistance checks run against the database produced by this demo.", ""]
lines.append(f"0. verify_chain() on the untouched log ({len(rows)} entries) -> {A.verify_chain(db)}")
for n, sql in [(1, "UPDATE audit_log SET action = 'login' WHERE action = 'login_failed'"),
               (2, "DELETE FROM audit_log WHERE action = 'token_frozen'")]:
    try:
        db.execute(sql); db.commit(); lines.append(f"{n}. {sql}\n   -> SUCCEEDED (unexpected)")
    except sqlite3.DatabaseError as e:
        lines.append(f"{n}. {sql}\n   -> rejected by trigger: {e}")
db.close()

def attacker_copy(name):
    """An attacker with raw file access: copy the DB and drop the append-only triggers."""
    path = f"{WORK}/{name}.db"; shutil.copy(env["WC_DB"], path)
    c = conn(path); c.execute("DROP TRIGGER audit_no_update"); c.execute("DROP TRIGGER audit_no_delete"); return c

c = attacker_copy("t3")
c.execute("UPDATE audit_log SET action = 'login' WHERE action = 'login_failed'"); c.commit()
lines.append("3. Attacker drops the triggers and rewrites 'login_failed' -> 'login' (hashes untouched)\n"
             f"   -> verify_chain() = {A.verify_chain(c)}  (stored hash no longer matches the entry)")

c = attacker_copy("t4")
victim = c.execute("SELECT id FROM audit_log WHERE action = 'token_frozen' LIMIT 1").fetchone()[0]
c.execute("DELETE FROM audit_log WHERE id = ?", (victim,)); c.commit()
lines.append(f"4. Attacker deletes entry #{victim} (token_frozen) to hide a moderator action\n"
             f"   -> verify_chain() = {A.verify_chain(c)}  (next entry's prev_hash points at a missing entry)")

c = attacker_copy("t5")
c.execute("UPDATE audit_log SET action = 'login' WHERE action = 'login_failed'")
prev = "0" * 64
for r in c.execute("SELECT * FROM audit_log ORDER BY id").fetchall():  # recompute every hash, but no key to re-sign
    h = A._hash(prev, r["ts"], r["action"], r["role"])
    c.execute("UPDATE audit_log SET prev_hash = ?, hash = ? WHERE id = ?", (prev, h, r["id"])); prev = h
c.commit()
lines.append("5. Attacker rewrites the entry AND recomputes the whole hash chain, but lacks audit_key.pem\n"
             f"   -> verify_chain() = {A.verify_chain(c)}  (Ed25519 signatures no longer match the new hashes)")
c = attacker_copy("t6")
c.execute("DELETE FROM audit_log WHERE id > (SELECT MAX(id) - 3 FROM audit_log)"); c.commit()
lines.append("6. Attacker deletes the 3 newest entries; what remains is still a perfectly linked, signed chain\n"
             f"   -> verify_chain() = {A.verify_chain(c)}  (head file outside the DB says entry #{len(rows)} must exist)")
with open(f"{OUT}/tamper_test.txt", "w") as f:
    f.write("\n".join(lines) + "\n")
print("\n".join(lines))
