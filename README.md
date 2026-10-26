# WhisperChain+

Anonymous compliment platform with role-based access control (FastAPI + SQLite).

## Setup
```bash
pip install -r requirements.txt
python create_admin.py <admin_username>   # bootstrap the first admin
uvicorn app.main:app --reload             # API docs at http://127.0.0.1:8000/docs
pytest -q                                 # run tests
```

## Registration flow
1. `POST /register` — user requests an account with roles (`sender`, `recipient`, `moderator`). The account stays `pending`.
2. `GET /admin/pending` → `POST /admin/users/{u}/approve` — an admin activates it, and can override the roles.
3. `POST /login` → bearer token → `GET /me`.

Admins can also `PUT /admin/users/{u}/roles` and `POST /admin/users/{u}/revoke`.

**Rules enforced:** admin accounts can't be self-requested; no user can be both admin and moderator; only active users can log in; passwords are hashed with scrypt.

## Anonymous tokens (one per Sender per round)
1. Admin opens a round: `POST /admin/rounds/open` (closes the previous one). `GET /rounds/current` shows it.
2. Once, a Sender makes an Ed25519 pseudonym key, **blinds** it with the server's RSA key (`GET /tokens/public-key`), and sends it to `POST /tokens/credential`. The server signs it without seeing it and only records *that* this user got a credential.
3. Each round, the Sender signs `round:<id>` with the pseudonym key. Credential + round signature = token. `redeem_token()` checks both signatures and accepts each pseudonym once per round, with no login, so the token can't be tied to a user.

## Role enforcement
| Endpoint | Who | Notes |
|---|---|---|
| `POST /messages` | Sender (via token) | No login, so the server can't tell which Sender. One per round. |
| `GET /inbox` | Recipient | Own messages only |
| `POST /messages/{id}/flag` | Recipient | Own messages only |
| `GET /moderation/flagged` | Moderator | Flagged messages only |

Admins have no endpoint that returns messages, and no sender info is stored anywhere to leak.
