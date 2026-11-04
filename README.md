# WhisperChain+

Anonymous compliment platform with RBAC, end-to-end encryption and audit logging (FastAPI + SQLite).

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python create_admin.py <admin_username>   # bootstrap the first admin
uvicorn app.main:app --reload             # API docs at http://127.0.0.1:8000/docs
python -m pytest -q                       # run tests
```

## Demo with the command-line client
Run the server in one terminal, then in another (`-u` picks the user; each command asks for that user's password):
```bash
python client.py -u ria register --roles recipient    # makes ria's key pair on this machine
python client.py -u sol register --roles sender
python client.py -u root login
python client.py -u root pending
python client.py -u root approve ria
python client.py -u root approve sol
python client.py -u root open-round
python client.py -u sol login
python client.py -u sol credential                    # once: anonymous sender credential
python client.py -u sol send ria "Hello"
python client.py -u ria login
python client.py -u ria inbox                         # decrypted and verified locally
python client.py -u root audit
```
Keys and sessions are stored in `~/.whisperchain/<user>/` (override with `WC_HOME`), readable only by you, with private keys encrypted under the account password. `WC_SERVER` points the client at another server.

## Registration flow
1. `POST /register` — user requests an account with roles (`sender`, `recipient`, `moderator`) and their RSA public key (2048+ bits, made on their device). The account stays `pending`.
2. `GET /admin/pending` → `POST /admin/users/{u}/approve` — an admin activates it, and can override the roles.
3. `POST /login` → bearer token → `GET /me`.

Admins can also `PUT /admin/users/{u}/roles` and `POST /admin/users/{u}/revoke`.

**Rules enforced:** admin accounts can't be self-requested; no user can be both admin and moderator; only active users can log in; passwords are hashed with scrypt.

## Anonymous tokens (one per Sender per round)
1. Admin opens a round: `POST /admin/rounds/open` (closes the previous one). `GET /rounds/current` shows it.
2. Once, a Sender makes an Ed25519 pseudonym key, **blinds** it with the server's RSA key (`GET /tokens/public-key`), and sends it to `POST /tokens/credential`. The server signs it without seeing it and only records *that* this user got a credential.
3. Each round, the Sender signs `round:<id>` with the pseudonym key. Credential + round signature = token. `redeem_token()` checks both signatures and accepts each pseudonym once per round, with no login, so the token can't be tied to a user.

## End-to-end encryption
All crypto is in `whisper_crypto.py`, shared by the client, server and tests.
1. The sender fetches `GET /directory` (every active recipient's public key; no login, and always the whole list, so the lookup doesn't reveal who they're writing to). The client pins each key's fingerprint and refuses to send if it later changes.
2. The compliment, the sender's pseudonym, credential and an Ed25519 signature are padded to a fixed 4 KB, encrypted with a fresh AES-256-GCM key, and that key is wrapped with the recipient's key (RSA-OAEP). The recipient's name is authenticated, so an envelope can't be moved to another inbox.
3. The server checks only the envelope's shape, stores it with no sender and no timestamp, and the recipient decrypts it locally. The client shows a message only if the signature and credential verify, so a message planted by the server is hidden.

## Role enforcement
| Endpoint | Who | Notes |
|---|---|---|
| `GET /directory` | Anyone | Public keys of active recipients |
| `POST /messages` | Sender (via token) | No login, so the server can't tell which Sender. One per round. |
| `GET /inbox` | Recipient | Own messages only, still encrypted |
| `POST /messages/{id}/flag` | Recipient | Own messages only |
| `GET /moderation/flagged` | Moderator | Flagged messages only |
| `GET /audit` | Moderator, Admin (read-only) | Role-level events + hash-chain check |

Admins have no endpoint that returns messages, and no sender info is stored anywhere to leak.

## Audit logging
Every key action appends an entry with a timestamp, action and role — never a username. Each entry includes the hash of the previous one, so editing any past entry breaks the chain (`GET /audit` reports `chain_valid`), and SQLite triggers reject any `UPDATE` or `DELETE` on the log.

Events: `admin_bootstrapped`, `registration_requested`, `key_registered`, `user_approved`, `roles_changed`, `user_revoked`, `round_opened`, `round_closed`, `credential_issued`, `token_used`, `token_rejected`, `message_sent`, `message_delivered`, `message_flagged`.