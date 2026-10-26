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
