# Audit Log Samples

Real output from WhisperChain+, produced by running the full system: a FastAPI server, the command-line client and a fresh SQLite database. Nothing here was written by hand. The scenario produces all 22 audit event types in 84 entries.

| File | Contents |
|---|---|
| [audit_log_admin_view.txt](audit_log_admin_view.txt) | What an admin sees from `python client.py -u root audit` (`GET /audit`) |
| [audit_log_raw.json](audit_log_raw.json) | The stored `audit_log` table, including `prev_hash`, `hash` and the Ed25519 `sig` for each entry |
| [demo_transcript.txt](demo_transcript.txt) | Every client command in the scenario and its output, in order |
| [tamper_test.txt](tamper_test.txt) | Six attempts to alter the log, and how each one is caught |
| [generate_samples.py](generate_samples.py) | Script that regenerates every file above |

## Scenario

Users: admin `root`, recipients `ria` and `kai`, moderator `moe`, and senders `sol`, `ana`, `ben`, `eve` and `zed`.

| Entries | What happened | Events |
|---|---|---|
| 1–2 | Admin bootstrapped and logged in | `admin_bootstrapped`, `login` |
| 3–18 | 8 users register, each with a key pair made on their own device | `registration_requested`, `key_registered` |
| 19–28 | Admin approves all 8, gives `zed` the extra recipient role, revokes `eve` | `user_approved`, `roles_changed`, `user_revoked` |
| 29–30 | `sol` uses a wrong password; revoked `eve` tries to log in | `login_failed` ×2 |
| 31–43 | Round 1: three senders get anonymous credentials and each send one message to `ria` | `round_opened`, `credential_issued`, `token_used`, `message_sent` |
| 44 | `sol` tries a second message in the same round | `token_rejected` (409, token already used) |
| 45–52 | Round 2: opening it closes round 1; three more messages | `round_closed`, `round_opened`, `token_used`, `message_sent` |
| 53–60 | `ria` and `kai` read their inboxes (6 messages delivered) | `login`, `message_delivered` |
| 61–66 | `ria` flags 5 messages; the 5th open flag raises an alert | `message_flagged` ×5, `alert_flag_threshold` |
| 67–78 | `moe` reviews the flags, freezes 3 abusive senders (the 3rd freeze raises an alert), and dismisses 2 flags | `flags_reviewed`, `audit_viewed`, `token_frozen`, `alert_freeze_threshold`, `flag_dismissed` |
| 79–82 | Round 3: opening it closes round 2; frozen `sol` tries to send again and is blocked; admin closes round 3 | `round_closed`, `round_opened`, `token_rejected` (403, frozen), `round_closed` |
| 83–84 | Moderator, then admin, read the audit log | `audit_viewed` |

## Analysis

### 1. Accountability without identities
Each entry records only a timestamp, an action and a **role**. No entry contains a username, a pseudonym, a message ID or message content. So the log shows *that* something happened and *which kind of user* did it, but not *who*:

- **Senders cannot be told apart.** Entries 38–43 are three different senders, and the log can't distinguish them. The replay attempt at #44 and the frozen sender's attempt at #81 are logged, but not linked to `sol`.
- **Failed logins don't leak account information.** #29 (wrong password for a real, active user) and #30 (a revoked account) both read `login_failed  unknown`. Someone reading the log can't use it to learn which usernames exist or which accounts were revoked.
- **Moderation stays anonymous.** The three `token_frozen` entries (#71, #73, #75) show that a moderator acted, but not whose token was frozen. The transcript confirms the moderator only ever saw short pseudonym prefixes, never names.
- **Admin actions are traceable to the admin role.** Approvals, role changes, the revocation and round management (#19–28, #31, #45–46, #79–80, #82) are all logged as `admin`. This is the oversight needed for the most powerful role.

### 2. Each security control leaves evidence
| Control | Evidence in the log |
|---|---|
| One message per sender per round | #44 `token_rejected` (409 in the transcript) |
| Freezing abusive senders | #81 `token_rejected` after the freezes at #71–75 (403 "Token frozen by a moderator") |
| Revoked accounts can't log in | #30 `login_failed`, right after `user_revoked` at #28 |
| Every round has a recorded start and end | `round_opened` / `round_closed` pairs: #31/#45, #46/#79, #80/#82 |
| Alert when flags pile up | #66 `alert_flag_threshold` fires exactly on the 5th open flag (#65) |
| Alert on possible moderator abuse | #76 `alert_freeze_threshold` fires on the 3rd freeze within 24 h (#75) |
| Watching the watchers | #69, #83 and #84: every read of the audit log is itself logged, with the reader's role |

Two entries need explaining. #69 is the moderator dashboard fetching the alerts list, which reads the audit log. #70, #72 and #74 are `flags_reviewed` because each `freeze` command fetches the open flags first, to verify the report before freezing.

### 3. Tamper resistance ([tamper_test.txt](tamper_test.txt))

1. **Append-only:** an ordinary `UPDATE` or `DELETE` on `audit_log` is rejected by SQLite triggers (tests 1–2).
2. **Hash chain:** an attacker who drops the triggers and edits an entry (test 3) or deletes one (test 4) breaks the chain, and `verify_chain()` returns `False`.
3. **Signatures:** an attacker who edits an entry and also recomputes every hash afterwards (test 5) still fails, because they can't re-sign the new hashes without `audit_key.pem`.
4. **Head anchor:** deleting the newest entries leaves a shorter chain that still links up and is correctly signed (test 6). It is caught because the newest entry's id and hash are also stored outside the database in `audit_head.json`, and `verify_chain()` requires that entry to still exist.

`GET /audit` checks the chain on every read and reports `chain_valid`, which is the `Hash chain and signatures valid: True` line at the top of the admin view.

### 4. Limitations
Fixed after these samples first exposed them:
- **Deleting the newest entries went undetected.** Now caught by the head anchor (test 6). The head file is written only after a transaction commits, so a rolled-back request can't cause a false alarm. Logs written before this fix are anchored once with `python -m app.audit`.
- **Implicit round closes weren't logged.** Opening a round closed the previous one without a `round_closed` event. It is now logged (#45, #79).

Still open:
- **The signing key and head file are on the server.** They stop an attacker who can only write to the database, but not one who can also change `audit_key.pem` or `audit_head.json`.
- **Timestamps have microsecond precision.** Someone who can watch both the network and the log could match a `message_sent` time to a sender's connection. Rounding timestamps, or batching message submissions, would reduce this.

## Regenerating
```bash
python "Audit Log Samples/generate_samples.py" . /tmp/wc_demo "Audit Log Samples"
```
The script starts a server on port 8765 with its own database, keys and client home in the work directory (`/tmp/wc_demo` here), so your real `whisperchain.db` and keys aren't touched. Timestamps, hashes, signatures and message IDs change on every run, but the event sequence stays the same.
