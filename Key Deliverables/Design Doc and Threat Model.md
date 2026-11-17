# WhisperChain+ Milestone 1: System Design

## 1. System Overview

WhisperChain+ is essentially a platform where people in a community can send each other anonymous, encrypted compliments, while still having enough security to stop abuse. The tricky part is that the system has to keep the sender secret and also hold people accountable if someone sends something harmful. We do this through blind-signed credentials so the server cannot connect a message to a person. Then encryption on the user’s own device is used so the server and admin see scrambled text and not any plaintext they can easily read. Finally, as detailed in a different document, a role-based access control (through a RBAC) and a signed audit log keep everyone in check and allow for proper analysis.

## 2. Roles

**Sender:** sends one anonymous encrypted message per round.

**Recipient:** receives messages in their own mailbox, decrypts them on their own device, and can flag abusive ones.

**Moderator:** reviews flagged messages, freeze abusive/malicious anonymous accounts, and can read audit logs.

**Admin:** registers users, assigns roles, manages the public key directory, but cannot see message content or who sent anything, so no PII is left out in the open.

A person can be both a Sender and Recipient allowing everybody to enjoy full functionality, but nobody can be both Admin and Moderator, so power is not concentrated among certain users.

## 3. How a Message Works

Imagine a student, Alex, who wants to thank a TA.

**Sign-up:** the admin approves Alex’s account and role. Alex’s browser creates an RSA key pair for encryption and a separate pseudonym key for signing. The public key goes in a directory, and private keys never leave Alex’s device.

**Credential:** once, Alex asks the token service for a credential. Alex “blinds” the pseudonym key first, kind of like signing through carbon paper, so the service certifies it without being able to read it. This allows the service to know that Alex has a credential but cannot tie it back to them exactly.

**Token:** each round of messages, Alex’s device makes a one-time value from the pseudonym key and the round number. The server accepts it only once, which gives one message per round.

**Sending:** the message is encrypted with a fresh AES key, and that key is locked with the TA’s public RSA key. The server only stores scrambled text and a random mailbox ID, with no sender field.

**Receiving:** the TA downloads the message and decrypts it on their own device and that is how they receive a complement or a question.

**Flagging:** if the message is abusive, the TA flags it, and their device re-encrypts it for the moderator. The moderator checks the sender’s signature to confirm it is a real account that exists on the system, then either dismisses the flag (if it is a false report), or freezes the associated sender without knowing who they are. Frozen pseudonyms from this point onwards are rejected when they try to send a new message, and alerts go out if too many messages are flagged.

## 4. Access Control Plan

We are using RBAC as the base, meaning each role has a list of allowed actions and anything not on the list is denied. We add a few extra rules on top like you can only touch your own mailbox, and Admins and Moderators must be different people. Sending also needs a valid unused token, not just the Sender role. The full role-permission table is in the attached Excel file.

## 5. Tech Stack

Python with FastAPI, SQLite, the cryptography library, the Web Crypto API in the browser, and TLS for transport. This is up for discussion as we add new features.

---

# WhisperChain+ Threat Model (Draft)

We are protecting message privacy, sender anonymity, an audit log that attempts to keep full integrity, and fair moderation. We assume TLS is secure and that users keep their own private keys safe, and are not treating those as vulnerabilities.

**1. Compromised admin:** let’s say an attacker steals the admin’s login. They still cannot read messages because the admin never has decryption keys, and they cannot tell who sent what because the credentials were blind-signed, so even with breaches anonymity is kept.

**2. Shared or stolen tokens:** the round token is tied to the user’s pseudonym key and the server accepts it once per round, so sharing it gives no extra messages and replaying it is rejected. The leftover risk is that a user could give away their one slot, or someone with their stolen device could use it until a moderator freezes it.

**3. Nonrepudiation:** this just means nobody can later deny what they did. The sender signs the message inside the encrypted message, so a recipient cannot make up an abusive message and the sender cannot deny it came from their pseudonym. Moderator and admin actions are signed with their own keys, and the audit log is signed and chained together so integrity within the system is protected, and when it is breached there is information about when and by who. The complication here is that with pseudonyms, we never know who the people behind the actions and their username are, but that is a system design not a flaw.

**4. Spam and fake accounts:** to prevent a spam of messages, each pseudonym gets only one token per round, and messages have a size cap and rate limits on how many can be sent. On the fake account side, the admin approves registrations so only verified users get through to the system, but a fake admin with a compromised account can throw a wrench in this.

**6. Abuse of moderation:** a problem that exists on other platforms, isn’t as big a deal here, as recipients flag their own messages, and moderators only see flagged messages, not being able to decide for themselves what is malicious or dangerous content. Additionally to keep moderators in check, every action they take is logged and signed, and unusual freeze counts trigger alerts to the admin.

**7. Server or database breach:** to prevent storage security concerns, only scrambled text is stored, with the private keys to decrypt them never existing on the server. If a user leaks their private key somehow, this could cause potential problems, but as determined above we are not treating this as a system vulnerability.
