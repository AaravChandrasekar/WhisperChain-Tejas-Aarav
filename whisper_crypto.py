"""Crypto shared by the client, the server and the tests. Handles key generation, 
blind signatures, envelope assembly, and verification. Most of these functions run client-side."""

import base64
import hashlib
import json
import math
import os
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
RSA_BITS = 3072      # size of new user keys
MIN_RSA_BITS = 2048  # smallest key the server accepts
MAX_TEXT = 500       # characters per compliment
INNER_SIZE = 4096    # every inner message is padded to exactly this many bytes
NONCE_SIZE = 12
TAG_SIZE = 16
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class InvalidMessage(Exception):
    """An envelope or inner message failed to parse, decrypt or verify."""


# ---------- User keys ----------

# A user's encryption key pair that is made on their device at sign-up; only the public half is sent
def generate_keys() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)

# Public key as a PEM string
def public_pem(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()

# Parse PEM and verify it's an RSA key meeting our minimum bit length
def load_public_key(pem: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ValueError("Not a PEM public key") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < MIN_RSA_BITS:
        raise ValueError(f"Public key must be RSA with at least {MIN_RSA_BITS} bits")
    return key

# Stable ID for a public key, so clients can pin it and notice if someone swaps it
def fingerprint(pem: str) -> str:
    der = load_public_key(pem).public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()

# Password-encrypted PEM, so private keys are encrypted at rest on the user's device
def export_private_key(key, password: str) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(password.encode()))

# Raises ValueError on a wrong password
def import_private_key(pem: bytes, password: str):
    return serialization.load_pem_private_key(pem, password=password.encode())


# ---------- Blind signatures ----------

def h(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")

# Hide msg behind a random factor r. Returns (blinded value to send, r to keep secret)
def blind(msg: bytes, n: int, e: int) -> tuple[int, int]:
    while True:
        r = secrets.randbelow(n)
        if r > 1 and math.gcd(r, n) == 1:
            return h(msg) * pow(r, e, n) % n, r

# Strip the blinding factor r from the server's signature
def unblind(blind_sig: int, r: int, n: int) -> int:
    return blind_sig * pow(r, -1, n) % n


def verify(msg: bytes, sig: int, n: int, e: int) -> bool:
    return pow(sig, e, n) == h(msg)


# ---------- Inner message (signed by the sender's pseudonym) ----------

# What the sender signs: canonical JSON, so field boundaries can't be shifted
def _signed_part(round_id: int, to: str, text: str) -> bytes:
    return json.dumps({"v": VERSION, "round": round_id, "to": to, "text": text},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

# Package message data, pseudonym, and signature into the inner dict
def build_inner(text: str, to: str, round_id: int, pseudonym: Ed25519PrivateKey, credential: int) -> dict:
    if not 1 <= len(text) <= MAX_TEXT:
        raise ValueError(f"Message must be 1-{MAX_TEXT} characters")
    return {"v": VERSION, "round": round_id, "to": to, "text": text,
            "pseudonym": pseudonym.public_key().public_bytes_raw().hex(),
            "credential": format(credential, "x"),
            "sig": pseudonym.sign(_signed_part(round_id, to, text)).hex()}

# Verify the message recipient, server-signed blind credential, and sender signature
def verify_inner(inner: dict, recipient: str, n: int, e: int):
    try:
        if inner["v"] != VERSION or inner["to"] != recipient:
            raise InvalidMessage("Message is not addressed to this recipient")
        pub = bytes.fromhex(inner["pseudonym"])
        if not verify(pub, int(inner["credential"], 16), n, e):
            raise InvalidMessage("Pseudonym has no valid server credential")
        Ed25519PublicKey.from_public_bytes(pub).verify(
            bytes.fromhex(inner["sig"]), _signed_part(inner["round"], inner["to"], inner["text"]))
    except InvalidSignature:
        raise InvalidMessage("Bad sender signature") from None
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidMessage("Malformed message") from exc


# ---------- Envelope (what the server stores) ----------

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

# Encrypt for inner["to"]. Returns the JSON string sent to the server as ciphertext
def seal(inner: dict, recipient_key: rsa.RSAPublicKey) -> str:
    body = json.dumps(inner, separators=(",", ":"), ensure_ascii=False).encode()
    if len(body) > INNER_SIZE - 2:
        raise ValueError("Message too long")
    # Fixed-size padding: the ciphertext length says nothing about the message length.
    padded = len(body).to_bytes(2, "big") + body + bytes(INNER_SIZE - 2 - len(body))
    aes_key, nonce = AESGCM.generate_key(256), os.urandom(NONCE_SIZE)
    return json.dumps({"v": VERSION,
                       "ek": _b64(recipient_key.encrypt(aes_key, OAEP)),
                       "nonce": _b64(nonce),
                       # The recipient's name is authenticated, so the envelope can't be moved to another inbox.
                       "ct": _b64(AESGCM(aes_key).encrypt(nonce, padded, inner["to"].encode()))})

# Server-side validation of envelope structure, field types, and expected byte lengths
def parse_envelope(envelope: str) -> dict:
    try:
        env = json.loads(envelope)
        fields = {f: base64.b64decode(env[f], validate=True) for f in ("ek", "nonce", "ct")}
    except (ValueError, TypeError, KeyError) as exc:
        raise InvalidMessage("Malformed envelope") from exc
    if (env.get("v") != VERSION or len(fields["ek"]) < MIN_RSA_BITS // 8
            or len(fields["nonce"]) != NONCE_SIZE or len(fields["ct"]) != INNER_SIZE + TAG_SIZE):
        raise InvalidMessage("Malformed envelope")
    return fields

# Decrypt AES key with recipient RSA private key, then decrypt and depad the payload
def unseal(envelope: str, key: rsa.RSAPrivateKey, recipient: str) -> dict:
    fields = parse_envelope(envelope)
    try:
        aes_key = key.decrypt(fields["ek"], OAEP)
        padded = AESGCM(aes_key).decrypt(fields["nonce"], fields["ct"], recipient.encode())
        return json.loads(padded[2:2 + int.from_bytes(padded[:2], "big")])
    except InvalidTag:
        raise InvalidMessage("Message was altered or is not for this recipient") from None
    except ValueError as exc:  # wrong RSA key, or garbage after decryption
        raise InvalidMessage("Cannot decrypt message") from exc