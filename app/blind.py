"""RSA blind signatures: the server signs a sender's pseudonym key without ever seeing it.

`cryptography` has no blind-signature API, so this is textbook RSA over a SHA-256 hash.
The signing key is used only for credentials, never for anything else.
"""
import hashlib
import math
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def load_server_key():
    """Load the server's RSA signing key, generating it on first run."""
    path = os.environ.get("WC_KEY", "server_key.pem")
    if not os.path.exists(path):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        os.chmod(path, 0o600)
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def h(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


# ---- Client side ----

def blind(msg: bytes, n: int, e: int) -> tuple[int, int]:
    """Hide msg behind a random factor r. Returns (blinded value to send, r to keep secret)."""
    while True:
        r = secrets.randbelow(n)
        if r > 1 and math.gcd(r, n) == 1:
            return h(msg) * pow(r, e, n) % n, r


def unblind(blind_sig: int, r: int, n: int) -> int:
    return blind_sig * pow(r, -1, n) % n


# ---- Server side ----

def sign_blinded(blinded: int, d: int, n: int) -> int:
    return pow(blinded, d, n)


def verify(msg: bytes, sig: int, n: int, e: int) -> bool:
    return pow(sig, e, n) == h(msg)
