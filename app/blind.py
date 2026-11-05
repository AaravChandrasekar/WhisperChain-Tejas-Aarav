"""Server side of the RSA blind signatures. The client side and verify() live in whisper_crypto."""
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from whisper_crypto import blind, h, unblind, verify  # noqa: F401  (re-exported for app.tokens and the tests)


def load_key(path: str, generate):
    """Load a PEM private key, making one with generate() and saving it on first run."""
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        os.chmod(path, 0o600)
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_server_key():
    """The server's RSA blind-signing key."""
    return load_key(os.environ.get("WC_KEY", "server_key.pem"),
                    lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048))


def sign_blinded(blinded: int, d: int, n: int) -> int:
    return pow(blinded, d, n)