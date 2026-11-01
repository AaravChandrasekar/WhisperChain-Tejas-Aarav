"""Server side of the RSA blind signatures. The client side and verify() live in whisper_crypto."""
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from whisper_crypto import blind, h, unblind, verify  # noqa: F401  (re-exported for app.tokens and the tests)


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


def sign_blinded(blinded: int, d: int, n: int) -> int:
    return pow(blinded, d, n)