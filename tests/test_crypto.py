"""Unit tests for whisper_crypto. No server involved."""
import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import whisper_crypto as wc

SERVER = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # stands in for the token service
N, E = SERVER.public_key().public_numbers().n, SERVER.public_key().public_numbers().e
D = SERVER.private_numbers().d
RIA, OMAR = wc.generate_keys(), wc.generate_keys()


def credential(pseudonym):
    """Run the blind-signature flow against SERVER; returns the unblinded credential."""
    blinded, r = wc.blind(pseudonym.public_key().public_bytes_raw(), N, E)
    return wc.unblind(pow(blinded, D, N), r, N)


PSEUDO = Ed25519PrivateKey.generate()
CRED = credential(PSEUDO)


def message(text="you explained recursion so well!", to="ria", pseudonym=PSEUDO, cred=CRED):
    return wc.build_inner(text, to, 1, pseudonym, cred)


def test_round_trip_and_verify():
    inner = message()
    got = wc.unseal(wc.seal(inner, RIA.public_key()), RIA, "ria")
    assert got == inner
    wc.verify_inner(got, "ria", N, E)


def test_envelope_reveals_nothing():
    env = wc.seal(message(), RIA.public_key())
    assert "recursion" not in env and message()["pseudonym"] not in env and "ria" not in env


def test_other_recipient_cannot_decrypt():
    with pytest.raises(wc.InvalidMessage):
        wc.unseal(wc.seal(message(), RIA.public_key()), OMAR, "omar")


def test_envelope_bound_to_recipient_name():
    with pytest.raises(wc.InvalidMessage):
        wc.unseal(wc.seal(message(), RIA.public_key()), RIA, "omar")


def test_tampered_ciphertext_rejected():
    env = json.loads(wc.seal(message(), RIA.public_key()))
    ct = bytearray(base64.b64decode(env["ct"]))
    ct[100] ^= 1
    env["ct"] = base64.b64encode(ct).decode()
    with pytest.raises(wc.InvalidMessage):
        wc.unseal(json.dumps(env), RIA, "ria")


def test_forged_or_misaddressed_messages_rejected():
    edited = message()
    edited["text"] = "something nasty"  # e.g. a recipient framing the sender
    rogue = Ed25519PrivateKey.generate()
    for bad, to in [(edited, "ria"),
                    (message(), "omar"),                             # not addressed to this recipient
                    (message(pseudonym=rogue), "ria"),               # someone else's credential
                    (message(pseudonym=rogue, cred=12345), "ria"),   # made-up credential
                    ({"v": 1, "to": "ria"}, "ria")]:                 # missing fields
        with pytest.raises(wc.InvalidMessage):
            wc.verify_inner(bad, to, N, E)


def test_padding_hides_length():
    short = wc.seal(message("hi"), RIA.public_key())
    longest = wc.seal(message("x" * wc.MAX_TEXT, to="a-much-longer-username"), RIA.public_key())
    assert len(short) == len(longest)


def test_size_limits():
    for text in ["", "x" * (wc.MAX_TEXT + 1)]:
        with pytest.raises(ValueError):
            message(text)
    worst = wc.seal(message("😀" * wc.MAX_TEXT), RIA.public_key())  # 4-byte characters still fit
    assert len(worst) < 8192  # the server's planned ciphertext limit


def test_server_shape_check():
    good = wc.seal(message(), RIA.public_key())
    assert set(wc.parse_envelope(good)) == {"ek", "nonce", "ct"}
    short_ct = {**json.loads(good), "ct": base64.b64encode(b"x" * 32).decode()}
    for bad in ["not json", "[]", '"str"', '{"v": 1}', json.dumps(short_ct),
                json.dumps({**json.loads(good), "nonce": "!!!"}), json.dumps({**json.loads(good), "v": 2})]:
        with pytest.raises(wc.InvalidMessage):
            wc.parse_envelope(bad)


def test_public_key_validation():
    pem = wc.public_pem(RIA)
    assert isinstance(wc.load_public_key(pem), rsa.RSAPublicKey)
    too_small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    not_rsa = ec.generate_private_key(ec.SECP256R1())
    for bad in ["garbage", wc.public_pem(too_small), wc.public_pem(not_rsa)]:
        with pytest.raises(ValueError):
            wc.load_public_key(bad)
    assert wc.fingerprint(pem) == wc.fingerprint(pem) != wc.fingerprint(wc.public_pem(OMAR))


def test_private_key_export_is_password_protected():
    pem = wc.export_private_key(RIA, "hunter22")
    assert b"ENCRYPTED" in pem
    assert wc.import_private_key(pem, "hunter22").private_numbers() == RIA.private_numbers()
    with pytest.raises(ValueError):
        wc.import_private_key(pem, "wrong-password")