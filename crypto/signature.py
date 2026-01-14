# crypto/signature.py

from ecdsa import SigningKey, VerifyingKey, SECP256k1
from crypto.hash import sha256_bytes


def generate_keypair():
    """
    Generate an ECDSA keypair for the bank (or authority).
    Returns (private_key, public_key).
    """
    sk = SigningKey.generate(curve=SECP256k1)
    pk = sk.verifying_key
    return sk, pk


def sign(sk: SigningKey, data: bytes) -> bytes:
    """
    Sign arbitrary data using the bank's private key.
    """
    digest = sha256_bytes(data)
    return sk.sign(digest)


def verify(pk: VerifyingKey, signature: bytes, data: bytes) -> bool:
    """
    Verify a signature using the bank's public key.
    """
    digest = sha256_bytes(data)
    try:
        return pk.verify(signature, digest)
    except Exception:
        return False
