# This file defines the mathematical universe in which all cryptography in the project happens.

from ecdsa import SECP256k1
from hashlib import sha256
import secrets

# curve parameters
CURVE = SECP256k1
G = CURVE.generator
ORDER = CURVE.order

def hash_to_scalar(tag: str) -> int: # helps in securly creating H for the pedresen commitment.
    """
    Deterministically map a string to a scalar mod curve order.
    Used to derive H safely.
    """
    digest = sha256(tag.encode()).digest()
    return int.from_bytes(digest, "big") % ORDER

def derive_H() -> object: # used in deriving H
    """
    Derive a second generator H such that nobody knows
    the discrete log between G and H.
    """
    h_scalar = hash_to_scalar("offline-cbdc-pedersen-H")
    return h_scalar * G

H = derive_H()

def random_scalar(): # the random bilding (r) factor used for the creation of C
    """
    Generate cryptographically secure random scalar mod curve order.
    """
    return secrets.randbelow(ORDER)
