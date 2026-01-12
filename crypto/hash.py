# crypto/hash.py

from hashlib import sha256


def sha256_bytes(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of input bytes.
    Returns raw 32-byte digest.
    """
    return sha256(data).digest()


def serialize_int(x: int) -> bytes:
    """
    Deterministically serialize an integer to bytes.
    """
    if x < 0:
        raise ValueError("Cannot serialize negative integers")

    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, byteorder="big")


def serialize_point(P) -> bytes:
    """
    Deterministically serialize an elliptic curve point.
    """
    x_bytes = serialize_int(P.x())
    y_bytes = serialize_int(P.y())
    return x_bytes + y_bytes
