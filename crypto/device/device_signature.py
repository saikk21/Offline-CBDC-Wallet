# crypto/device/device_signature.py

import secrets
from crypto.curve import G, ORDER
from crypto.hash import sha256_int, serialize_point


def sign_spend_transcript(
    sk_device: int,
    transcript_hash: bytes
) -> bytes:
    """
    Sign a spend authorization transcript using the device private key.

    transcript_hash: 32-byte hash output from build_spend_transcript()
    Returns:
        device_signature = serialize_point(R) || z
    """

    if len(transcript_hash) != 32:
        raise ValueError("Transcript hash must be 32 bytes")

    # --------------------------------------------------
    # 1. Schnorr nonce
    # --------------------------------------------------
    k = secrets.randbelow(ORDER)
    if k == 0:
        raise ValueError("Invalid Schnorr nonce")

    R = k * G

    # --------------------------------------------------
    # 2. Fiat–Shamir challenge
    # --------------------------------------------------
    e = sha256_int(
        serialize_point(R) + transcript_hash
    ) % ORDER

    # --------------------------------------------------
    # 3. Response
    # --------------------------------------------------
    z = (k + e * sk_device) % ORDER

    # --------------------------------------------------
    # 4. Signature encoding
    #   signature = R || z
    # --------------------------------------------------
    signature = (
        serialize_point(R) +
        z.to_bytes(32, "big")
    )

    return signature
