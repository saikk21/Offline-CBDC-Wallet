# crypto/device/certificate.py

import time
from dataclasses import dataclass
from typing import Optional

from crypto.curve import G, ORDER
from crypto.hash import sha256_int, serialize_point, deserialize_point


@dataclass(frozen=True)
class DeviceCertificate:
    """
    Bank-issued certificate binding a device public key.
    """
    pk_device: object
    cert_id: bytes
    issued_at: int
    expires_at: int
    signature: Optional[bytes] = None


def verify_device_certificate(cert: DeviceCertificate, pk_bank) -> bool:
    """
    Verify a bank-issued device certificate.
    """

    # --------------------------------------------------
    # 1. Expiry check
    # --------------------------------------------------
    now = int(time.time())
    if now > cert.expires_at:
        return False

    if cert.signature is None:
        return False

    # --------------------------------------------------
    # 2. Rebuild signing transcript
    # --------------------------------------------------
    message = (
        serialize_point(cert.pk_device) +
        cert.cert_id +
        cert.issued_at.to_bytes(8, "big") +
        cert.expires_at.to_bytes(8, "big")
    )

    # --------------------------------------------------
    # 3. Parse signature
    #   signature = serialize_point(R) || z
    # --------------------------------------------------
    sig = cert.signature

    R_bytes = sig[:64]          # x || y
    z_bytes = sig[64:96]        # 32-byte scalar

    # Deserialize R using the SAME convention
    x = int.from_bytes(R_bytes[:32], "big")
    y = int.from_bytes(R_bytes[32:], "big")

    from ecdsa.ellipticcurve import Point
    from ecdsa.curves import SECP256k1

    curve = SECP256k1.curve
    R = Point(curve, x, y)

    z = int.from_bytes(z_bytes, "big") % ORDER

    # --------------------------------------------------
    # 4. Recompute challenge
    # --------------------------------------------------
    e = sha256_int(
        serialize_point(R) + message
    ) % ORDER

    # --------------------------------------------------
    # 5. Schnorr verification
    # --------------------------------------------------
    lhs = z * G
    rhs = R + e * pk_bank

    return lhs.to_affine() == rhs.to_affine()
