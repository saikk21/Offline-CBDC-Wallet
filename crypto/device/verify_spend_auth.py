# crypto/device/verify_spend_auth.py

from crypto.curve import G, ORDER
from crypto.hash import sha256_int, serialize_point
from crypto.device.certificate import verify_device_certificate


def verify_spend_authorization(
    transcript_hash: bytes,
    device_signature: bytes,
    device_certificate,
    pk_bank
) -> bool:
    """
    Verify that a registered device authorized an offline spend.

    Checks:
    1. Device certificate validity
    2. Device signature correctness
    """

    # --------------------------------------------------
    # 1. Verify device certificate (bank trust)
    # --------------------------------------------------
    if not verify_device_certificate(device_certificate, pk_bank):
        return False

    pk_device = device_certificate.pk_device

    # --------------------------------------------------
    # 2. Parse device signature
    #   signature = serialize_point(R) || z
    # --------------------------------------------------
    if len(device_signature) != 96:
        return False

    R_bytes = device_signature[:64]
    z_bytes = device_signature[64:]

    # Deserialize R using project convention (x || y)
    x = int.from_bytes(R_bytes[:32], "big")
    y = int.from_bytes(R_bytes[32:], "big")

    from ecdsa.ellipticcurve import Point
    from ecdsa.curves import SECP256k1

    curve = SECP256k1.curve
    R = Point(curve, x, y)

    z = int.from_bytes(z_bytes, "big") % ORDER

    # --------------------------------------------------
    # 3. Recompute Fiat–Shamir challenge
    # --------------------------------------------------
    e = sha256_int(
        serialize_point(R) + transcript_hash
    ) % ORDER

    # --------------------------------------------------
    # 4. Verify Schnorr equation
    #   z·G == R + e·pk_device
    # --------------------------------------------------
    lhs = z * G
    rhs = R + e * pk_device

    return lhs.to_affine() == rhs.to_affine()
