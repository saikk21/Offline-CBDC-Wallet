# transport/proof_serializer.py

from crypto.hash import serialize_point
from crypto.zkp.spend import SpendProof
from crypto.zkp.value import ValueProof
from crypto.zkp.recursive import RecursiveInvariantProof

from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1


# ==========================================================
# Helpers
# ==========================================================

def _point_from_bytes(data: bytes) -> Point:
    """
    Deserialize EC point from 64-byte (x || y) format.
    """
    if len(data) != 64:
        raise ValueError("Invalid EC point encoding")

    x = int.from_bytes(data[:32], "big")
    y = int.from_bytes(data[32:], "big")

    curve = SECP256k1.curve
    return Point(curve, x, y)


# ==========================================================
# SpendProof Serialization
# Format:
# A_commit (64)
# A_serial (64)
# z_v (32)
# z_r (32)
# z_s (32)
# Total: 224 bytes
# ==========================================================

def serialize_spend_proof(proof: SpendProof) -> bytes:
    return (
        serialize_point(proof.A_commit) +
        serialize_point(proof.A_serial) +
        proof.z_v.to_bytes(32, "big") +
        proof.z_r.to_bytes(32, "big") +
        proof.z_s.to_bytes(32, "big")
    )


def deserialize_spend_proof(data: bytes) -> SpendProof:
    if len(data) != 224:
        raise ValueError("Invalid SpendProof length")

    A_commit = _point_from_bytes(data[0:64])
    A_serial = _point_from_bytes(data[64:128])

    z_v = int.from_bytes(data[128:160], "big")
    z_r = int.from_bytes(data[160:192], "big")
    z_s = int.from_bytes(data[192:224], "big")

    return SpendProof(A_commit, A_serial, z_v, z_r, z_s)


# ==========================================================
# ValueProof Serialization
# Format:
# A (64)
# z_v (32)
# z_r (32)
# Total: 128 bytes
# ==========================================================

def serialize_value_proof(proof: ValueProof) -> bytes:
    return (
        serialize_point(proof.A) +
        proof.z_v.to_bytes(32, "big") +
        proof.z_r.to_bytes(32, "big")
    )


def deserialize_value_proof(data: bytes) -> ValueProof:
    if len(data) != 128:
        raise ValueError("Invalid ValueProof length")

    A = _point_from_bytes(data[0:64])
    z_v = int.from_bytes(data[64:96], "big")
    z_r = int.from_bytes(data[96:128], "big")

    return ValueProof(A, z_v, z_r)


# ==========================================================
# RecursiveInvariantProof Serialization
# Format:
# A (64)
# z (32)
# Total: 96 bytes
# ==========================================================

def serialize_recursive_proof(proof: RecursiveInvariantProof) -> bytes:
    return (
        serialize_point(proof.A) +
        proof.z.to_bytes(32, "big")
    )


def deserialize_recursive_proof(data: bytes) -> RecursiveInvariantProof:
    if len(data) != 96:
        raise ValueError("Invalid RecursiveInvariantProof length")

    A = _point_from_bytes(data[0:64])
    z = int.from_bytes(data[64:96], "big")

    return RecursiveInvariantProof(A, z)
