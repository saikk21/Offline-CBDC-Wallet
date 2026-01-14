# crypto/zkp/mint.py

from crypto.curve import G, H, ORDER, random_scalar
from crypto.hash import sha256_int


class MintingProof:
    def __init__(self, A, z1, z2):
        self.A = A
        self.z1 = z1
        self.z2 = z2


def _compute_challenge(A, C):
    return sha256_int(
        A.x().to_bytes(32, "big") +
        A.y().to_bytes(32, "big") +
        C.x().to_bytes(32, "big") +
        C.y().to_bytes(32, "big")
    ) % ORDER


def prove_opening(v: int, r: int, C):
    a = random_scalar()
    b = random_scalar()

    A = a * G + b * H
    e = _compute_challenge(A, C)

    z1 = (a + e * v) % ORDER
    z2 = (b + e * r) % ORDER

    return MintingProof(A, z1, z2)


def verify_opening(C, proof: MintingProof) -> bool:
    e = _compute_challenge(proof.A, C)

    left = proof.z1 * G + proof.z2 * H
    right = proof.A + e * C

    return left == right


# ================= Denomination Enforcement =================

ALLOWED_DENOMINATIONS = [1, 2, 5, 10, 20, 50, 100]


class DenominationProof:
    def __init__(self, proofs):
        self.proofs = proofs


def prove_minting(v: int, r: int, C):
    if v not in ALLOWED_DENOMINATIONS:
        raise ValueError("Invalid denomination")

    proofs = {}

    for d in ALLOWED_DENOMINATIONS:
        if d == v:
            proofs[d] = prove_opening(v, r, C)
        else:
            a = random_scalar()
            b = random_scalar()
            A = a * G + b * H
            z1 = random_scalar()
            z2 = random_scalar()
            proofs[d] = MintingProof(A, z1, z2)

    return DenominationProof(proofs)


def verify_minting(C, denom_proof: DenominationProof) -> bool:
    for proof in denom_proof.proofs.values():
        if verify_opening(C, proof):
            return True
    return False
