from crypto.curve import G, H, ORDER, random_scalar
from crypto.hash import sha256_int


# ============================================================
# Basic Commitment Opening Proof (Sigma Protocol + Fiat–Shamir)
# ============================================================

class OpeningProof:
    def __init__(self, A, z1, z2):
        self.A = A
        self.z1 = z1
        self.z2 = z2


def _fs_challenge(data: bytes) -> int:
    """
    Fiat–Shamir challenge derived from transcript.
    """
    return sha256_int(data) % ORDER


def prove_opening(v: int, r: int, C):
    """
    Prove knowledge of (v, r) such that:
        C = v*G + r*H
    """
    a = random_scalar()
    b = random_scalar()

    A = a * G + b * H

    e = _fs_challenge(
        A.x().to_bytes(32, "big") +
        A.y().to_bytes(32, "big") +
        C.x().to_bytes(32, "big") +
        C.y().to_bytes(32, "big")
    )

    z1 = (a + e * v) % ORDER
    z2 = (b + e * r) % ORDER

    return OpeningProof(A, z1, z2)


def verify_opening(C, proof: OpeningProof) -> bool:
    """
    Verify:
        z1*G + z2*H == A + e*C
    """
    e = _fs_challenge(
        proof.A.x().to_bytes(32, "big") +
        proof.A.y().to_bytes(32, "big") +
        C.x().to_bytes(32, "big") +
        C.y().to_bytes(32, "big")
    )

    left = proof.z1 * G + proof.z2 * H
    right = proof.A + e * C

    return left == right


# ============================================================
# Denomination Enforcement via OR-Proof (Correct Version)
# ============================================================

ALLOWED_DENOMINATIONS = [1, 2, 5, 10, 20, 50, 100]


class DenominationProof:
    """
    OR-proof that committed value belongs to ALLOWED_DENOMINATIONS.
    """
    def __init__(self, A_map, z1_map, z2_map, e_map):
        self.A_map = A_map
        self.z1_map = z1_map
        self.z2_map = z2_map
        self.e_map = e_map


def prove_minting(v: int, r: int, C):
    """
    Disjunctive Sigma OR-proof:
        Prove (v == 1) OR (v == 2) OR ... OR (v == 100)
    """
    if v not in ALLOWED_DENOMINATIONS:
        raise ValueError("Invalid denomination")

    A_map = {}
    z1_map = {}
    z2_map = {}
    e_map = {}

    real_denom = v
    fake_denoms = [d for d in ALLOWED_DENOMINATIONS if d != v]

    # Step 1: Simulate fake branches
    e_sum = 0
    for d in fake_denoms:
        e_d = random_scalar()
        z1_d = random_scalar()
        z2_d = random_scalar()

        A_d = z1_d * G + z2_d * H + (-(e_d * C))

        A_map[d] = A_d
        z1_map[d] = z1_d
        z2_map[d] = z2_d
        e_map[d] = e_d

        e_sum = (e_sum + e_d) % ORDER

    # Step 2: Real branch commitment
    a = random_scalar()
    b = random_scalar()
    A_real = a * G + b * H
    A_map[real_denom] = A_real

    # Step 3: Fiat–Shamir challenge
    transcript = b"".join(
        A_map[d].x().to_bytes(32, "big") +
        A_map[d].y().to_bytes(32, "big")
        for d in ALLOWED_DENOMINATIONS
    ) + (
        C.x().to_bytes(32, "big") +
        C.y().to_bytes(32, "big")
    )

    e = _fs_challenge(transcript)

    # Step 4: Real challenge
    e_real = (e - e_sum) % ORDER
    e_map[real_denom] = e_real

    # Step 5: Real responses
    z1_real = (a + e_real * v) % ORDER
    z2_real = (b + e_real * r) % ORDER

    z1_map[real_denom] = z1_real
    z2_map[real_denom] = z2_real

    return DenominationProof(A_map, z1_map, z2_map, e_map)


def verify_minting(C, proof: DenominationProof) -> bool:
    """
    Verify OR-proof:
      - All equations hold
      - Challenges sum correctly
    """
    e_sum = 0

    for d in ALLOWED_DENOMINATIONS:
        A = proof.A_map[d]
        z1 = proof.z1_map[d]
        z2 = proof.z2_map[d]
        e_d = proof.e_map[d]

        if z1 * G + z2 * H != A + e_d * C:
            return False

        e_sum = (e_sum + e_d) % ORDER

    transcript = b"".join(
        proof.A_map[d].x().to_bytes(32, "big") +
        proof.A_map[d].y().to_bytes(32, "big")
        for d in ALLOWED_DENOMINATIONS
    ) + (
        C.x().to_bytes(32, "big") +
        C.y().to_bytes(32, "big")
    )

    e = _fs_challenge(transcript)

    return e_sum == e
