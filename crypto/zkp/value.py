from crypto.curve import G, H, ORDER, random_scalar
from crypto.hash import sha256_int


# ============================================================
# Fiat–Shamir Challenge
# ============================================================

def _fs_challenge(data: bytes) -> int:
    """
    Fiat–Shamir challenge derived from transcript.
    """
    return sha256_int(data) % ORDER


# ============================================================
# Value Conservation Proof Container
# ============================================================

class ValueProof:
    """
    Proves value conservation:
        C_in = C_out + C_change
    without revealing values.
    """

    def __init__(self, A, z_v, z_r):
        self.A = A        # EC point
        self.z_v = z_v    # scalar
        self.z_r = z_r    # scalar


# ============================================================
# Prover: Value Conservation ZKP
# ============================================================

def prove_value_conservation(
    v_in: int,
    r_in: int,
    v_out: int,
    r_out: int,
    v_change: int,
    r_change: int,
    C_in,
    C_out,
    C_change
) -> ValueProof:
    """
    Prove:
        v_in = v_out + v_change

    Uses Pedersen commitment homomorphism:
        C_in - C_out - C_change = 0*G + (r_in - r_out - r_change)*H
    """

    # --------------------------------------------------------
    # Local sanity check (not revealed)
    # --------------------------------------------------------
    if v_in != v_out + v_change:
        raise ValueError("Value mismatch")

    # --------------------------------------------------------
    # Commitment difference (IMPORTANT FIX)
    #   EC subtraction must be done via negation
    # --------------------------------------------------------
    C_diff = C_in + (-C_out) + (-C_change)

    # --------------------------------------------------------
    # Randomness
    # --------------------------------------------------------
    a_v = random_scalar()
    a_r = random_scalar()

    # --------------------------------------------------------
    # Ephemeral commitment
    # --------------------------------------------------------
    A = a_v * G + a_r * H

    # --------------------------------------------------------
    # Fiat–Shamir challenge
    # --------------------------------------------------------
    e = _fs_challenge(
        A.x().to_bytes(32, "big") +
        A.y().to_bytes(32, "big") +
        C_diff.x().to_bytes(32, "big") +
        C_diff.y().to_bytes(32, "big")
    )

    # --------------------------------------------------------
    # Responses
    #   v_in - v_out - v_change = 0
    # --------------------------------------------------------
    z_v = (a_v + e * 0) % ORDER
    z_r = (a_r + e * (r_in - r_out - r_change)) % ORDER

    return ValueProof(A, z_v, z_r)


# ============================================================
# Verifier: Value Conservation ZKP
# ============================================================

def verify_value_conservation(
    C_in,
    C_out,
    C_change,
    proof: ValueProof
) -> bool:
    """
    Verify value conservation proof.
    """

    # --------------------------------------------------------
    # Recompute commitment difference
    # --------------------------------------------------------
    C_diff = C_in + (-C_out) + (-C_change)

    # --------------------------------------------------------
    # Recompute Fiat–Shamir challenge
    # --------------------------------------------------------
    e = _fs_challenge(
        proof.A.x().to_bytes(32, "big") +
        proof.A.y().to_bytes(32, "big") +
        C_diff.x().to_bytes(32, "big") +
        C_diff.y().to_bytes(32, "big")
    )

    # --------------------------------------------------------
    # Verify equation:
    #   z_v*G + z_r*H == A + e*C_diff
    # --------------------------------------------------------
    left = proof.z_v * G + proof.z_r * H
    right = proof.A + e * C_diff

    return left == right
