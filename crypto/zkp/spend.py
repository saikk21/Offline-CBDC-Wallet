# crypto/zkp/spend.py

from crypto.curve import G, H, ORDER, random_scalar
from crypto.hash import sha256_int


# ---------------------------------------------------------
# Serial / Nullifier (linear, ZKP-safe)
# ---------------------------------------------------------

def derive_serial(secret: int):
    """
    Derive a serial (nullifier) as an elliptic curve point.

    serial = s * G
    """
    return secret * G


# ---------------------------------------------------------
# Fiat–Shamir challenge
# ---------------------------------------------------------

def _fs_challenge(data: bytes) -> int:
    return sha256_int(data) % ORDER


# ---------------------------------------------------------
# Spend ownership proof container
# ---------------------------------------------------------

class SpendProof:
    def __init__(self, A_commit, A_serial, z_v, z_r, z_s):
        self.A_commit = A_commit  # EC point
        self.A_serial = A_serial  # EC point
        self.z_v = z_v            # scalar
        self.z_r = z_r            # scalar
        self.z_s = z_s            # scalar


# ---------------------------------------------------------
# Prover: Spend ownership + serial binding
# ---------------------------------------------------------

def prove_spend_ownership(
    v: int,
    r: int,
    s: int,
    C,
    serial
) -> SpendProof:
    """
    Prove knowledge of (v, r, s) such that:
      C      = v*G + r*H
      serial = s*G
    """

    # Step 1: choose randomness
    a_v = random_scalar()
    a_r = random_scalar()
    a_s = random_scalar()

    # Step 2: ephemeral commitments
    A_commit = a_v * G + a_r * H
    A_serial = a_s * G

    # Step 3: Fiat–Shamir challenge
    e = _fs_challenge(
        A_commit.x().to_bytes(32, "big") +
        A_commit.y().to_bytes(32, "big") +
        A_serial.x().to_bytes(32, "big") +
        A_serial.y().to_bytes(32, "big") +
        C.x().to_bytes(32, "big") +
        C.y().to_bytes(32, "big") +
        serial.x().to_bytes(32, "big") +
        serial.y().to_bytes(32, "big")
    )

    # Step 4: responses
    z_v = (a_v + e * v) % ORDER
    z_r = (a_r + e * r) % ORDER
    z_s = (a_s + e * s) % ORDER

    return SpendProof(A_commit, A_serial, z_v, z_r, z_s)


# ---------------------------------------------------------
# Verifier: Spend ownership + serial binding
# ---------------------------------------------------------

def verify_spend_ownership(C, serial, proof: SpendProof) -> bool:
    """
    Verify spend ownership proof.
    """

    # Recompute challenge
    e = _fs_challenge(
        proof.A_commit.x().to_bytes(32, "big") +
        proof.A_commit.y().to_bytes(32, "big") +
        proof.A_serial.x().to_bytes(32, "big") +
        proof.A_serial.y().to_bytes(32, "big") +
        C.x().to_bytes(32, "big") +
        C.y().to_bytes(32, "big") +
        serial.x().to_bytes(32, "big") +
        serial.y().to_bytes(32, "big")
    )

    # Commitment equation
    if proof.z_v * G + proof.z_r * H != proof.A_commit + e * C:
        return False

    # Serial equation
    if proof.z_s * G != proof.A_serial + e * serial:
        return False

    return True
