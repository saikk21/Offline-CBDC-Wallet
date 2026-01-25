import secrets
from crypto.curve import H, ORDER
from crypto.hash import sha256_int, serialize_point
from crypto.state.proof_state import ProofState


class RecursiveInvariantProof:
    def __init__(self, A, z):
        self.A = A
        self.z = z


def prove_recursive_invariant(state: ProofState) -> RecursiveInvariantProof:
    """
    Prove knowledge of rho such that:
        C_out_total - C_in_total = rho * H
    """
    # Public statement
    D = state.C_out_total + (-state.C_in_total)

    # Witness
    rho = (state.r_out_total - state.r_in_total) % ORDER

    # Sigma protocol
    k = secrets.randbelow(ORDER)
    A = k * H

    e = sha256_int(
        serialize_point(A) + serialize_point(D)
    ) % ORDER

    z = (k + e * rho) % ORDER

    return RecursiveInvariantProof(A=A, z=z)


def verify_recursive_invariant(
    state: ProofState, proof: RecursiveInvariantProof
) -> bool:
    """
    Verify the recursive invariant proof.
    """
    # Public statement
    D = state.C_out_total + (-state.C_in_total)

    # Recompute Fiat–Shamir challenge
    e = sha256_int(
        serialize_point(proof.A) + serialize_point(D)
    ) % ORDER

    # Verify Sigma protocol equation
    lhs = proof.z * H
    rhs = proof.A + e * D

    # Use affine comparison for robustness
    return lhs.to_affine() == rhs.to_affine()

