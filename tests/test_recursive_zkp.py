from types import SimpleNamespace

from crypto.curve import G
from crypto.commitment import commit
from crypto.curve import random_scalar
from crypto.state.proof_state import ProofState
from crypto.zkp.recursive import (
    prove_recursive_invariant,
    verify_recursive_invariant,
)


def make_token(v):
    r = random_scalar()
    C = commit(v, r)
    return SimpleNamespace(C=C, r=r)


def test_recursive_proof_valid_state():
    """
    Valid closed-system state → proof verifies
    """
    # Mint
    t0 = make_token(50)
    state = ProofState.init_from_mint([t0])

    # Spend ALL value: 50 -> 30 + 20
    t1 = make_token(30)
    t2 = make_token(20)

    state.update_from_spend([t0], [t1, t2])

    # Prove + verify
    proof = prove_recursive_invariant(state)
    assert verify_recursive_invariant(state, proof)


def test_recursive_proof_detects_tampering():
    """
    Tampered state → proof fails
    """
    # Mint
    t0 = make_token(50)
    state = ProofState.init_from_mint([t0])

    # Spend ALL value
    t1 = make_token(30)
    t2 = make_token(20)
    state.update_from_spend([t0], [t1, t2])

    proof = prove_recursive_invariant(state)

    # Maliciously tamper with state
    state.C_out_total = state.C_out_total + G


    assert not verify_recursive_invariant(state, proof)
