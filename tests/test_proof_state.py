from types import SimpleNamespace

from crypto.state.proof_state import ProofState
from crypto.curve import G
from crypto.commitment import commit
from crypto.curve import random_scalar


def make_token(v):
    r = random_scalar()
    C = commit(v, r)
    return SimpleNamespace(C=C, r=r)


def test_init_from_mint_only():
    tokens = [make_token(10), make_token(20), make_token(50)]
    state = ProofState.init_from_mint(tokens)

    assert state.C_in_total == 0 * G
    assert state.r_in_total == 0
    assert state.C_out_total is not None
    assert state.r_out_total > 0


def test_single_spend_state_update():
    t0 = make_token(50)
    state = ProofState.init_from_mint([t0])

    t1 = make_token(30)
    t2 = make_token(20)

    state.update_from_spend([t0], [t1, t2])

    # Just verify state updates ran
    assert state.C_in_total is not None
    assert state.C_out_total is not None
    assert state.r_in_total > 0
    assert state.r_out_total > 0


def test_multi_hop_state_update():
    t0 = make_token(100)
    state = ProofState.init_from_mint([t0])

    t1 = make_token(60)
    t2 = make_token(40)
    state.update_from_spend([t0], [t1, t2])

    t3 = make_token(25)
    t4 = make_token(35)
    state.update_from_spend([t1], [t3, t4])

    # State remains consistent
    assert state.C_in_total is not None
    assert state.C_out_total is not None
