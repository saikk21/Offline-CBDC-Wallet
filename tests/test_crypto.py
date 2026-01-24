# tests/test_crypto.py
from crypto.curve import random_scalar
from crypto.commitment import commit
from crypto.signature import generate_keypair, sign, verify
from crypto.hash import serialize_point
from crypto.curve import ORDER
from crypto.zkp.mint import (
    prove_minting,
    verify_minting,
    prove_opening,
    verify_opening,
)


def test_commitment_properties():
    v1, v2 = 10, 20
    r1, r2 = random_scalar(), random_scalar()

    C1 = commit(v1, r1)
    C2 = commit(v2, r2)

    # Homomorphic property
    C_sum = C1 + C2
    C_expected = commit(v1 + v2, (r1 + r2) % ORDER)

    assert C_sum == C_expected


def test_signature():
    sk, pk = generate_keypair()
    data = b"test-token"

    sig = sign(sk, data)
    assert verify(pk, sig, data)
    assert not verify(pk, sig, b"tampered")

def test_minting_zkp_with_denomination():
    v = 20
    r = random_scalar()

    C = commit(v, r)
    denom_proof = prove_minting(v, r, C)

    assert verify_minting(C, denom_proof)
    
def test_minting_zkp_opening_fiat_shamir():
    v = 20
    r = random_scalar()

    C = commit(v, r)
    proof = prove_opening(v, r, C)

    assert verify_opening(C, proof)
