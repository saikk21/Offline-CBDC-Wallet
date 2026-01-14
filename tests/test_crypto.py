# tests/test_crypto.py
from crypto.curve import random_scalar
from crypto.commitment import commit
from crypto.signature import generate_keypair, sign, verify
from crypto.hash import serialize_point
from crypto.curve import ORDER

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
