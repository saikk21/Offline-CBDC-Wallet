def test_spend_ownership_proof():
    from crypto.curve import random_scalar
    from crypto.commitment import commit
    from crypto.zkp.spend import (
        derive_serial,
        prove_spend_ownership,
        verify_spend_ownership,
    )

    v = 10
    r = random_scalar()
    s = random_scalar()

    C = commit(v, r)
    serial = derive_serial(s)

    proof = prove_spend_ownership(v, r, s, C, serial)
    assert verify_spend_ownership(C, serial, proof)

def test_double_spend_rejected():
    from crypto.curve import random_scalar
    from crypto.commitment import commit
    from crypto.zkp.spend import derive_serial, prove_spend_ownership
    from crypto.spend_verifier import SpentSerialDB, verify_and_record_spend

    v = 10
    r = random_scalar()
    s = random_scalar()

    C = commit(v, r)
    serial = derive_serial(s)

    proof = prove_spend_ownership(v, r, s, C, serial)

    db = SpentSerialDB()

    assert verify_and_record_spend(C, serial, proof, db)
    assert not verify_and_record_spend(C, serial, proof, db)

