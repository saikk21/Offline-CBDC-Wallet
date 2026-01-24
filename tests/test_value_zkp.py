from crypto.curve import G, H, random_scalar
from crypto.zkp.value import (
    prove_value_conservation,
    verify_value_conservation
)


def test_value_conservation_valid():
    v_in = 50
    v_out = 30
    v_change = 20

    r_in = random_scalar()
    r_out = random_scalar()
    r_change = random_scalar()

    C_in = v_in * G + r_in * H
    C_out = v_out * G + r_out * H
    C_change = v_change * G + r_change * H

    proof = prove_value_conservation(
        v_in, r_in,
        v_out, r_out,
        v_change, r_change,
        C_in, C_out, C_change
    )

    assert verify_value_conservation(C_in, C_out, C_change, proof)


def test_value_conservation_invalid():
    v_in = 50
    v_out = 40
    v_change = 20  # INVALID (40 + 20 != 50)

    r_in = random_scalar()
    r_out = random_scalar()
    r_change = random_scalar()

    C_in = v_in * G + r_in * H
    C_out = v_out * G + r_out * H
    C_change = v_change * G + r_change * H

    try:
        prove_value_conservation(
            v_in, r_in,
            v_out, r_out,
            v_change, r_change,
            C_in, C_out, C_change
        )
        assert False, "Invalid value conservation should fail"
    except ValueError:
        assert True
