from transport.proof_serializer import (
    serialize_spend_proof,
    deserialize_spend_proof,
    serialize_value_proof,
    deserialize_value_proof,
    serialize_recursive_proof,
    deserialize_recursive_proof,
)

from crypto.zkp.spend import prove_spend_ownership
from crypto.zkp.value import prove_value_conservation
from crypto.zkp.recursive import prove_recursive_invariant
from crypto.commitment import commit
from crypto.curve import random_scalar
from crypto.state.proof_state import ProofState


# ---------------------------------------------------------
# 1️⃣ Test SpendProof
# ---------------------------------------------------------

v = 10
r = random_scalar()
s = random_scalar()

C = commit(v, r)
serial = s * C.curve.generator if False else s * C  # if needed adjust

proof = prove_spend_ownership(v, r, s, C, s * C)

serialized = serialize_spend_proof(proof)
proof2 = deserialize_spend_proof(serialized)

assert proof.A_commit == proof2.A_commit
assert proof.A_serial == proof2.A_serial
assert proof.z_v == proof2.z_v
assert proof.z_r == proof2.z_r
assert proof.z_s == proof2.z_s

print("SpendProof serialization OK")


# ---------------------------------------------------------
# 2️⃣ Test ValueProof
# ---------------------------------------------------------

v_out = 6
v_change = 4

r_out = random_scalar()
r_change = random_scalar()

C_out = commit(v_out, r_out)
C_change = commit(v_change, r_change)

value_proof = prove_value_conservation(
    v_in=v,
    r_in=r,
    v_out=v_out,
    r_out=r_out,
    v_change=v_change,
    r_change=r_change,
    C_in=C,
    C_out=C_out,
    C_change=C_change
)

serialized_v = serialize_value_proof(value_proof)
value_proof2 = deserialize_value_proof(serialized_v)

assert value_proof.A == value_proof2.A
assert value_proof.z_v == value_proof2.z_v
assert value_proof.z_r == value_proof2.z_r

print("ValueProof serialization OK")


# ---------------------------------------------------------
# 3️⃣ Test RecursiveInvariantProof
# ---------------------------------------------------------

state = ProofState(
    C_in_total=C,
    C_out_total=C_out + C_change,
    r_in_total=r,
    r_out_total=(r_out + r_change)
)

recursive_proof = prove_recursive_invariant(state)

serialized_r = serialize_recursive_proof(recursive_proof)
recursive_proof2 = deserialize_recursive_proof(serialized_r)

assert recursive_proof.A == recursive_proof2.A
assert recursive_proof.z == recursive_proof2.z

print("RecursiveProof serialization OK")
