from transport.transaction_serializer import (
    serialize_offline_transaction,
    deserialize_offline_transaction
)

from models.offline_transaction import OfflineTransaction
from crypto.zkp.spend import prove_spend_ownership
from crypto.zkp.value import prove_value_conservation
from crypto.zkp.recursive import prove_recursive_invariant
from crypto.commitment import commit
from crypto.curve import random_scalar
from crypto.device.identity import DeviceIdentity
from crypto.device.authority import BankAuthority
from crypto.device.spend_transcript import build_spend_transcript
from crypto.device.device_signature import sign_spend_transcript
from crypto.state.proof_state import ProofState


def test_transaction_roundtrip():

    # ----------------------------------------
    # Setup bank + device
    # ----------------------------------------
    bank = BankAuthority.generate()
    device = DeviceIdentity.generate()
    import os
    import time

    cert_id = os.urandom(16)
    issued_at = int(time.time())
    expires_at = issued_at + 3600

    cert = bank.issue_device_certificate(
        device.pk_device,
        cert_id,
        issued_at,
        expires_at
    )
    v = 10
    r = random_scalar()
    s = random_scalar()

    C = commit(v, r)
    serial = s * C

    spend_proof = prove_spend_ownership(v, r, s, C, serial)

    # ----------------------------------------
    # Create outputs
    # ----------------------------------------
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

    # ----------------------------------------
    # Proof state for recursive proof
    # ----------------------------------------
    state = ProofState(
        C_in_total=C,
        C_out_total=C_out + C_change,
        r_in_total=r,
        r_out_total=r_out + r_change
    )

    recursive_proof = prove_recursive_invariant(state)

    # ----------------------------------------
    # Transcript + signature
    # ----------------------------------------
    nonce = b"test_nonce_1234"

    transcript_hash = build_spend_transcript(
        [serial],
        [C_out, C_change],
        spend_proof,
        value_proof,
        nonce
    )

    device_signature = sign_spend_transcript(
        device.sk_device,
        transcript_hash
    )

    # ----------------------------------------
    # Build OfflineTransaction
    # ----------------------------------------
    tx = OfflineTransaction(
        input_serials=[serial],
        input_commitments=[C],
        output_commitments=[C_out, C_change],
        spend_proof=spend_proof,
        value_proof=value_proof,
        recursive_proof=recursive_proof,
        transcript_hash=transcript_hash,
        device_signature=device_signature,
        device_certificate=cert,
        nonce=nonce
    )

    # ----------------------------------------
    # Serialize → Deserialize
    # ----------------------------------------
    payload = serialize_offline_transaction(tx)
    tx2 = deserialize_offline_transaction(payload)

    # ----------------------------------------
    # Assertions
    # ----------------------------------------

    assert tx2.transcript_hash == tx.transcript_hash
    assert tx2.device_signature == tx.device_signature
    assert tx2.nonce == tx.nonce

    assert tx2.device_certificate.cert_id == tx.device_certificate.cert_id
    assert tx2.device_certificate.pk_device == tx.device_certificate.pk_device

    assert tx2.input_serials[0] == tx.input_serials[0]
    assert tx2.output_commitments[0] == tx.output_commitments[0]

    assert tx2.spend_proof.z_v == tx.spend_proof.z_v
    assert tx2.value_proof.z_r == tx.value_proof.z_r
    assert tx2.recursive_proof.z == tx.recursive_proof.z

    print("Transaction serialization roundtrip OK")
