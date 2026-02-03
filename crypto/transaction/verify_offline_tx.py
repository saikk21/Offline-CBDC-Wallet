# crypto/transaction/verify_offline_tx.py

def verify_offline_transaction(
    tx,
    pk_bank,
    seen_serials: set
) -> bool:
    """
    Receiver-side offline verification of an OfflineTransaction.
    """

    # --------------------------------------------------
    # 1. Verify device authorization & certificate
    # --------------------------------------------------
    from crypto.device.verify_spend_auth import verify_spend_authorization

    if not verify_spend_authorization(
        tx.spend_transcript_hash,
        tx.device_signature,
        tx.device_certificate,
        pk_bank
    ):
        return False

    # --------------------------------------------------
    # 2. Verify spend ownership ZKPs
    # --------------------------------------------------
    from crypto.zkp.spend import verify_spend_ownership

    for serial, proof in zip(tx.input_serials, tx.spend_proof):
        if not verify_spend_ownership(
            proof["C"],
            serial,
            proof["proof"]
        ):
            return False

    # --------------------------------------------------
    # 3. Verify value conservation
    # --------------------------------------------------
    from crypto.zkp.value import verify_value_conservation

    if not verify_value_conservation(
        tx.value_proof["C_in"],
        tx.value_proof["C_out"],
        tx.value_proof["C_change"],
        tx.value_proof["proof"]
    ):
        return False

    # --------------------------------------------------
    # 4. Local double-spend prevention
    # --------------------------------------------------
    for serial in tx.input_serials:
        if serial in seen_serials:
            return False

    return True
