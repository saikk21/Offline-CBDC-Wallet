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
        tx.transcript_hash,
        tx.device_signature,
        tx.device_certificate,
        pk_bank
    ):
        return False

    # --------------------------------------------------
    #   2. Verify spend ownership ZKP
    # --------------------------------------------------
    from crypto.zkp.spend import verify_spend_ownership

    if not verify_spend_ownership(
        tx.input_commitments[0],
        tx.input_serials[0],
        tx.spend_proof
    ):
        return False
    # --------------------------------------------------
    # 3. Verify value conservation
    # --------------------------------------------------
    from crypto.zkp.value import verify_value_conservation

    if not verify_value_conservation(
        tx.input_commitments[0],          # C_in
        tx.output_commitments[0],         # C_out
        tx.output_commitments[1],         # C_change
        tx.value_proof
    ):
        return False

    # --------------------------------------------------
    # 4. Local double-spend prevention
    # --------------------------------------------------
    from crypto.hash import serialize_point

    for serial in tx.input_serials:
        serial_bytes = serialize_point(serial)

        if serial_bytes in seen_serials:
            return False

        # Mark as seen
        seen_serials.add(serial_bytes)

    return True
