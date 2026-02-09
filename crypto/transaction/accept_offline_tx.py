# crypto/transaction/accept_offline_tx.py

def accept_offline_transaction(
    tx,
    receiver_state
):
    """
    Accept a verified offline transaction and update receiver state.

    Preconditions:
    - verify_offline_transaction(tx, ...) == True
    """

    # --------------------------------------------------
    # 1. Mark input serials as seen
    # --------------------------------------------------
    for serial in tx.input_serials:
        receiver_state.seen_serials.add(serial)

    # --------------------------------------------------
    # 2. Store received output tokens
    # --------------------------------------------------
    for token in tx.output_commitments:
        receiver_state.owned_tokens.append(token)

    # --------------------------------------------------
    # 3. Update proof state (for reconciliation)
    # --------------------------------------------------
    if receiver_state.proof_state is not None:
        receiver_state.proof_state.update_from_spend(
            input_tokens=[],               # receiver consumes nothing
            output_tokens=tx.output_commitments
        )
