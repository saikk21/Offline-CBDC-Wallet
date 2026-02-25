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
    from crypto.hash import serialize_point

    for serial in tx.input_serials:
        receiver_state.seen_serials.add(serialize_point(serial))

    # --------------------------------------------------
    # 2. Store received output tokens
    # --------------------------------------------------
    for token in tx.output_commitments:
        receiver_state.owned_tokens.append(token)

    # --------------------------------------------------
    # 3. Update proof state (for reconciliation)
    # --------------------------------------------------
    if receiver_state.proof_state is not None:

        # Wrap commitments into objects expected by ProofState
        class _Tmp:
            def __init__(self, C):
                self.C = C
                self.r = 0  # receiver does not know blinding factor

        wrapped_outputs = [_Tmp(C) for C in tx.output_commitments]

        receiver_state.proof_state.update_from_spend(
            input_tokens=[],          # receiver consumes nothing
            output_tokens=wrapped_outputs
        )
