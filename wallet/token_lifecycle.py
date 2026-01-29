# wallet/token_lifecycle.py

from typing import List, Tuple
from models.token import Token
from models.token_state import TokenState
from wallet.token_store import TokenStore

from crypto.state.proof_state import ProofState
from crypto.zkp.spend import (
    derive_serial,
    prove_spend_ownership,
    SpendProof
)
from crypto.zkp.value import (
    prove_value_conservation,
    ValueProof
)
from crypto.zkp.recursive import (
    prove_recursive_invariant,
    RecursiveInvariantProof
)
from crypto.curve import random_scalar


class TokenLifecycle:
    """
    Handles token consumption and derivation during offline spending.
    """

    def __init__(self, store: TokenStore, proof_state: ProofState):
        self.store = store
        self.proof_state = proof_state

    def spend(
        self,
        input_serials: List[int],
        v_out: int,
        v_change: int,
        expiry: int
    ) -> Tuple[
        List[Token],
        List,
        List[SpendProof],
        ValueProof,
        RecursiveInvariantProof
    ]:
        """
        Perform an offline spend.

        Returns:
        - derived_tokens
        - spend_serials
        - spend_proofs
        - value_proof
        - recursive_proof
        """

        # --------------------------------------------------
        # 1. Fetch and validate input tokens
        # --------------------------------------------------
        input_tokens = []

        for serial in input_serials:
            state = self.store.get_token_state(serial)
            if state != TokenState.UNSPENT:
                raise ValueError(f"Token {serial} is not spendable")

            token, _ = self.store._tokens[serial]
            input_tokens.append(token)

        if len(input_tokens) != 1:
            raise NotImplementedError("Prototype supports single-input spends")

        t_in = input_tokens[0]

        v_in = t_in.v
        r_in = t_in.r
        s_in = t_in.s
        C_in = t_in.commitment

        if v_in != v_out + v_change:
            raise ValueError("Input value does not match outputs")

        # --------------------------------------------------
        # 2. Derive spend serial
        # --------------------------------------------------
        serial = derive_serial(s_in)

        # --------------------------------------------------
        # 3. Spend ownership ZKP
        # --------------------------------------------------
        spend_proof = prove_spend_ownership(
            v=v_in,
            r=r_in,
            s=s_in,
            C=C_in,
            serial=serial
        )

        # --------------------------------------------------
        # 4. Create output commitments
        # --------------------------------------------------
        r_out = random_scalar()
        r_change = random_scalar()

        # NOTE: commitment creation already exists in crypto.commitment
        from crypto.commitment import commit

        C_out = commit(v_out, r_out)
        C_change = commit(v_change, r_change)

        # --------------------------------------------------
        # 5. Value conservation ZKP
        # --------------------------------------------------
        value_proof = prove_value_conservation(
            v_in=v_in,
            r_in=r_in,
            v_out=v_out,
            r_out=r_out,
            v_change=v_change,
            r_change=r_change,
            C_in=C_in,
            C_out=C_out,
            C_change=C_change
        )

        # --------------------------------------------------
        # 6. Update proof state
        # --------------------------------------------------
        class _Tmp:
            def __init__(self, C, r):
                self.C = C
                self.r = r

        input_wrapped = [_Tmp(C_in, r_in)]
        output_wrapped = [
            _Tmp(C_out, r_out),
            _Tmp(C_change, r_change)
        ]

        self.proof_state.update_from_spend(
            input_tokens=input_wrapped,
            output_tokens=output_wrapped
        )

        recursive_proof = prove_recursive_invariant(self.proof_state)

        # --------------------------------------------------
        # 7. Mark input token as spent
        # --------------------------------------------------
        self.store.mark_spent(t_in.serial)

        # --------------------------------------------------
        # 8. Create derived tokens
        # --------------------------------------------------
        derived_tokens = []

        s_out = random_scalar()
        s_change = random_scalar()

        token_out = Token(
            serial=None,              # derived tokens have no global serial
            commitment=C_out,
            expiry=expiry,
            signature=None,
            v=v_out,
            r=r_out,
            s=s_out
        )

        token_change = Token(
            serial=None,
            commitment=C_change,
            expiry=expiry,
            signature=None,
            v=v_change,
            r=r_change,
            s=s_change
        )

        derived_tokens.extend([token_out, token_change])

        return (
            derived_tokens,
            [serial],
            [spend_proof],
            value_proof,
            recursive_proof
        )
