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
from crypto.curve import random_scalar, ORDER
from crypto.hash import sha256_int, serialize_point


class TokenLifecycle:
    """
    Handles token minting, consumption, and derivation during offline spending.
    """

    def __init__(self, store: TokenStore, proof_state: ProofState):
        self.store = store
        self.proof_state = proof_state

    # ==================================================
    # STEP 6.2 — WALLET MINT FLOW
    # ==================================================
    def mint(
        self,
        v: int,
        expiry: int,
        bank_public_key,
        bank_mint_fn
    ) -> Token:

        r = random_scalar()
        from crypto.commitment import commit
        C = commit(v, r)

        from crypto.zkp.mint import prove_minting
        mint_proof = prove_minting(v, r, C)

        bank_token = bank_mint_fn(C, mint_proof)

        if not bank_token.verify_bank_signature(bank_public_key):
            raise ValueError("Invalid bank signature on minted token")

        wallet_token = Token(
            serial=bank_token.serial,
            commitment=bank_token.commitment,
            expiry=bank_token.expiry,
            signature=bank_token.signature,
            v=v,
            r=r,
            s=bank_token.serial
        )

        self.store.add_token(wallet_token)
        return wallet_token

    # ==================================================
    # STEP 7 — OFFLINE SPEND (ATOMIC + CORRECT)
    # ==================================================
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

        # ==================================================
        # PHASE 1 — COMPUTE (NO STATE MUTATION)
        # ==================================================

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

        spend_serial = derive_serial(s_in)

        spend_proof = prove_spend_ownership(
            v=v_in,
            r=r_in,
            s=s_in,
            C=C_in,
            serial=spend_serial
        )

        r_out = random_scalar()
        r_change = random_scalar()

        from crypto.commitment import commit
        C_out = commit(v_out, r_out)
        C_change = commit(v_change, r_change)

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

        # ==================================================
        # DETERMINISTIC LOCAL SERIALS (CRITICAL FIX)
        # ==================================================

        local_serial_out = sha256_int(serialize_point(C_out)) % ORDER
        local_serial_change = sha256_int(serialize_point(C_change)) % ORDER

        s_out = random_scalar()
        s_change = random_scalar()

        token_out = Token(
            serial=local_serial_out,
            commitment=C_out,
            expiry=expiry,
            signature=None,
            v=v_out,
            r=r_out,
            s=s_out
        )

        token_change = Token(
            serial=local_serial_change,
            commitment=C_change,
            expiry=expiry,
            signature=None,
            v=v_change,
            r=r_change,
            s=s_change
        )

        derived_tokens = [token_out, token_change]

        class _Tmp:
            def __init__(self, C, r):
                self.C = C
                self.r = r

        input_wrapped = [_Tmp(C_in, r_in)]
        output_wrapped = [
            _Tmp(C_out, r_out),
            _Tmp(C_change, r_change)
        ]

        # ==================================================
        # PHASE 2 — COMMIT
        # ==================================================

        self.proof_state.update_from_spend(
            input_tokens=input_wrapped,
            output_tokens=output_wrapped
        )

        recursive_proof = prove_recursive_invariant(self.proof_state)

        self.store.mark_spent(t_in.serial)

        for t in derived_tokens:
            self.store.add_token(t)

        return (
            derived_tokens,
            [spend_serial],
            [spend_proof],
            value_proof,
            recursive_proof
        )
