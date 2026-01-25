from crypto.curve import G


class ProofState:
    def __init__(self, C_in_total, C_out_total, r_in_total, r_out_total):
        self.C_in_total = C_in_total
        self.C_out_total = C_out_total
        self.r_in_total = r_in_total
        self.r_out_total = r_out_total

    @classmethod
    def init_from_mint(cls, tokens):
        """
        Initialize proof state from freshly minted tokens.

        tokens: iterable of objects with:
            - t.C : elliptic curve commitment (Point)
            - t.r : blinding factor (int)
        """

        C_identity = 0 * G
        r_identity = 0

        C_out_total = C_identity
        r_out_total = r_identity

        for t in tokens:
            C_out_total = C_out_total + t.C
            r_out_total = r_out_total + t.r

        return cls(
            C_in_total=C_identity,
            C_out_total=C_out_total,
            r_in_total=r_identity,
            r_out_total=r_out_total,
        )

    def update_from_spend(self, input_tokens, output_tokens):
        """
        Update proof state after an offline spend.
        """

        # Consume inputs
        for t in input_tokens:
            self.C_in_total = self.C_in_total + t.C
            self.r_in_total = self.r_in_total + t.r

            # EC subtraction = addition with negation
            self.C_out_total = self.C_out_total + (-t.C)
            self.r_out_total = self.r_out_total - t.r

        # Add outputs
        for t in output_tokens:
            self.C_out_total = self.C_out_total + t.C
            self.r_out_total = self.r_out_total + t.r
