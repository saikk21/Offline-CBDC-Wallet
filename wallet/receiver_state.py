class ReceiverWalletState:
    def __init__(self, proof_state=None):
        self.seen_serials = set()
        self.owned_tokens = []
        self.proof_state = proof_state
