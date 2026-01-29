# wallet/token_store.py

from typing import Dict, List
from models.token import Token
from models.token_state import TokenState


class TokenStore:
    """
    Local wallet storage for Digital Rupee tokens.
    Tracks tokens and their lifecycle state.
    """

    def __init__(self):
        # Maps token serial -> (Token, TokenState)
        self._tokens: Dict[int, tuple[Token, TokenState]] = {}

    def add_token(self, token: Token):
        """
        Add a newly received token to the wallet as UNSPENT.
        """
        if token.serial in self._tokens:
            raise ValueError("Token with this serial already exists in store")

        self._tokens[token.serial] = (token, TokenState.UNSPENT)

    def mark_spent(self, serial: int):
        """
        Mark a token as SPENT after it has been consumed.
        """
        if serial not in self._tokens:
            raise KeyError("Token not found in store")

        token, state = self._tokens[serial]

        if state != TokenState.UNSPENT:
            raise ValueError("Only UNSPENT tokens can be marked as SPENT")

        self._tokens[serial] = (token, TokenState.SPENT)

    def mark_expired(self, serial: int):
        """
        Mark a token as EXPIRED.
        """
        if serial not in self._tokens:
            raise KeyError("Token not found in store")

        token, state = self._tokens[serial]

        if state == TokenState.SPENT:
            return  # spent tokens stay spent

        self._tokens[serial] = (token, TokenState.EXPIRED)

    def get_unspent_tokens(self, current_time: int) -> List[Token]:
        """
        Return all tokens that are UNSPENT and not expired.
        """
        unspent = []

        for token, state in self._tokens.values():
            if state == TokenState.UNSPENT and not token.is_expired(current_time):
                unspent.append(token)

        return unspent

    def get_token_state(self, serial: int) -> TokenState:
        """
        Get the lifecycle state of a token.
        """
        if serial not in self._tokens:
            raise KeyError("Token not found in store")

        return self._tokens[serial][1]

    def all_tokens(self):
        """
        Return all tokens with their states (for debugging / reconciliation prep).
        """
        return dict(self._tokens)
