# models/token_state.py

from enum import Enum, auto


class TokenState(Enum):
    """
    Local lifecycle state of a Digital Rupee token inside a wallet.
    """
    UNSPENT = auto()
    SPENT = auto()
    EXPIRED = auto()
