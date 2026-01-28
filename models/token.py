# models/token.py

from dataclasses import dataclass
from crypto.hash import sha256_bytes, serialize_int, serialize_point
from crypto.signature import verify


@dataclass(frozen=True)
class Token:
    """
    Immutable representation of a Digital Rupee (e₹) token.
    """
    serial: int | None
    commitment: object
    expiry: int
    signature: bytes | None

    # Wallet-private fields (NOT serialized)
    v: int
    r: int
    s: int

    def serialize_for_signature(self) -> bytes:
        """
        Deterministically serialize token fields for signature verification.
        """
        return (
            serialize_int(self.serial) +
            serialize_point(self.commitment) +
            serialize_int(self.expiry)
        )

    def verify_bank_signature(self, bank_public_key) -> bool:
        """
        Verify that this token was signed by the bank/RBI.
        """
        data = self.serialize_for_signature()
        return verify(bank_public_key, self.signature, data)

    def is_expired(self, current_time: int) -> bool:
        """
        Check whether the token is expired.
        """
        return current_time >= self.expiry
