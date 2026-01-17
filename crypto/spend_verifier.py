# crypto/spend_verifier.py

from crypto.zkp.spend import verify_spend_ownership


def _serialize_point(P) -> bytes:
    """
    Canonical serialization of an EC point for hashing / storage.
    """
    return (
        P.x().to_bytes(32, "big") +
        P.y().to_bytes(32, "big")
    )


class SpentSerialDB:
    """
    Offline database of spent serials (stored as serialized EC points).
    """

    def __init__(self):
        self._spent = set()

    def is_spent(self, serial) -> bool:
        return _serialize_point(serial) in self._spent

    def mark_spent(self, serial):
        self._spent.add(_serialize_point(serial))


def verify_and_record_spend(
    C,
    serial,
    proof,
    spent_db: SpentSerialDB
) -> bool:
    """
    Full offline spend verification pipeline.
    """

    # Step 1: cryptographic verification
    if not verify_spend_ownership(C, serial, proof):
        return False

    # Step 2: double-spend check
    if spent_db.is_spent(serial):
        return False

    # Step 3: record serial
    spent_db.mark_spent(serial)

    return True
