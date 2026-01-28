# wallet/pending_store.py

from typing import List, Dict
import time


class PendingSpend:
    """
    Represents a locally completed offline spend
    that has not yet been reconciled with the bank/RBI.
    """

    def __init__(self, serial, proof):
        self.serial = serial          # EC point or serialized form
        self.proof = proof            # RecursiveInvariantProof
        self.timestamp = int(time.time())


class PendingStore:
    """
    Tracks all offline spends pending reconciliation.
    """

    def __init__(self):
        # serialized_serial -> PendingSpend
        self._pending: Dict[bytes, PendingSpend] = {}

    @staticmethod
    def _serialize_serial(serial) -> bytes:
        """
        Canonical serialization of a serial (EC point).
        """
        return (
            serial.x().to_bytes(32, "big") +
            serial.y().to_bytes(32, "big")
        )

    def add(self, serial, proof):
        """
        Record a new pending spend.
        """
        key = self._serialize_serial(serial)

        if key in self._pending:
            raise ValueError("Spend already recorded as pending")

        self._pending[key] = PendingSpend(serial, proof)

    def list_pending(self) -> List[PendingSpend]:
        """
        Return all pending spends.
        """
        return list(self._pending.values())

    def clear(self, serial):
        """
        Remove a spend after successful reconciliation.
        """
        key = self._serialize_serial(serial)
        self._pending.pop(key, None)

    def count(self) -> int:
        return len(self._pending)
