# tests/test_pending_store.py

from wallet.pending_store import PendingStore
from crypto.curve import G
from crypto.zkp.recursive import RecursiveInvariantProof


def test_pending_store_add_and_list():
    store = PendingStore()

    serial = 5 * G
    proof = RecursiveInvariantProof(A=7 * G, z=11)

    store.add(serial, proof)

    pending = store.list_pending()
    assert len(pending) == 1
    assert pending[0].serial == serial
    assert pending[0].proof == proof


def test_pending_store_duplicate_rejected():
    store = PendingStore()

    serial = 3 * G
    proof = RecursiveInvariantProof(A=9 * G, z=4)

    store.add(serial, proof)

    try:
        store.add(serial, proof)
        assert False, "Duplicate pending spend was allowed"
    except ValueError:
        pass


def test_pending_store_clear():
    store = PendingStore()

    serial = 2 * G
    proof = RecursiveInvariantProof(A=8 * G, z=6)

    store.add(serial, proof)
    assert store.count() == 1

    store.clear(serial)
    assert store.count() == 0
