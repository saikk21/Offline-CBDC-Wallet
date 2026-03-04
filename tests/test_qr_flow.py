from transport.qr_encoder import encode_transaction_to_qr
from transport.qr_decoder import decode_qr_payload
from transport.transaction_serializer import serialize_offline_transaction
import base64

def test_qr_base64_roundtrip(sample_tx):

    payload = serialize_offline_transaction(sample_tx)
    b64 = base64.b64encode(payload).decode()

    tx2 = decode_qr_payload(b64)

    assert tx2.transcript_hash == sample_tx.transcript_hash
