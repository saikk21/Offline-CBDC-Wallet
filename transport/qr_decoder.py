# transport/qr_decoder.py

import base64
from transport.transaction_serializer import deserialize_offline_transaction


def decode_qr_payload(b64_string: str):
    """
    Base64 string → bytes → OfflineTransaction
    """
    raw_bytes = base64.b64decode(b64_string)
    return deserialize_offline_transaction(raw_bytes)
