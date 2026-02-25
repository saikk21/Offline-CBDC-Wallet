from crypto.hash import serialize_point
from transport.proof_serializer import (
    serialize_spend_proof,
    serialize_value_proof,
    serialize_recursive_proof,
    deserialize_spend_proof,
    deserialize_value_proof,
    deserialize_recursive_proof,
)
from models.offline_transaction import OfflineTransaction
from crypto.device.certificate import DeviceCertificate
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1


# ==========================================================
# Helpers
# ==========================================================

def _point_from_bytes(data: bytes) -> Point:
    x = int.from_bytes(data[:32], "big")
    y = int.from_bytes(data[32:], "big")
    return Point(SECP256k1.curve, x, y)


# ==========================================================
# Serialize
# ==========================================================

def serialize_offline_transaction(tx: OfflineTransaction) -> bytes:

    payload = b""

    # ----------------------------
    # 1️⃣ Input serials
    # ----------------------------
    payload += len(tx.input_serials).to_bytes(4, "big")
    for s in tx.input_serials:
        payload += serialize_point(s)

    # ----------------------------
    # 2️⃣ Input commitments  ← MUST BE HERE
    # ----------------------------
    payload += len(tx.input_commitments).to_bytes(4, "big")
    for C in tx.input_commitments:
        payload += serialize_point(C)

    # ----------------------------
    # 3️⃣ Output commitments
    # ----------------------------
    payload += len(tx.output_commitments).to_bytes(4, "big")
    for C in tx.output_commitments:
        payload += serialize_point(C)

    # ----------------------------
    # 4️⃣ Proofs
    # ----------------------------
    payload += serialize_spend_proof(tx.spend_proof)
    payload += serialize_value_proof(tx.value_proof)
    payload += serialize_recursive_proof(tx.recursive_proof)

    # ----------------------------
    # 5️⃣ Transcript + signature
    # ----------------------------
    payload += tx.transcript_hash
    payload += tx.device_signature

    # ----------------------------
    # 6️⃣ Certificate
    # ----------------------------
    cert = tx.device_certificate

    payload += serialize_point(cert.pk_device)

    payload += len(cert.cert_id).to_bytes(4, "big")
    payload += cert.cert_id

    payload += cert.issued_at.to_bytes(8, "big")
    payload += cert.expires_at.to_bytes(8, "big")

    payload += cert.signature

    # ----------------------------
    # 7️⃣ Nonce
    # ----------------------------
    payload += len(tx.nonce).to_bytes(4, "big")
    payload += tx.nonce

    return payload

# ==========================================================
# Deserialize
# ==========================================================

def deserialize_offline_transaction(data: bytes) -> OfflineTransaction:

    offset = 0

    # ----------------------------
    # 1️⃣ Input serials
    # ----------------------------
    n_inputs = int.from_bytes(data[offset:offset+4], "big")
    offset += 4

    input_serials = []
    for _ in range(n_inputs):
        pt = _point_from_bytes(data[offset:offset+64])
        offset += 64
        input_serials.append(pt)

    # ----------------------------
    # 2️⃣ Input commitments  ← MUST MATCH SERIALIZER
    # ----------------------------
    n_input_commitments = int.from_bytes(data[offset:offset+4], "big")
    offset += 4

    input_commitments = []
    for _ in range(n_input_commitments):
        pt = _point_from_bytes(data[offset:offset+64])
        offset += 64
        input_commitments.append(pt)

    # ----------------------------
    # 3️⃣ Output commitments
    # ----------------------------
    n_outputs = int.from_bytes(data[offset:offset+4], "big")
    offset += 4

    output_commitments = []
    for _ in range(n_outputs):
        pt = _point_from_bytes(data[offset:offset+64])
        offset += 64
        output_commitments.append(pt)

    # ----------------------------
    # 4️⃣ Proofs
    # ----------------------------
    spend_proof = deserialize_spend_proof(data[offset:offset+224])
    offset += 224

    value_proof = deserialize_value_proof(data[offset:offset+128])
    offset += 128

    recursive_proof = deserialize_recursive_proof(data[offset:offset+96])
    offset += 96

    # ----------------------------
    # 5️⃣ Transcript + signature
    # ----------------------------
    transcript_hash = data[offset:offset+32]
    offset += 32

    device_signature = data[offset:offset+96]
    offset += 96

    # ----------------------------
    # 6️⃣ Certificate
    # ----------------------------
    pk_device = _point_from_bytes(data[offset:offset+64])
    offset += 64

    cert_len = int.from_bytes(data[offset:offset+4], "big")
    offset += 4

    cert_id = data[offset:offset+cert_len]
    offset += cert_len

    issued_at = int.from_bytes(data[offset:offset+8], "big")
    offset += 8

    expires_at = int.from_bytes(data[offset:offset+8], "big")
    offset += 8

    signature = data[offset:offset+96]
    offset += 96

    certificate = DeviceCertificate(
        pk_device=pk_device,
        cert_id=cert_id,
        issued_at=issued_at,
        expires_at=expires_at,
        signature=signature
    )

    # ----------------------------
    # 7️⃣ Nonce
    # ----------------------------
    nonce_len = int.from_bytes(data[offset:offset+4], "big")
    offset += 4

    nonce = data[offset:offset+nonce_len]

    return OfflineTransaction(
        input_serials=input_serials,
        input_commitments=input_commitments,
        output_commitments=output_commitments,
        spend_proof=spend_proof,
        value_proof=value_proof,
        recursive_proof=recursive_proof,
        transcript_hash=transcript_hash,
        device_signature=device_signature,
        device_certificate=certificate,
        nonce=nonce
    )
