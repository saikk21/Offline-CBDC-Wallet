# crypto/device/spend_transcript.py

from crypto.hash import sha256_int, serialize_point
from transport.proof_serializer import (
    serialize_spend_proof,
    serialize_value_proof,
)


def build_spend_transcript(
    serials,
    output_commitments,
    spend_proof,
    value_proof,
    nonce: bytes
) -> bytes:
    """
    Build a canonical transcript for device authorization of an offline spend.

    This transcript binds:
    - spent token serials
    - output commitments
    - spend ownership ZKP
    - value conservation ZKP
    - freshness nonce
    """

    # --------------------------------------------------
    # 1. Canonicalize serials (EC points)
    # --------------------------------------------------
    serial_bytes = b"".join(
        sorted(serialize_point(s) for s in serials)
    )

    # --------------------------------------------------
    # 2. Canonicalize output commitments (EC points)
    # --------------------------------------------------
    commitment_bytes = b"".join(
        sorted(serialize_point(C) for C in output_commitments)
    )

    # --------------------------------------------------
    # 3. Bind spend ZKP (DETERMINISTIC)
    # --------------------------------------------------
    spend_proof_bytes = sha256_int(
        serialize_spend_proof(spend_proof)
    ).to_bytes(32, "big")

    # --------------------------------------------------
    # 4. Bind value conservation ZKP (DETERMINISTIC)
    # --------------------------------------------------
    value_proof_bytes = sha256_int(
        serialize_value_proof(value_proof)
    ).to_bytes(32, "big")

    # --------------------------------------------------
    # 5. Final transcript hash
    # --------------------------------------------------
    transcript = (
        serial_bytes +
        commitment_bytes +
        spend_proof_bytes +
        value_proof_bytes +
        nonce
    )

    return sha256_int(transcript).to_bytes(32, "big")
