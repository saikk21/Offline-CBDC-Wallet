from typing import List
from models.token import Token
from crypto.hash import (
    sha256_bytes,
    serialize_int,
    serialize_point
)


SPEND_TRANSCRIPT_VERSION = b"offline-cbdc-spend-v1"


def _serialize_proof(obj) -> bytes:
    """
    Deterministically serialize a proof object by hashing its __dict__.
    """
    items = []

    for k in sorted(obj.__dict__.keys()):
        v = obj.__dict__[k]

        if isinstance(v, int):
            items.append(serialize_int(v))
        elif isinstance(v, bytes):
            items.append(v)
        elif hasattr(v, "x") and hasattr(v, "y"):
            items.append(serialize_point(v))
        elif isinstance(v, dict):
            for dk in sorted(v.keys()):
                items.append(serialize_int(dk))
                dv = v[dk]
                if hasattr(dv, "x"):
                    items.append(serialize_point(dv))
                else:
                    items.append(serialize_int(dv))
        else:
            raise TypeError(f"Unsupported proof field type: {type(v)}")

    return sha256_bytes(b"".join(items))


def build_spend_transcript(
    spend_serials: List[object],          # EC points
    input_commitments: List[object],      # EC points
    output_tokens: List[Token],
    spend_proof,
    value_proof,
    recursive_proof
) -> bytes:
    """
    Build a canonical, deterministic transcript for an offline spend.
    """

    transcript = []

    # --------------------------------------------------
    # 1. Version
    # --------------------------------------------------
    transcript.append(SPEND_TRANSCRIPT_VERSION)

    # --------------------------------------------------
    # 2. Inputs (SPEND SERIALS + INPUT COMMITMENTS)
    # --------------------------------------------------

    # Spend serials are EC points (nullifiers)
    for s in sorted(spend_serials, key=serialize_point):
        transcript.append(serialize_point(s))

    # Input commitments are EC points
    for C in sorted(input_commitments, key=serialize_point):
        transcript.append(serialize_point(C))

    # --------------------------------------------------
    # 3. Outputs (sorted by commitment bytes)
    # --------------------------------------------------
    outputs = sorted(
        output_tokens,
        key=lambda t: serialize_point(t.commitment)
    )

    for t in outputs:
        transcript.append(serialize_point(t.commitment))
        transcript.append(serialize_int(t.expiry))

    # --------------------------------------------------
    # 4. Proofs (fixed order)
    # --------------------------------------------------
    transcript.append(_serialize_proof(spend_proof))
    transcript.append(_serialize_proof(value_proof))
    transcript.append(_serialize_proof(recursive_proof))

    # --------------------------------------------------
    # 5. Final transcript hash
    # --------------------------------------------------
    return sha256_bytes(b"".join(transcript))
