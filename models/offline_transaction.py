from dataclasses import dataclass
from typing import List
from crypto.device.certificate import DeviceCertificate

@dataclass
class OfflineTransaction:
    input_serials: List[object]
    input_commitments: List[object]   # ← ADD THIS
    output_commitments: List[object]
    spend_proof: object
    value_proof: object
    recursive_proof: object
    transcript_hash: bytes
    device_signature: bytes
    device_certificate: DeviceCertificate
    nonce: bytes
