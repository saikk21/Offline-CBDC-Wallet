# crypto/device/authority.py
import secrets
from crypto.hash import sha256_int, serialize_point
from crypto.device.certificate import DeviceCertificate
from crypto.curve import G, ORDER, random_scalar


class BankAuthority:
    """
    Represents the issuing authority (Bank / RBI).

    - sk_bank: private signing key (scalar)
    - pk_bank: public verification key (EC point)
    """

    def __init__(self, sk_bank: int, pk_bank):
        self.sk_bank = sk_bank
        self.pk_bank = pk_bank

    @classmethod
    def generate(cls):
        """
        Generate a new bank authority keypair.

        sk_bank ∈ [1, ORDER)
        pk_bank = sk_bank * G
        """
        sk_bank = random_scalar()

        # Defensive correctness
        if sk_bank == 0 or sk_bank >= ORDER:
            raise ValueError("Invalid bank secret key generated")

        pk_bank = sk_bank * G

        return cls(sk_bank=sk_bank, pk_bank=pk_bank)
    def issue_device_certificate(
        self,
        pk_device,
        cert_id: bytes,
        issued_at: int,
        expires_at: int
    ) -> DeviceCertificate:
        """
        Issue a signed device certificate for a wallet device.
        """

        # --------------------------------------------------
        # 1. Build signing transcript
        # --------------------------------------------------
        message = (
            serialize_point(pk_device) +
            cert_id +
            issued_at.to_bytes(8, "big") +
            expires_at.to_bytes(8, "big")
        )

        # --------------------------------------------------
        # 2. Schnorr signature
        # --------------------------------------------------
        k = secrets.randbelow(ORDER)
        R = k * G

        e = sha256_int(
            serialize_point(R) + message
        ) % ORDER

        z = (k + e * self.sk_bank) % ORDER

        signature = (
            serialize_point(R) +
            z.to_bytes(32, "big")
        )

        # --------------------------------------------------
        # 3. Return immutable certificate
        # --------------------------------------------------
        return DeviceCertificate(
            pk_device=pk_device,
            cert_id=cert_id,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature
        )
