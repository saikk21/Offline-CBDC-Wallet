# crypto/device/identity.py

from crypto.curve import G, ORDER, random_scalar


class DeviceIdentity:
    """
    Represents a wallet device cryptographic identity.

    - sk_device: private signing key (scalar)
    - pk_device: public verification key (EC point)
    """

    def __init__(self, sk_device: int, pk_device):
        self.sk_device = sk_device
        self.pk_device = pk_device

    @classmethod
    def generate(cls):
        """
        Generate a new device identity.

        sk_device ∈ [1, ORDER)
        pk_device = sk_device * G
        """
        sk_device = random_scalar()

        # Defensive check
        if sk_device == 0 or sk_device >= ORDER:
            raise ValueError("Invalid device secret key generated")

        pk_device = sk_device * G

        return cls(sk_device=sk_device, pk_device=pk_device)
