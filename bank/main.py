# bank/main.py

from crypto.curve import random_scalar
from crypto.zkp.mint import verify_minting
from crypto.signature import generate_keypair, sign
from models.token import Token
import time


# ------------------------------------------------------------------
# Bank Initialization (mock bank authority)
# ------------------------------------------------------------------

# Generate bank keypair once (mock bank)
BANK_SK, BANK_PK = generate_keypair()


# ------------------------------------------------------------------
# Step 6.1 — Mint Token (Bank Authority)
# ------------------------------------------------------------------

def mint_token(commitment, mint_proof, expiry_seconds: int = 30 * 24 * 60 * 60) -> Token:
    """
    Mint a new CBDC token after verifying mint ZKP.

    Args:
        commitment: Pedersen commitment C = v*G + r*H
        mint_proof: DenominationProof from prove_minting()
        expiry_seconds: Token validity duration (default 30 days)

    Returns:
        Token: Bank-signed token
    """

    # 1. Verify mint ZKP (denomination correctness)
    if not verify_minting(commitment, mint_proof):
        raise ValueError("Mint ZKP verification failed")

    # 2. Generate token serial (scalar)
    serial = random_scalar()

    # 3. Compute expiry timestamp
    expiry = int(time.time()) + expiry_seconds

    # 4. Construct unsigned token (bank does NOT know v, r, s)
    token = Token(
        serial=serial,
        commitment=commitment,
        expiry=expiry,
        signature=None,
        v=0,   # unknown to bank
        r=0,   # unknown to bank
        s=serial
    )

    # 5. Sign token
    message = token.serialize_for_signature()
    signature = sign(BANK_SK, message)

    # 6. Return signed token
    return Token(
        serial=serial,
        commitment=commitment,
        expiry=expiry,
        signature=signature,
        v=0,
        r=0,
        s=serial
    )
