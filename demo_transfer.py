import base64
import os
import time

from crypto.device.identity import DeviceIdentity
from crypto.device.authority import BankAuthority
from crypto.device.spend_transcript import build_spend_transcript
from crypto.device.device_signature import sign_spend_transcript
from crypto.transaction.verify_offline_tx import verify_offline_transaction
from crypto.transaction.accept_offline_tx import accept_offline_transaction
from crypto.commitment import commit
from crypto.curve import random_scalar

from wallet.token_store import TokenStore
from wallet.token_lifecycle import TokenLifecycle
from crypto.state.proof_state import ProofState

from models.offline_transaction import OfflineTransaction

from transport.qr_encoder import encode_transaction_to_qr
from transport.qr_decoder import decode_qr_payload
from transport.transaction_serializer import serialize_offline_transaction


# ==========================================================
# 1️⃣ Setup Bank
# ==========================================================

print("\n=== Setting up Bank ===")
bank = BankAuthority.generate()


# ==========================================================
# 2️⃣ Setup Device A (Sender)
# ==========================================================

print("\n=== Setting up Device A (Sender) ===")
device_A = DeviceIdentity.generate()

cert_id = os.urandom(16)
issued_at = int(time.time())
expires_at = issued_at + 3600

cert_A = bank.issue_device_certificate(
    device_A.pk_device,
    cert_id,
    issued_at,
    expires_at
)

store_A = TokenStore()
proof_state_A = ProofState(
    C_in_total=commit(0, 0),
    C_out_total=commit(0, 0),
    r_in_total=0,
    r_out_total=0
)

wallet_A = TokenLifecycle(store_A, proof_state_A)


# ==========================================================
# 3️⃣ Setup Device B (Receiver)
# ==========================================================

print("\n=== Setting up Device B (Receiver) ===")
device_B = DeviceIdentity.generate()
from wallet.receiver_state import ReceiverWalletState

proof_state_B = ProofState(
    C_in_total=commit(0, 0),
    C_out_total=commit(0, 0),
    r_in_total=0,
    r_out_total=0
)

receiver_B = ReceiverWalletState(proof_state=proof_state_B)
store_B = TokenStore()
proof_state_B = ProofState(
    C_in_total=commit(0, 0),
    C_out_total=commit(0, 0),
    r_in_total=0,
    r_out_total=0
)

seen_serials_B = set()


# ==========================================================
# 4️⃣ Mint Token to A
# ==========================================================

print("\n=== Minting 10 units to Device A ===")

def bank_mint_fn(C, proof):
    # simple mint stub for demo
    serial = random_scalar()
    expiry = int(time.time()) + 3600
    signature = b"demo_signature"
    class BankToken:
        def __init__(self):
            self.serial = serial
            self.commitment = C
            self.expiry = expiry
            self.signature = signature
        def verify_bank_signature(self, _):
            return True
    return BankToken()

minted_token = wallet_A.mint(
    v=10,
    expiry=int(time.time()) + 3600,
    bank_public_key=bank.pk_bank,
    bank_mint_fn=bank_mint_fn
)
from wallet.receiver_state import ReceiverWalletState

proof_state_B = ProofState(
    C_in_total=commit(0, 0),
    C_out_total=commit(0, 0),
    r_in_total=0,
    r_out_total=0
)

receiver_B = ReceiverWalletState(proof_state=proof_state_B)
print("Mint successful.")


# ==========================================================
# 5️⃣ Device A spends 6 to Device B
# ==========================================================

print("\n=== Device A spending 6 units ===")

derived_tokens, spend_serials, spend_proofs, value_proof, recursive_proof = wallet_A.spend(
    input_serials=[minted_token.serial],
    v_out=6,
    v_change=4,
    expiry=int(time.time()) + 3600
)

serial_point = spend_serials[0]

nonce = os.urandom(16)

transcript_hash = build_spend_transcript(
    [serial_point],
    [derived_tokens[0].commitment, derived_tokens[1].commitment],
    spend_proofs[0],
    value_proof,
    nonce
)

device_signature = sign_spend_transcript(
    device_A.sk_device,
    transcript_hash
)

tx = OfflineTransaction(
    input_serials=[serial_point],
    input_commitments=[minted_token.commitment],
    output_commitments=[derived_tokens[0].commitment, derived_tokens[1].commitment],
    spend_proof=spend_proofs[0],
    value_proof=value_proof,
    recursive_proof=recursive_proof,
    transcript_hash=transcript_hash,
    device_signature=device_signature,
    device_certificate=cert_A,
    nonce=nonce
)

print("Transaction created.")


# ==========================================================
# 6️⃣ Encode to QR
# ==========================================================

print("\n=== Encoding transaction to QR ===")
encode_transaction_to_qr(tx, output_file="offline_payment.png")

payload = serialize_offline_transaction(tx)
b64_string = base64.b64encode(payload).decode()

print("Payload size:", len(payload), "bytes")


# ==========================================================
# 7️⃣ Receiver decodes QR
# ==========================================================

print("\n=== Device B decoding QR ===")
tx_received = decode_qr_payload(b64_string)


# ==========================================================
# 8️⃣ Receiver verifies transaction
# ==========================================================

print("\n=== Verifying transaction on Device B ===")

is_valid = verify_offline_transaction(
    tx_received,
    bank.pk_bank,
    seen_serials_B
)

if not is_valid:
    print("❌ Transaction rejected.")
else:
    print("✅ Transaction verified.")
    accept_offline_transaction(tx_received, receiver_B)
    print("💰 Funds accepted by Device B.")
