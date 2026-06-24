# Offline CBDC Wallet

A privacy-preserving offline payment system for Central Bank Digital Currency (CBDC), built using elliptic curve cryptography, Pedersen commitments, and zero-knowledge proofs. Enables secure peer-to-peer transactions between devices with no internet connectivity required.

Developed as part of a research internship at **Cystar, IIT Madras Research Park** under **Prof. John Augustine** and **Mr. Jaimandeep Singh**.

---

## Current Status

**Step 8 — Offline Communication Layer: ✅ Fully Complete**

The system supports a full end-to-end offline transfer flow:

```
Bank → Device A → (QR Code) → Device B
```

All tests are passing in a clean virtual environment.

---

## Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| Curve | secp256k1 |
| Hash | SHA-256 |
| Generators | G, H (fixed) |
| Signature Scheme | Schnorr-based device authorization |
| Commitments | Pedersen (C = vG + rH) |

---

## Project Structure

```
Offline-CBDC-Wallet/
│
├── bank/                        # Bank authority — key generation, certificate issuance
│
├── crypto/
│   ├── commitment.py            # Pedersen commitment scheme
│   ├── curve.py                 # secp256k1 curve ops, point serialization
│   ├── device/
│   │   ├── identity.py          # Device key generation
│   │   ├── authority.py         # BankAuthority — issues device certificates
│   │   ├── spend_transcript.py  # Deterministic transcript hashing (no repr())
│   │   └── device_signature.py  # ECDSA signing over spend transcripts
│   ├── transaction/
│   │   ├── verify_offline_tx.py # Full receiver-side transaction verification
│   │   └── accept_offline_tx.py # Funds acceptance + wallet state update
│   └── state/
│       └── proof_state.py       # ProofState — tracks cumulative commitments
│
├── wallet/
│   ├── token_store.py           # Token storage for sender
│   ├── token_lifecycle.py       # Mint and spend operations
│   └── receiver_state.py        # ReceiverWalletState — owned tokens, seen serials
│
├── models/
│   └── offline_transaction.py   # OfflineTransaction data model
│
├── transport/
│   ├── proof_serializer.py      # Deterministic binary serialization for ZK proofs
│   ├── transaction_serializer.py# Binary serialization/deserialization for OfflineTransaction
│   ├── qr_encoder.py            # Transaction → base64 → QR image
│   └── qr_decoder.py            # QR → base64 → Transaction object
│
├── tests/                       # Full test suite
├── demo_transfer.py             # End-to-end demo script
├── offline_payment.png          # Sample QR output from demo
└── pytest.ini
```

---

## Transaction Structure

Each `OfflineTransaction` carries:

| Field | Description |
|---|---|
| `input_serials` | EC point serial numbers of spent tokens |
| `input_commitments` | Pedersen commitments of input tokens |
| `output_commitments` | Commitments for spend amount + change |
| `spend_proof` | ZKP proving valid spend |
| `value_proof` | ZKP proving value conservation |
| `recursive_proof` | Recursive invariant proof |
| `transcript_hash` | Deterministic hash binding all proof data |
| `device_signature` | Schnorr signature over transcript |
| `device_certificate` | Bank-issued certificate for sender device |
| `nonce` | 16-byte random nonce |

---

## End-to-End Flow

### 1. Bank Setup
`BankAuthority` generates a key pair and issues device certificates that authenticate wallets during offline transactions.

### 2. Device Registration
Each device generates a `DeviceIdentity` (key pair). The bank signs a certificate binding the device public key with an expiry timestamp.

### 3. Minting
The bank mints tokens to Device A. Each token has a serial number, Pedersen commitment, bank signature, and expiry.

### 4. Spending (Offline)
Device A:
- Selects input tokens and computes output commitments (spend + change)
- Generates spend proof, value conservation proof, and recursive invariant proof
- Builds a deterministic spend transcript and signs it with the device key
- Packages everything into an `OfflineTransaction`

### 5. QR Transport
The transaction is serialized to binary → base64 → QR image (`offline_payment.png`). No internet required.

### 6. Verification & Acceptance (Device B)
Device B:
- Decodes QR payload and reconstructs the transaction
- Verifies the bank certificate on sender's device
- Validates device signature over the transcript
- Checks spend proof and value conservation proof
- Serializes EC point serials and checks against `seen_serials` (double-spend detection)
- Calls `accept_offline_transaction()` to update `ReceiverWalletState`

---

## What Was Completed in Step 8

### New Files Added

**`transport/proof_serializer.py`**
Deterministic binary serialization for `SpendProof`, `ValueProof`, and `RecursiveInvariantProof`. Replaced unsafe `repr()` usage that was previously used in transcript hashing. Guarantees cross-device determinism and cryptographic stability.

**`transport/transaction_serializer.py`**
Binary serialization and deserialization for the full `OfflineTransaction` in strict field order. Ensures deterministic transport, safe QR encoding, and exact reconstruction on the receiver side. Serializer and deserializer are strictly symmetric.

**`transport/qr_encoder.py`**
Encodes a serialized transaction into a base64 payload and writes it as a QR image file.

**`wallet/receiver_state.py`**
Introduced `ReceiverWalletState` — a proper wallet-level state object for receivers with `seen_serials`, `owned_tokens`, and `proof_state`. Replaced incorrect use of `TokenStore` for receiver-side logic.

### Key Files Modified

**`crypto/device/spend_transcript.py`**
Removed `repr(spend_proof)` and `repr(value_proof)`. Replaced with deterministic proof serialization. `repr()` is non-deterministic, unsafe across environments, and not cryptographically stable.

**`crypto/transaction/verify_offline_tx.py`**
- Replaced dictionary-style proof access (`tx.value_proof["C_in"]`) with proper object-based calls
- Fixed double-spend detection: EC points are not hashable, so serials are now serialized to bytes before set membership checks

**`crypto/transaction/accept_offline_tx.py`**
- Stores serialized serials in `seen_serials`
- Wraps output commitments in temporary objects with `.C` and `.r` fields (receiver doesn't know blinding factor, so `r=0` is correct)

---

## Step 8 Completion Checklist

| Component | Status |
|---|---|
| Spend ZKP | ✅ Complete |
| Value ZKP | ✅ Complete |
| Recursive invariant proof | ✅ Complete |
| Deterministic transcript hashing | ✅ Complete |
| Schnorr device authorization | ✅ Complete |
| Certificate verification | ✅ Complete |
| Transaction serialization | ✅ Complete |
| QR transport | ✅ Complete |
| Receiver-side verification | ✅ Complete |
| Acceptance logic | ✅ Complete |
| End-to-end demo | ✅ Complete |
| All tests passing | ✅ Yes |

---

## Running the Demo

```bash
# Set up virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run end-to-end transfer demo
python demo_transfer.py
```

Expected output:
```
=== Setting up Bank ===
=== Setting up Device A (Sender) ===
=== Setting up Device B (Receiver) ===
=== Minting 10 units to Device A ===
=== Device A spending 6 units ===
=== Encoding transaction to QR ===
=== Device B decoding QR ===
=== Verifying transaction on Device B ===
✅ Transaction verified.
💰 Funds accepted by Device B.
```

## Running Tests

```bash
pytest
```

---

## Next Steps — Step 9: Receiver-Side Hardening & Offline Risk Controls

The system is currently a **cryptographically complete functional prototype**. Step 9 transitions it into a **risk-controlled wallet system**.

### 1. Persistent Double-Spend Tracking *(High Priority)*
**Problem:** `seen_serials` is currently an in-memory set. It is wiped on every restart, allowing replay attacks after reboot.

**Fix:**
- Persist `seen_serials` to SQLite or a file-backed DB
- Reload on wallet startup
- Prevent serial replay across sessions

### 2. Token Expiry Enforcement *(High Priority)*
**Problem:** Token expiry exists in the model but is not enforced at the receiver side.

**Fix:** Add expiry check inside `verify_offline_transaction()`:
```python
if current_time > token.expiry:
    reject transaction
```

### 3. Certificate Revocation Logic *(Medium Priority)*
**Problem:** Only certificate expiry is currently checked. A compromised device cannot be invalidated.

**Fix:**
- Introduce a revocation list structure
- Allow the bank to mark device certificates as revoked
- Add revocation check inside receiver-side verification

### 4. Offline Spending Limits *(Medium Priority)*
**Problem:** No cap on how much a device can spend offline, creating risk exposure.

**Fix:**
- Maximum offline spend per transaction
- Maximum cumulative offline spend per device
- Maximum transaction chain depth

Requires tracking cumulative spend state and enforcing thresholds before accepting.

### 5. Local Audit Log *(Medium Priority)*
**Problem:** No record of accepted transactions on the receiver side.

**Fix:** Receiver should log:
- Accepted transaction hashes
- Timestamps
- Sender device identity
- Serial history

This prepares the system for bank reconciliation in Step 10.

### Recommended Implementation Order for Step 9

1. Add SQLite persistent storage layer
2. Migrate `seen_serials` to persistent storage
3. Enforce token expiry in verifier
4. Add certificate revocation list structure
5. Implement offline spending caps
6. Add local audit log

---

## Critical Notes for the Next Developer

- **Do NOT reintroduce dictionary-style proof structures.** All proofs are object-based.
- **Always serialize EC points before using as dictionary keys or set members.** Points are not hashable.
- **Never use `repr()` in cryptographic hashing.** It is non-deterministic across environments.
- **Transaction serializer and deserializer must remain strictly symmetric.** Any change to one must be mirrored in the other.
- **`ProofState.update_from_spend()` expects token-like objects with `.C` and `.r`.** When receiver doesn't know blinding factor, pass `r=0`.
