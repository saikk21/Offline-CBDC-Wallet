# transport/qr_encoder.py

import base64
import qrcode

from transport.transaction_serializer import serialize_offline_transaction


def encode_transaction_to_qr(tx, output_file="offline_tx.png"):
    """
    Serialize transaction → Base64 → QR image file.
    """

    payload = serialize_offline_transaction(tx)

    # Base64 encode for QR safety
    b64_payload = base64.b64encode(payload).decode()

    qr = qrcode.QRCode(
        version=None,  # auto size
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )

    qr.add_data(b64_payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_file)

    print(f"QR code saved to {output_file}")
    print(f"Payload size: {len(payload)} bytes")
