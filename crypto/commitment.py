# returns the C

from crypto.curve import G, H, ORDER


def commit(v: int, r: int):
    """
    Pedersen commitment:
    C = v*G + r*H
    """
    if v < 0:
        raise ValueError("Value must be non-negative")

    if not (0 <= r < ORDER):
        raise ValueError("Blinding factor r out of range")

    C = v * G + r * H
    return C
