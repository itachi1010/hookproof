from __future__ import annotations

import base64
import hashlib
import hmac


def sign_hex(secret: bytes, payload: bytes, algorithm: str = "sha256") -> str:
    return hmac.new(secret, payload, algorithm).hexdigest()


def sign_base64(secret: bytes, payload: bytes, algorithm: str = "sha256") -> str:
    return base64.b64encode(hmac.new(secret, payload, algorithm).digest()).decode("ascii")


def sign_stripe(secret: bytes, payload: bytes, timestamp: int) -> str:
    message = f"{timestamp}.".encode("ascii") + payload
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={signature}"
