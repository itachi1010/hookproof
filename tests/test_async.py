from __future__ import annotations

from conftest import sign_hex
from hookproof import Verifier, averify

SECRET = b"async-secret"
PAYLOAD = b'{"event":"ping"}'


async def test_averify_with_plain_secret() -> None:
    header = sign_hex(SECRET, PAYLOAD)
    assert await averify(PAYLOAD, header, SECRET) is True


async def test_averify_with_sync_resolver() -> None:
    header = sign_hex(SECRET, PAYLOAD)

    def resolver() -> bytes:
        return SECRET

    assert await averify(PAYLOAD, header, resolver) is True


async def test_averify_with_async_resolver() -> None:
    header = sign_hex(SECRET, PAYLOAD)

    async def resolver() -> bytes:
        return SECRET

    assert await averify(PAYLOAD, header, resolver) is True


async def test_averify_detects_tampering() -> None:
    header = sign_hex(SECRET, PAYLOAD)
    assert await averify(b"tampered", header, SECRET) is False


async def test_verifier_averify() -> None:
    header = sign_hex(SECRET, PAYLOAD)
    assert await Verifier(SECRET).averify(PAYLOAD, header) is True
