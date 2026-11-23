from __future__ import annotations

import json
from pathlib import Path

import pytest

from crypto_lab.bigint import BigInt
from crypto_lab.curves import P256, SECP256K1
from crypto_lab.ecdsa import (
    ECDSAError,
    PrivateKey,
    Signature,
    generate_private_key,
    private_key_from_int,
    sign,
    verify,
)
from crypto_lab.hashing import sha256
from crypto_lab.rfc6979 import generate_nonces

VECTOR_DIR = Path(__file__).resolve().parent.parent / "vectors"


def test_rfc6979_p256_vectors() -> None:
    vectors = json.loads((VECTOR_DIR / "rfc6979_p256_sha256.json").read_text())
    private_key = private_key_from_int(int(vectors["private_key"], 16), P256)
    public_key = private_key.public_key()
    assert public_key.point.x is not None and public_key.point.y is not None
    assert public_key.point.x.to_int() == int(vectors["public_key"]["x"], 16)
    assert public_key.point.y.to_int() == int(vectors["public_key"]["y"], 16)

    for case in vectors["cases"]:
        message = case["message"].encode()
        nonce = next(generate_nonces(private_key.scalar, sha256(message), P256.n))
        assert nonce == BigInt.from_hex(case["k"])
        signature = sign(private_key, message, low_s=False)
        assert signature.r == BigInt.from_hex(case["r"])
        assert signature.s == BigInt.from_hex(case["s"])
        assert verify(public_key, message, signature)


def test_secp256k1_sign_verify_and_low_s() -> None:
    private_key = private_key_from_int(0x1234567890ABCDEF, SECP256K1)
    public_key = private_key.public_key()
    message = b"crypto-lab deterministic signature"
    signature = sign(private_key, message)
    assert signature.s <= BigInt.from_int(SECP256K1.n) >> 1
    assert verify(public_key, message, signature)
    assert verify(public_key, message, signature, low_s=True)
    assert not verify(public_key, message + b"!", signature)
    assert not verify(private_key_from_int(2, SECP256K1).public_key(), message, signature)


def test_signature_is_deterministic() -> None:
    private_key = private_key_from_int(42, SECP256K1)
    first = sign(private_key, b"same message")
    second = sign(private_key, b"same message")
    assert first == second


def test_malleable_high_s_signature() -> None:
    private_key = private_key_from_int(7, SECP256K1)
    public_key = private_key.public_key()
    message = b"malleability"
    low = sign(private_key, message)
    order = BigInt.from_int(SECP256K1.n)
    high = Signature(low.r, order - low.s)
    assert high.is_malleable(order)
    assert not low.is_malleable(order)
    assert verify(public_key, message, high)
    assert not verify(public_key, message, high, low_s=True)
    assert high.normalized(order) == low
    assert verify(public_key, message, high.normalized(order), low_s=True)


def test_der_roundtrip() -> None:
    private_key = private_key_from_int(99, SECP256K1)
    signature = sign(private_key, b"der")
    encoded = signature.to_der()
    assert Signature.from_der(encoded) == signature


def test_invalid_signature_values_are_rejected() -> None:
    private_key = private_key_from_int(5, SECP256K1)
    public_key = private_key.public_key()
    order = BigInt.from_int(SECP256K1.n)
    for signature in (
        Signature(BigInt.ZERO, BigInt.ONE),
        Signature(BigInt.ONE, BigInt.ZERO),
        Signature(order, BigInt.ONE),
        Signature(BigInt.ONE, order),
    ):
        assert not verify(public_key, b"x", signature)


def test_private_key_validation() -> None:
    with pytest.raises(ECDSAError):
        PrivateKey(SECP256K1, BigInt.ZERO)
    with pytest.raises(ECDSAError):
        PrivateKey(SECP256K1, BigInt.from_int(SECP256K1.n))
    assert generate_private_key().public_key().curve is SECP256K1
