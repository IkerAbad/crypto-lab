from __future__ import annotations

import json
from pathlib import Path

import pytest

from crypto_lab.curves import SECP256K1
from crypto_lab.ecdsa import (
    ECDSAError,
    PublicKey,
    Signature,
    find_recovery_id,
    private_key_from_int,
    recover_public_key,
    sign,
)
from crypto_lab.encoding import parse_point

VECTOR_DIR = Path(__file__).resolve().parent.parent / "vectors"


def test_recovery_vectors() -> None:
    vectors = json.loads((VECTOR_DIR / "ecdsa_recovery.json").read_text())
    for case in vectors["cases"]:
        public_key = PublicKey(SECP256K1, parse_point(SECP256K1, bytes.fromhex(case["public_key"])))
        signature = Signature.from_der(bytes.fromhex(case["signature_der"]))
        message = bytes.fromhex(case["message"])
        recovery_id = case["recovery_id"]
        assert find_recovery_id(public_key, message, signature) == recovery_id
        recovered = recover_public_key(SECP256K1, message, signature, recovery_id)
        assert recovered.point == public_key.point


def test_recovery_from_generated_signature() -> None:
    private_key = private_key_from_int(0x1234567890ABCDEF, SECP256K1)
    message = b"recovery from a locally generated signature"
    signature = sign(private_key, message)
    public_key = private_key.public_key()
    recovery_id = find_recovery_id(public_key, message, signature)
    assert recovery_id is not None
    recovered = recover_public_key(SECP256K1, message, signature, recovery_id)
    assert recovered.point == public_key.point


def test_recovery_rejects_invalid_recovery_id() -> None:
    private_key = private_key_from_int(9, SECP256K1)
    signature = sign(private_key, b"id")
    for recovery_id in (-1, 4, 99):
        with pytest.raises(ECDSAError):
            recover_public_key(SECP256K1, b"id", signature, recovery_id)


def test_recovery_with_wrong_message_returns_a_different_key() -> None:
    private_key = private_key_from_int(10, SECP256K1)
    message = b"correct message"
    signature = sign(private_key, message)
    recovery_id = find_recovery_id(private_key.public_key(), message, signature)
    assert recovery_id is not None
    recovered = recover_public_key(SECP256K1, b"wrong message", signature, recovery_id)
    assert recovered.point != private_key.public_key().point
