from __future__ import annotations

import base64

import pytest

from crypto_lab.bigint import BigInt
from crypto_lab.curves import SECP256K1
from crypto_lab.ecdsa import private_key_from_int
from crypto_lab.encoding import (
    base58_decode,
    base58_encode,
    base58check_decode,
    base58check_encode,
    decode_der_signature,
    encode_der_signature,
    encode_ec_private_key_pem,
    encode_ec_public_key_pem,
    parse_point,
    serialize_point_compressed,
    serialize_point_uncompressed,
)
from crypto_lab.scalarmult import montgomery_ladder


def test_generator_serialization() -> None:
    compressed = serialize_point_compressed(SECP256K1.g)
    uncompressed = serialize_point_uncompressed(SECP256K1.g)
    assert compressed.hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    assert uncompressed.hex() == (
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )


@pytest.mark.parametrize("scalar", [1, 2, 3, 7, 12345, 2**200 + 1])
def test_point_parse_roundtrip(scalar: int) -> None:
    point = montgomery_ladder(SECP256K1, scalar, SECP256K1.g)
    for encoded in (serialize_point_compressed(point), serialize_point_uncompressed(point)):
        decoded = parse_point(SECP256K1, encoded)
        assert decoded.x == point.x
        assert decoded.y == point.y


def test_invalid_point_encodings() -> None:
    with pytest.raises(ValueError):
        parse_point(SECP256K1, b"")
    with pytest.raises(ValueError):
        parse_point(SECP256K1, b"\x05" + b"\x00" * 64)
    with pytest.raises(ValueError):
        parse_point(SECP256K1, b"\x04" + b"\x00" * 64)


def test_der_signature_roundtrip() -> None:
    encoded = encode_der_signature(1, 2)
    assert encoded.hex() == "3006020101020102"
    assert decode_der_signature(encoded) == (BigInt.ONE, BigInt.from_int(2))


def test_der_high_bit_padding() -> None:
    encoded = encode_der_signature(0x80, 1)
    assert encoded.hex() == "300702020080020101"
    assert decode_der_signature(encoded) == (BigInt.from_int(0x80), BigInt.ONE)


@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        b"\x30\x00",
        b"\x30\x06\x02\x01\x00\x02\x01\x01",
        b"\x30\x06\x02\x01\x01\x02\x01\x00",
        b"\x30\x06\x02\x01\x81\x02\x01\x01",
        b"\x30\x06\x02\x01\x01\x02\x01\x01\x00",
    ],
)
def test_invalid_der_signatures(encoded: bytes) -> None:
    with pytest.raises(ValueError):
        decode_der_signature(encoded)


def test_base58_known_values() -> None:
    assert base58_encode(b"") == ""
    assert base58_encode(b"\x00") == "1"
    assert base58_encode(b"\x00\x00") == "11"
    assert base58_encode(b"Hello World!") == "2NEpo7TZRRrLZSi2U"
    assert base58_decode("2NEpo7TZRRrLZSi2U") == b"Hello World!"


def test_base58check_roundtrip() -> None:
    payload = bytes.fromhex("00010203040506070809")
    encoded = base58check_encode(payload)
    assert base58check_decode(encoded) == payload
    with pytest.raises(ValueError):
        base58check_decode(encoded[:-1] + "2")


def test_pem_key_containers() -> None:
    private_key = private_key_from_int(1)
    public_key = private_key.public_key()
    private_pem = encode_ec_private_key_pem(private_key.curve, private_key.scalar, public_key.point)
    public_pem = encode_ec_public_key_pem(private_key.curve, public_key.point)
    assert private_pem.startswith("-----BEGIN EC PRIVATE KEY-----")
    assert public_pem.startswith("-----BEGIN PUBLIC KEY-----")
    private_der = base64.b64decode("".join(private_pem.strip().splitlines()[1:-1]))
    public_der = base64.b64decode("".join(public_pem.strip().splitlines()[1:-1]))
    assert private_der[:2] == b"\x30\x74"
    assert public_der[:2] == b"\x30\x56"
