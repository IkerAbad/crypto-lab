from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.curves import SECP256K1
from crypto_lab.ecdsa import private_key_from_int, sign, verify
from crypto_lab.encoding import (
    parse_point,
    serialize_point_compressed,
    serialize_point_uncompressed,
)
from crypto_lab.scalarmult import montgomery_ladder


@settings(max_examples=6, deadline=None)
@given(st.integers(min_value=1, max_value=SECP256K1.n - 1))
def test_scalar_to_point_serialization_roundtrip(scalar: int) -> None:
    point = montgomery_ladder(SECP256K1, scalar, SECP256K1.g)
    for encoded in (serialize_point_compressed(point), serialize_point_uncompressed(point)):
        decoded = parse_point(SECP256K1, encoded)
        assert decoded.x == point.x
        assert decoded.y == point.y


@settings(max_examples=3, deadline=None)
@given(
    st.integers(min_value=1, max_value=SECP256K1.n - 1),
    st.binary(min_size=0, max_size=64),
)
def test_sign_verify_property(scalar: int, message: bytes) -> None:
    private_key = private_key_from_int(scalar)
    signature = sign(private_key, message)
    assert verify(private_key.public_key(), message, signature)
