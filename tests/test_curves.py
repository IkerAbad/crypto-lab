from __future__ import annotations

import json
from pathlib import Path

from crypto_lab.bigint import BigInt
from crypto_lab.curves import P256, SECP256K1, AffinePoint, Curve, JacobianPoint
from crypto_lab.scalarmult import montgomery_ladder

VECTOR_DIR = Path(__file__).resolve().parent.parent / "vectors"


def test_secp256k1_generator() -> None:
    assert SECP256K1.is_on_curve(SECP256K1.g)
    assert SECP256K1.p == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    assert SECP256K1.n == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def test_known_multiples_of_g() -> None:
    expected = {
        2: (
            0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
            0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
        ),
        3: (
            0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
            0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672,
        ),
    }
    for scalar, (x, y) in expected.items():
        point = montgomery_ladder(SECP256K1, scalar, SECP256K1.g)
        assert point.x is not None and point.y is not None
        assert point.x.to_int() == x
        assert point.y.to_int() == y


def test_order_times_g_is_infinity() -> None:
    assert montgomery_ladder(SECP256K1, SECP256K1.n, SECP256K1.g).is_infinity


def test_minus_g() -> None:
    point = montgomery_ladder(SECP256K1, SECP256K1.n - 1, SECP256K1.g)
    assert point.x == SECP256K1.g.x
    assert point.y == -SECP256K1.g.y


def test_affine_and_jacobian_addition_agree() -> None:
    g = SECP256K1.g
    for left_scalar, right_scalar in ((1, 1), (2, 3), (5, 7), (123, 456)):
        left = montgomery_ladder(SECP256K1, left_scalar, g)
        right = montgomery_ladder(SECP256K1, right_scalar, g)
        affine = SECP256K1.add_affine(left, right)
        jacobian = SECP256K1.add_jacobian(
            SECP256K1.affine_to_jacobian(left), SECP256K1.affine_to_jacobian(right)
        )
        converted = SECP256K1.jacobian_to_affine(jacobian)
        assert affine.x == converted.x
        assert affine.y == converted.y


def test_exceptional_cases() -> None:
    g = SECP256K1.g
    assert SECP256K1.add_affine(g, SECP256K1.negate(g)).is_infinity
    assert SECP256K1.add_affine(g, SECP256K1.infinity()) == g
    assert SECP256K1.double_jacobian(
        JacobianPoint(SECP256K1.field.zero, SECP256K1.field.zero, SECP256K1.field.zero)
    ).is_infinity


def test_p256_public_key_matches_rfc6979() -> None:
    vectors = json.loads((VECTOR_DIR / "rfc6979_p256_sha256.json").read_text())
    private_key = BigInt.from_hex(vectors["private_key"])
    point = montgomery_ladder(P256, private_key, P256.g)
    assert point.x is not None and point.y is not None
    assert point.x.to_int() == int(vectors["public_key"]["x"], 16)
    assert point.y.to_int() == int(vectors["public_key"]["y"], 16)


def test_invalid_point_is_rejected() -> None:
    curve = Curve("tiny", 17, 2, 2, 19, 5, 1)
    assert not curve.is_on_curve(AffinePoint(curve.field.element(0), curve.field.element(5)))
    assert curve.is_on_curve(curve.g)
