from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.curves import P256, SECP256K1
from crypto_lab.field import MontgomeryField


@pytest.mark.parametrize("modulus", [SECP256K1.p, P256.p, 2**255 - 19, 2**127 - 1])
def test_field_matches_python_arithmetic(modulus: int) -> None:
    field = MontgomeryField(modulus)
    for value in (0, 1, 2, modulus - 1, modulus // 2):
        assert field.element(value).to_int() == value


@pytest.mark.parametrize("modulus", [SECP256K1.p, P256.p])
@settings(max_examples=80)
@given(
    st.integers(min_value=0, max_value=2**256 - 1),
    st.integers(min_value=0, max_value=2**256 - 1),
)
def test_add_sub_mul_match_python(modulus: int, left: int, right: int) -> None:
    left %= modulus
    right %= modulus
    field = MontgomeryField(modulus)
    a = field.element(left)
    b = field.element(right)
    assert (a + b).to_int() == (left + right) % modulus
    assert (a - b).to_int() == (left - right) % modulus
    assert (a * b).to_int() == (left * right) % modulus


@pytest.mark.parametrize("modulus", [SECP256K1.p, P256.p])
@settings(max_examples=20)
@given(st.integers(min_value=1, max_value=2**256 - 1))
def test_inverse(modulus: int, value: int) -> None:
    value %= modulus
    if value == 0:
        return
    field = MontgomeryField(modulus)
    element = field.element(value)
    assert (element * element.inverse()).to_int() == 1


def test_batch_inverse() -> None:
    field = SECP256K1.field
    values = [field.element(value) for value in (3, 5, 7, 11, 13)]
    inverses = field.batch_inverse(values)
    assert [
        (value * inverse).to_int() for value, inverse in zip(values, inverses, strict=True)
    ] == [
        1,
        1,
        1,
        1,
        1,
    ]


def test_select_is_branchless_choice() -> None:
    field = SECP256K1.field
    a = field.element(123)
    b = field.element(456)
    assert field.select(0, a, b) == a
    assert field.select(1, a, b) == b


def test_sqrt_for_p256_and_secp256k1() -> None:
    for curve in (SECP256K1, P256):
        field = curve.field
        for value in (2, 3, 5, 7):
            square = field.element(value) * field.element(value)
            root = field.sqrt(square)
            assert root * root == square


def test_zero_has_no_inverse() -> None:
    field = SECP256K1.field
    with pytest.raises(ZeroDivisionError):
        field.inverse(field.zero)
