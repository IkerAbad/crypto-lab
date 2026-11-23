from __future__ import annotations

import math

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from crypto_lab.bigint import BigInt, mod_inverse, pow_mod


def test_from_int_roundtrip() -> None:
    for value in (0, 1, 2**64 - 1, 2**64, 2**256 - 1, 2**521 - 1):
        assert BigInt.from_int(value).to_int() == value


def test_bytes_and_hex_roundtrip() -> None:
    data = bytes(range(16))
    value = BigInt.from_bytes(data)
    assert value.to_bytes(len(data)) == data
    assert BigInt.from_hex(value.to_hex()) == value
    assert BigInt.from_hex("0x0a") == BigInt.from_int(10)


def test_comparison_uses_most_significant_limb() -> None:
    small = BigInt.from_int(2**64)
    large = BigInt.from_int(2**64 + 1)
    assert small < large
    assert large > small
    assert small != large


@settings(max_examples=200)
@given(st.integers(min_value=0, max_value=2**520), st.integers(min_value=0, max_value=2**520))
def test_add_mul_match_python(left: int, right: int) -> None:
    a = BigInt.from_int(left)
    b = BigInt.from_int(right)
    assert (a + b).to_int() == left + right
    assert (a * b).to_int() == left * right


@settings(max_examples=150)
@given(st.integers(min_value=0, max_value=2**520), st.integers(min_value=1, max_value=2**400))
def test_divmod_matches_python(numerator: int, denominator: int) -> None:
    quotient, remainder = divmod(BigInt.from_int(numerator), BigInt.from_int(denominator))
    assert (quotient.to_int(), remainder.to_int()) == divmod(numerator, denominator)


@settings(max_examples=80)
@given(st.integers(min_value=1, max_value=2**300), st.integers(min_value=0, max_value=2**300))
def test_shifts_match_python(value: int, shift: int) -> None:
    shift %= 128
    big = BigInt.from_int(value)
    assert (big << shift).to_int() == value << shift
    assert (big >> shift).to_int() == value >> shift


@settings(max_examples=40)
@given(
    st.integers(min_value=3, max_value=2**256 - 1),
    st.integers(min_value=1, max_value=2**255),
)
def test_mod_inverse(modulus: int, value: int) -> None:
    assume(modulus % 2 == 1)
    value %= modulus
    assume(value != 0 and math.gcd(value, modulus) == 1)
    inverse = mod_inverse(BigInt.from_int(value), BigInt.from_int(modulus))
    assert (BigInt.from_int(value) * inverse % BigInt.from_int(modulus)).to_int() == 1


@settings(max_examples=80)
@given(
    st.integers(min_value=0, max_value=2**128),
    st.integers(min_value=0, max_value=2**128),
    st.integers(min_value=1, max_value=2**128),
)
def test_pow_mod(base: int, exponent: int, modulus: int) -> None:
    expected = pow(base, exponent, modulus)
    assert (
        pow_mod(BigInt.from_int(base), BigInt.from_int(exponent), BigInt.from_int(modulus)).to_int()
        == expected
    )


def test_zero_and_one_constants() -> None:
    assert BigInt.ZERO.to_int() == 0
    assert BigInt.ONE.to_int() == 1
    assert not BigInt.ZERO
    assert BigInt.ONE
